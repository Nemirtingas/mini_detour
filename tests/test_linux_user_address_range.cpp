#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_LINUX)
#include <sys/mman.h>
#include <errno.h>

#include <vector>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> _GetFreeRegions()
{
    std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> freeRegions(MiniDetour::MemoryManipulation::GetFreeRegions(nullptr, 0) * 2);
    freeRegions.resize(MiniDetour::MemoryManipulation::GetFreeRegions(freeRegions.data(), freeRegions.size()));
    return freeRegions;
}

// The memory between the stack and [vsyscall] (x64) or [vectors] (ARM) was listed as free, but it is above the
// user address space: mmap fails there with ENOMEM.
TEST_CASE("Free regions are inside the user address space", "[mem regions]")
{
    const size_t pageSize = MiniDetour::MemoryManipulation::PageSize();

    for (auto const& region : _GetFreeRegions())
    {
        if (region.End - region.Start < pageSize)
            continue;

        void* address = reinterpret_cast<void*>(region.End - pageSize);
        void* mapped = mmap(address, pageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        const int error = errno;
        if (mapped != MAP_FAILED)
            munmap(mapped, pageSize);

        INFO("Free region [" << (void*)region.Start << ", " << (void*)region.End << ")");
        CHECK((mapped != MAP_FAILED || error != ENOMEM));
    }
}

#if defined(MINIDETOUR_ARCH_X64) || defined(MINIDETOUR_ARCH_ARM64)
// MemoryAlloc capped the addresses at 0x7ffefffff000, 4 GB below the end of a 47 bits address space (and far
// below the libraries of a 48 bits AArch64 kernel): memory near a module loaded there was never used.
TEST_CASE("Near allocation above 0x7ffefffff000", "[mem alloc near]")
{
    const uintptr_t oldLimit = 0x7ffefffff000;
    const size_t pageSize = MiniDetour::MemoryManipulation::PageSize();

    uintptr_t hint = 0;
    for (auto const& region : _GetFreeRegions())
    {
        const uintptr_t start = region.Start > oldLimit + pageSize ? region.Start : oldLimit + pageSize;
        if (start < region.End && region.End - start >= pageSize * 2)
        {
            // The middle of the region, which is inside the address space if the region is.
            hint = (start + (region.End - start) / 2) & ~(uintptr_t)(pageSize - 1);
            break;
        }
    }

    if (hint == 0)
    {
        WARN("No free memory above 0x7ffefffff000 in this process.");
        return;
    }

    void* address = MiniDetour::MemoryManipulation::MemoryAlloc(reinterpret_cast<void*>(hint), pageSize, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);
    CHECK(address == reinterpret_cast<void*>(hint));

    if (address != nullptr)
        MiniDetour::MemoryManipulation::MemoryFree(address, pageSize);
}
#endif
#endif
