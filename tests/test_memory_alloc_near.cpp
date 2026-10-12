#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#include <algorithm>
#include <chrono>
#include <limits>
#include <vector>

#if defined(MINIDETOUR_OS_LINUX) || defined(MINIDETOUR_OS_APPLE)
#include <sys/mman.h>
#endif

// The near allocation search tested allocAddress + size <= region.End: with a huge size the sum wrapped
// around, the test always passed and the search tried every page of the address space.
TEST_CASE("Near allocation with a huge size fails quickly", "[mem alloc near]")
{
    const size_t size = (std::numeric_limits<size_t>::max() - 0x100000) & ~(size_t)0xFFFF;

    auto start    = std::chrono::steady_clock::now();
    void *address = MiniDetour::MemoryManipulation::MemoryAlloc((void *)0x10000, size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);
    auto elapsed  = std::chrono::steady_clock::now() - start;

    CHECK(address == nullptr);
    CHECK(elapsed < std::chrono::seconds(5));
}

#if defined(MINIDETOUR_OS_LINUX) || defined(MINIDETOUR_OS_APPLE)
// The downward search started at region.End - pageSize, so an allocation bigger than one page never fitted
// in a free region below the hint.
TEST_CASE("Near allocation below the hint", "[mem alloc near]")
{
    const size_t pageSize = MiniDetour::MemoryManipulation::PageSize();

    // [guard page][hole: 32 pages][block: 32 pages][guard page]
    auto base = static_cast<uint8_t *>(mmap(nullptr, pageSize * 66, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(base != MAP_FAILED);
    REQUIRE(munmap(base + pageSize, pageSize * 32) == 0);

    // The hole is the closest free region to the hint, and it is below it.
    uint8_t *hint = base + pageSize * 33;
    void *address = MiniDetour::MemoryManipulation::MemoryAlloc(hint, pageSize * 2, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);
    CHECK(address == hint - pageSize * 2);

    if (address != nullptr)
        MiniDetour::MemoryManipulation::MemoryFree(address, pageSize * 2);

    munmap(base, pageSize);
    munmap(base + pageSize * 33, pageSize * 33);
}
#endif

#if defined(MINIDETOUR_OS_WINDOWS)
#include <Windows.h>
#endif

#if defined(MINIDETOUR_OS_LINUX) && !defined(MAP_FIXED_NOREPLACE)
#define MAP_FIXED_NOREPLACE 0x100000
#endif

// Reserves size bytes exactly at address, nullptr if they aren't free.
static void *NearTestReserveAt(uintptr_t address, size_t size)
{
#if defined(MINIDETOUR_OS_WINDOWS)
    return VirtualAlloc(reinterpret_cast<void *>(address), size, MEM_RESERVE, PAGE_NOACCESS);
#else
#if defined(MINIDETOUR_OS_LINUX)
    void *reserved = mmap(reinterpret_cast<void *>(address), size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
#else
    void *reserved = mmap(reinterpret_cast<void *>(address), size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    if (reserved == MAP_FAILED)
        return nullptr;

    if (reserved != reinterpret_cast<void *>(address))
    {
        munmap(reserved, size);
        return nullptr;
    }

    return reserved;
#endif
}

static void NearTestRelease(void *address, size_t size)
{
#if defined(MINIDETOUR_OS_WINDOWS)
    (void)size;
    VirtualFree(address, 0, MEM_RELEASE);
#else
    munmap(address, size);
#endif
}

// Free regions were sorted by the distance to their start only, so a large free region holding the hint came after a
// small one closer to it, and the search started at the region start, far from the hint.
TEST_CASE("Near allocation inside a large free region", "[mem alloc near]")
{
    const size_t mb = 0x100000;

    // [large free region: 48 MB][blocker: 8 MB][small free region: 64 KB][blocker]
    // The hint is 4 MB below the end of the large region: the small region starts 12 MB away from it, the large one
    // 44 MB away. The area is taken from the system first, so nothing else (qemu's own hidden mappings) is in it.
    const size_t areaSize = 64 * mb;
    void *area            = MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, areaSize, MiniDetour::MemoryManipulation::MemoryRights::mem_none);
    REQUIRE(area != nullptr);
    const uintptr_t base = (reinterpret_cast<uintptr_t>(area) + 0xFFFF) & ~static_cast<uintptr_t>(0xFFFF);
    MiniDetour::MemoryManipulation::MemoryFree(area, areaSize);

    void *firstBlocker  = NearTestReserveAt(base + 48 * mb, 8 * mb);
    void *secondBlocker = NearTestReserveAt(base + 56 * mb + 0x10000, 4 * mb);
    REQUIRE(firstBlocker != nullptr);
    REQUIRE(secondBlocker != nullptr);

    const uintptr_t hint = base + 44 * mb;
    const size_t size    = MiniDetour::MemoryManipulation::PageSize();
    void *address        = MiniDetour::MemoryManipulation::MemoryAlloc(reinterpret_cast<void *>(hint), size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);
    INFO("Hint: " << (void *)hint << ", allocated: " << address);
    CHECK(address == reinterpret_cast<void *>(hint));

    if (address != nullptr)
        MiniDetour::MemoryManipulation::MemoryFree(address, size);

    NearTestRelease(secondBlocker, 4 * mb);
    NearTestRelease(firstBlocker, 8 * mb);
}
