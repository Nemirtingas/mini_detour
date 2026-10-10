#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_WINDOWS)
#include <Windows.h>

#include <algorithm>
#include <limits>
#include <vector>

// VirtualQuery reports [0, 64 KB) as free. Trying to allocate at its start called VirtualAlloc(NULL), which
// allocates anywhere: that address was taken as the near allocation and the other free regions were skipped.
TEST_CASE("Near allocation doesn't use the region at address 0", "[mem alloc near]")
{
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    const uintptr_t granularity = systemInfo.dwAllocationGranularity;
    const uintptr_t hint        = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    const size_t size           = granularity;

    // Take the lowest usable address if it is free: the region at 0 is then strictly the closest one to the hint.
    void *blocker = VirtualAlloc(reinterpret_cast<void *>(hint), granularity, MEM_RESERVE, PAGE_NOACCESS);

    // Smallest possible distance, from the free regions an allocation can use.
    std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> freeRegions(MiniDetour::MemoryManipulation::GetFreeRegions(nullptr, 0) * 2);
    freeRegions.resize(MiniDetour::MemoryManipulation::GetFreeRegions(freeRegions.data(), freeRegions.size()));
    uintptr_t bestDistance = (std::numeric_limits<uintptr_t>::max)();
    for (auto const &region : freeRegions)
    {
        const uintptr_t start = ((std::max)(region.Start, hint) + granularity - 1) / granularity * granularity;
        if (start >= region.End || region.End - start < size)
            continue;

        bestDistance = (std::min)(bestDistance, start - hint);
    }
    REQUIRE(bestDistance != (std::numeric_limits<uintptr_t>::max)());

    auto address =
        reinterpret_cast<uintptr_t>(MiniDetour::MemoryManipulation::MemoryAlloc(reinterpret_cast<void *>(hint), size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw));
    CHECK(address >= hint);
    CHECK(address - hint == bestDistance);

    if (address != 0)
        MiniDetour::MemoryManipulation::MemoryFree(reinterpret_cast<void *>(address), size);

    if (blocker != nullptr)
        VirtualFree(blocker, 0, MEM_RELEASE);
}
#endif
