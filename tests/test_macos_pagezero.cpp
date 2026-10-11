#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_APPLE)
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

#include <vector>

// __PAGEZERO is reserved from 0 up to the main executable, but mach_vm_region doesn't report it: it was listed as free
// memory, and near allocations tried (and failed) on every page of it before going elsewhere.
TEST_CASE("__PAGEZERO is not free memory", "[macos_pagezero]")
{
    // Not always image 0: libraries inserted with DYLD_INSERT_LIBRARIES come first.
    uintptr_t executableStart = 0;
    for (uint32_t i = 0; i < _dyld_image_count() && executableStart == 0; ++i)
    {
        if (_dyld_get_image_header(i)->filetype == MH_EXECUTE)
            executableStart = reinterpret_cast<uintptr_t>(_dyld_get_image_header(i));
    }
    REQUIRE(executableStart != 0);

    const uintptr_t belowExecutable = executableStart - MiniDetour::MemoryManipulation::PageSize();

    std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> freeRegions(MiniDetour::MemoryManipulation::GetFreeRegions(nullptr, 0) * 2);
    freeRegions.resize(MiniDetour::MemoryManipulation::GetFreeRegions(freeRegions.data(), freeRegions.size()));

    bool listedAsFree = false;
    for (auto const &region : freeRegions)
        listedAsFree |= region.Start <= belowExecutable && belowExecutable < region.End;

    CHECK_FALSE(listedAsFree);
}
#endif
