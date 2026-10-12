#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_APPLE)
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <string.h>

#include <vector>

// __PAGEZERO is reserved from 0, but mach_vm_region doesn't report it: it was listed as free memory, and near
// allocations tried (and failed) on every page of it before going elsewhere.
TEST_CASE("__PAGEZERO is not free memory", "[macos_pagezero]")
{
    // The main executable is not always image 0: libraries inserted with DYLD_INSERT_LIBRARIES come first.
    const mach_header_64 *executable = nullptr;
    for (uint32_t i = 0; i < _dyld_image_count() && executable == nullptr; ++i)
    {
        if (_dyld_get_image_header(i)->filetype == MH_EXECUTE)
            executable = reinterpret_cast<const mach_header_64 *>(_dyld_get_image_header(i));
    }
    REQUIRE(executable != nullptr);

    // Its size depends on the link options: the tests use a small one on x64.
    uintptr_t pageZeroEnd = 0;
    auto command          = reinterpret_cast<const load_command *>(executable + 1);
    for (uint32_t i = 0; i < executable->ncmds; ++i)
    {
        auto segment = reinterpret_cast<const segment_command_64 *>(command);
        if (command->cmd == LC_SEGMENT_64 && strcmp(segment->segname, SEG_PAGEZERO) == 0)
            pageZeroEnd = static_cast<uintptr_t>(segment->vmaddr + segment->vmsize);

        command = reinterpret_cast<const load_command *>(reinterpret_cast<uintptr_t>(command) + command->cmdsize);
    }
    REQUIRE(pageZeroEnd != 0);

    const uintptr_t inPageZero = pageZeroEnd - MiniDetour::MemoryManipulation::PageSize();

    std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> freeRegions(MiniDetour::MemoryManipulation::GetFreeRegions(nullptr, 0) * 2);
    freeRegions.resize(MiniDetour::MemoryManipulation::GetFreeRegions(freeRegions.data(), freeRegions.size()));

    bool listedAsFree = false;
    for (auto const &region : freeRegions)
        listedAsFree |= region.Start <= inPageZero && inPageZero < region.End;

    CHECK_FALSE(listedAsFree);
}
#endif
