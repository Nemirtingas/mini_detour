#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_OS_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <vector>

using MiniDetour::MemoryManipulation::MemoryRights;

// Rights of the region starting at address, as listed by GetAllRegions.
static MemoryRights GetListedRegionRights(void *address)
{
    std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> regions(MiniDetour::MemoryManipulation::GetAllRegions(nullptr, 0) * 2);
    regions.resize(std::min(regions.size(), MiniDetour::MemoryManipulation::GetAllRegions(regions.data(), regions.size())));

    for (auto const &region : regions)
    {
        if (region.Start == reinterpret_cast<uintptr_t>(address))
            return region.Rights;
    }

    return MemoryRights::mem_unset;
}

static void CheckCopyOnWriteView(DWORD mappingProtection, DWORD viewAccess, MemoryRights expectedRights)
{
    const DWORD size = 4096;
    HANDLE mapping   = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, mappingProtection, 0, size, nullptr);
    REQUIRE(mapping != nullptr);

    void *view = MapViewOfFile(mapping, viewAccess, 0, 0, size);
    REQUIRE(view != nullptr);

    MEMORY_BASIC_INFORMATION nativeInfos;
    REQUIRE(VirtualQuery(view, &nativeInfos, sizeof(nativeInfos)) != 0);
    INFO("native protection: " << nativeInfos.Protect);

    MiniDetour::MemoryManipulation::RegionInfos_t infos;
    MiniDetour::MemoryManipulation::GetRegionInfos(view, &infos);
    CHECK(infos.Rights == expectedRights);
    CHECK(GetListedRegionRights(view) == expectedRights);

    UnmapViewOfFile(view);
    CloseHandle(mapping);
}

// BUGS.md #26: copy-on-write pages were reported as mem_none (RestoreFunction takes mem_none for freed memory).
TEST_CASE("Copy-on-write pages have the right rights", "[windows_rights]")
{
    CheckCopyOnWriteView(PAGE_READWRITE, FILE_MAP_COPY, MemoryRights::mem_rw);
    CheckCopyOnWriteView(PAGE_EXECUTE_READWRITE, FILE_MAP_COPY | FILE_MAP_EXECUTE, MemoryRights::mem_rwx);
}

// BUGS.md #26: GetAllRegions didn't mask the protection modifiers (PAGE_GUARD, PAGE_NOCACHE...).
TEST_CASE("Guard pages have the rights of their protection", "[windows_rights]")
{
    void *memory = VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD);
    REQUIRE(memory != nullptr);

    MiniDetour::MemoryManipulation::RegionInfos_t infos;
    MiniDetour::MemoryManipulation::GetRegionInfos(memory, &infos);
    CHECK(infos.Rights == MemoryRights::mem_rw);
    CHECK(GetListedRegionRights(memory) == MemoryRights::mem_rw);

    VirtualFree(memory, 0, MEM_RELEASE);
}

#endif
