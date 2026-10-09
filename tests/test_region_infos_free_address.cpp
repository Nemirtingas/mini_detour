#include "catch.hpp"

#include <mini_detour/mini_detour.h>

// BUGS.md #36: on macOS, GetRegionInfos left the output untouched for a free address, so callers read
// whatever was there (restoring rights from it, for example).
TEST_CASE("Region infos of a free address", "[region_infos_free]")
{
    const size_t size = MiniDetour::MemoryManipulation::PageSize();
    void* address = MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);
    REQUIRE(address != nullptr);
    MiniDetour::MemoryManipulation::MemoryFree(address, size);

    MiniDetour::MemoryManipulation::RegionInfos_t infos;
    infos.Rights = MiniDetour::MemoryManipulation::MemoryRights::mem_rwx;
    infos.Start = 1;
    infos.End = 2;
    MiniDetour::MemoryManipulation::GetRegionInfos(address, &infos);

    // Windows reports free memory as mem_none, Linux and macOS as mem_unset.
    CHECK((infos.Rights == MiniDetour::MemoryManipulation::MemoryRights::mem_unset || infos.Rights == MiniDetour::MemoryManipulation::MemoryRights::mem_none));
}
