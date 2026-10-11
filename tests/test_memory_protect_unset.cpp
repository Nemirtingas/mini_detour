#include "catch.hpp"

#include "test_utils.h"

// Restoring rights read from an unknown region (mem_unset) used to apply PROT_NONE.
TEST_CASE("MemoryProtect refuses mem_unset", "[memprotect_unset]")
{
    CodeBuffer buffer;
    REQUIRE(buffer.IsValid());

    CHECK_FALSE(MiniDetour::MemoryManipulation::MemoryProtect(buffer.Data(), 16, MiniDetour::MemoryManipulation::MemoryRights::mem_unset));

    MiniDetour::MemoryManipulation::RegionInfos_t infos;
    MiniDetour::MemoryManipulation::GetRegionInfos(buffer.Data(), &infos);
    CHECK(infos.Rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rx);
}
