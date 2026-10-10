#include "catch.hpp"

#include <mini_detour/mini_detour.h>

// On Windows, the old rights were read from VirtualProtect's output even when it failed, where it isn't set.
TEST_CASE("A failed MemoryProtect gives mem_unset as old rights", "[memprotect_failure]")
{
    const size_t pageSize = MiniDetour::MemoryManipulation::PageSize();
    void *page            = MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, pageSize, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);
    REQUIRE(page != nullptr);
    MiniDetour::MemoryManipulation::MemoryFree(page, pageSize);

    auto oldRights = MiniDetour::MemoryManipulation::MemoryRights::mem_rwx;
    if (MiniDetour::MemoryManipulation::MemoryProtect(page, pageSize, MiniDetour::MemoryManipulation::MemoryRights::mem_rx, &oldRights))
    {
        // qemu user mode accepts mprotect on memory that isn't mapped.
        WARN("MemoryProtect succeeded on freed memory, test skipped.");
        return;
    }

    CHECK(oldRights == MiniDetour::MemoryManipulation::MemoryRights::mem_unset);
}
