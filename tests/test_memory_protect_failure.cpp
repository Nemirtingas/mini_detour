#include "catch.hpp"

#include <mini_detour/mini_detour.h>

// On Windows, the old rights were read from VirtualProtect's output even when it failed, where it isn't set.
TEST_CASE("A failed MemoryProtect gives mem_unset as old rights", "[memprotect_failure]")
{
    // The last page of the address space and the one after it: the range wraps around, every system refuses it (qemu
    // user mode included, which accepts mprotect on memory that isn't mapped).
    const size_t pageSize = MiniDetour::MemoryManipulation::PageSize();
    void *lastPage        = reinterpret_cast<void *>(~static_cast<uintptr_t>(pageSize - 1));

    auto oldRights = MiniDetour::MemoryManipulation::MemoryRights::mem_rwx;
    CHECK_FALSE(MiniDetour::MemoryManipulation::MemoryProtect(lastPage, pageSize * 2, MiniDetour::MemoryManipulation::MemoryRights::mem_rx, &oldRights));
    CHECK(oldRights == MiniDetour::MemoryManipulation::MemoryRights::mem_unset);
}
