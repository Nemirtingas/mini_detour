#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#include <limits>

// BUGS.md #28: mmap returns MAP_FAILED ((void*)-1) on failure, which was returned as a valid allocation.
TEST_CASE("Failed allocation returns nullptr", "[mem alloc failure]")
{
    // Larger than any free range, even for a 32-bit process on a 64-bit kernel, but small enough
    // that the near allocation search doesn't wrap around when adding it to a 64-bit address.
    const size_t size = sizeof(void*) == 8 ? (size_t)1 << 62 : (std::numeric_limits<size_t>::max() - 0x100000) & ~(size_t)0xFFFF;
    void* const hint = (void*)0x10000;

    void* anywhere = MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);
    CHECK(anywhere == nullptr);

    void* near = MiniDetour::MemoryManipulation::MemoryAlloc(hint, size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);
    CHECK(near == nullptr);
}
