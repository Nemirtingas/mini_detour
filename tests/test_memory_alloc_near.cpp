#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#include <chrono>
#include <limits>

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
