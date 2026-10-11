#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#include <algorithm>
#include <chrono>
#include <limits>
#include <vector>

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

#if defined(MINIDETOUR_OS_WINDOWS)
#include <Windows.h>
#define NEAR_TEST_LIBRARY "./export_hook_test_library.dll"
#define NEAR_TEST_LOAD(path) ((void *)LoadLibraryA(path))
#define NEAR_TEST_SYMBOL(handle, name) ((void *)GetProcAddress((HMODULE)(handle), name))
#define NEAR_TEST_FREE(handle) FreeLibrary((HMODULE)(handle))
#else
#include <dlfcn.h>
#if defined(MINIDETOUR_OS_APPLE)
#define NEAR_TEST_LIBRARY "./export_hook_test_library.dylib"
#else
#define NEAR_TEST_LIBRARY "./export_hook_test_library.so"
#endif
#define NEAR_TEST_LOAD(path) dlopen(path, RTLD_NOW)
#define NEAR_TEST_SYMBOL(handle, name) dlsym(handle, name)
#define NEAR_TEST_FREE(handle) dlclose(handle)
#endif

// Free regions were sorted by the distance to their start only, so a large free region holding the hint
// came after a small one above the module, and the search started at the region start, far from the hint.
TEST_CASE("Near allocation inside a large free region", "[mem alloc near]")
{
    void *h = NEAR_TEST_LOAD(NEAR_TEST_LIBRARY);
    REQUIRE(h != nullptr);
    auto symbol = reinterpret_cast<uintptr_t>(NEAR_TEST_SYMBOL(h, "add"));
    REQUIRE(symbol != 0);

    // Below the shared libraries the address space is mostly free.
    const uintptr_t hint = symbol - 0x10000000;
    const size_t size    = MiniDetour::MemoryManipulation::PageSize();

    // Smallest possible distance, from the free regions (earlier tests may already use the memory around the hint).
    std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> freeRegions(MiniDetour::MemoryManipulation::GetFreeRegions(nullptr, 0) * 2);
    freeRegions.resize(MiniDetour::MemoryManipulation::GetFreeRegions(freeRegions.data(), freeRegions.size()));
    uintptr_t bestDistance = (std::numeric_limits<uintptr_t>::max)();
    for (auto const &region : freeRegions)
    {
        if (region.End - region.Start < size)
            continue;

        const uintptr_t closest = (std::min)((std::max)(hint, region.Start), region.End - size);
        bestDistance            = (std::min)(bestDistance, closest > hint ? closest - hint : hint - closest);
    }

    auto address =
        reinterpret_cast<uintptr_t>(MiniDetour::MemoryManipulation::MemoryAlloc(reinterpret_cast<void *>(hint), size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw));
    REQUIRE(address != 0);

    // Allocations are aligned on the allocation granularity (64 KB on Windows).
    const uintptr_t distance = address > hint ? address - hint : hint - address;
    CHECK(distance <= bestDistance + 0x10000);

    MiniDetour::MemoryManipulation::MemoryFree(reinterpret_cast<void *>(address), size);
    NEAR_TEST_FREE(h);
}
