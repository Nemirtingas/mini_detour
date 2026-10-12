#include "catch.hpp"

#include <mini_detour/mini_detour.h>
#include <spdlog/spdlog.h>

#include <cstring>
#include <string>
#include <vector>

// The region listing tests only printed the regions: they now check what is listed.

template <size_t ExtraNameSpace>
struct NamedRegionInfos : MiniDetour::MemoryManipulation::RegionInfos_t
{
    NamedRegionInfos() { StructSize = sizeof(*this); }

    char extraNameSpace[ExtraNameSpace];
};

// Room for the name, its terminating '\0' included, as the library counts it: what StructSize adds to the structure.
template <typename T>
static size_t NameCapacity()
{
    return sizeof(T) - (sizeof(MiniDetour::MemoryManipulation::RegionInfos_t) - sizeof(MiniDetour::MemoryManipulation::RegionInfos_t::ModuleName));
}

template <typename T>
static std::vector<T> ListAllRegions()
{
    // Twice the count: the tests allocate memory between the two calls.
    std::vector<T> regions(MiniDetour::MemoryManipulation::GetAllRegions(nullptr, 0) * 2);
    const size_t regionCount = MiniDetour::MemoryManipulation::GetAllRegions(regions.data(), regions.size());
    REQUIRE(regionCount <= regions.size());
    regions.resize(regionCount);
    return regions;
}

template <typename T>
static const T *FindRegion(std::vector<T> const &regions, const void *address)
{
    const uintptr_t value = reinterpret_cast<uintptr_t>(address);
    for (auto const &region : regions)
    {
        if (region.Start <= value && value < region.End)
            return &region;
    }

    return nullptr;
}

template <typename T>
static void CheckSortedWithoutOverlap(std::vector<T> const &regions)
{
    for (size_t i = 0; i < regions.size(); ++i)
    {
        INFO("Region " << i << ": [" << (void *)regions[i].Start << ", " << (void *)regions[i].End << ")");
        CHECK(regions[i].Start < regions[i].End);
        if (i > 0)
            CHECK(regions[i - 1].End <= regions[i].Start);
    }
}

// Prints the regions as the tests see them, with MINIDETOUR_TEST_LOG_LEVEL=info: [start-end]: [rwx-] name, "free" for free
// memory.
template <typename T>
static void LogRegions(std::vector<T> const &regions)
{
    for (auto const &region : regions)
    {
        char rights[5] = {'f', 'r', 'e', 'e', '\0'};
        if (region.Rights != MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
        {
            rights[0] = region.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_r ? 'r' : '-';
            rights[1] = region.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_w ? 'w' : '-';
            rights[2] = region.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_x ? 'x' : '-';
            rights[3] = '-';
        }

        SPDLOG_INFO("[{:016X}-{:016X}]: [{}] {}", region.Start, region.End, rights, region.ModuleName);
    }
}

static int MappingsCodeFunction(int x)
{
    return x * 3;
}

static bool HasRights(MiniDetour::MemoryManipulation::MemoryRights rights, MiniDetour::MemoryManipulation::MemoryRights wanted)
{
    return rights != MiniDetour::MemoryManipulation::MemoryRights::mem_unset && (rights & wanted) == wanted;
}

static std::string FullRegionName(const void *address)
{
    NamedRegionInfos<1024> infos;
    MiniDetour::MemoryManipulation::GetRegionInfos(const_cast<void *>(address), &infos);
    return infos.ModuleName;
}

TEST_CASE("Memory mappings", "[vmmap]")
{
    SPDLOG_INFO("Memory mappings with big enough name space");
    auto regions = ListAllRegions<NamedRegionInfos<1024>>();
    LogRegions(regions);
    REQUIRE(!regions.empty());
    CheckSortedWithoutOverlap(regions);

    // The code of the tests executable: executable, and named after it.
    auto code = FindRegion(regions, reinterpret_cast<const void *>(&MappingsCodeFunction));
    REQUIRE(code != nullptr);
    CHECK(HasRights(code->Rights, MiniDetour::MemoryManipulation::MemoryRights::mem_rx));
    INFO("Code region name: " << code->ModuleName);
    CHECK(std::string(code->ModuleName).find("tests") != std::string::npos);

    int local  = 0;
    auto stack = FindRegion(regions, &local);
    REQUIRE(stack != nullptr);
    CHECK(HasRights(stack->Rights, MiniDetour::MemoryManipulation::MemoryRights::mem_rw));

    // The same regions as GetRegionInfos.
    MiniDetour::MemoryManipulation::RegionInfos_t infos;
    MiniDetour::MemoryManipulation::GetRegionInfos(reinterpret_cast<void *>(&MappingsCodeFunction), &infos);
    CHECK(infos.Start == code->Start);
    CHECK(infos.End == code->End);
    CHECK(infos.Rights == code->Rights);
}

TEST_CASE("Memory mappings with name buffer too small", "[vmmap]")
{
    using SmallRegionInfos = NamedRegionInfos<7>;
    const size_t capacity  = NameCapacity<SmallRegionInfos>();

    SPDLOG_INFO("Memory mappings with small module name");
    auto regions = ListAllRegions<SmallRegionInfos>();
    LogRegions(regions);
    REQUIRE(!regions.empty());
    CheckSortedWithoutOverlap(regions);

    // Every name fits in its buffer, with its '\0'.
    for (auto const &region : regions)
        CHECK(memchr(region.ModuleName, '\0', capacity) != nullptr);

    // The name is the start of the full one.
    auto code = FindRegion(regions, reinterpret_cast<const void *>(&MappingsCodeFunction));
    REQUIRE(code != nullptr);
    const std::string fullName  = FullRegionName(reinterpret_cast<const void *>(&MappingsCodeFunction));
    const std::string shortName = code->ModuleName;
    INFO("Full name: " << fullName << ", truncated name: " << shortName);
    REQUIRE(fullName.size() >= capacity);
    CHECK(shortName == fullName.substr(0, capacity - 1));
}

TEST_CASE("Memory mappings with region buffer too small", "[vmmap]")
{
    const uintptr_t sentinel = 0x5A5A5A5A;

    // 5 regions given, a sixth one to check nothing is written after them.
    std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> regions(6);
    for (auto &region : regions)
    {
        region.StructSize = sizeof(region);
        region.Start      = sentinel;
        region.End        = sentinel;
    }

    const size_t regionCount = MiniDetour::MemoryManipulation::GetAllRegions(regions.data(), 5);

    // The count of every region is returned, only 5 are written.
    CHECK(regionCount > 5);
    CHECK(regions[5].Start == sentinel);
    CHECK(regions[5].End == sentinel);

    regions.resize(5);
    SPDLOG_INFO("Only 5 memory mappings without crash");
    LogRegions(regions);
    CheckSortedWithoutOverlap(regions);
    for (auto const &region : regions)
        CHECK(region.ModuleName[0] == '\0');
}
