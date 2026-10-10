#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_OS_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <chrono>
#include <string>
#include <vector>

static void RegionInfosCostFunction()
{
}

static DWORD WINAPI WaitingThread(LPVOID event)
{
    WaitForSingleObject(static_cast<HANDLE>(event), INFINITE);
    return 0;
}

// GetRegionInfos listed the heaps and opened every thread of the process to name the region, even when the structure
// has no room for a name. The library calls it several times per hook.
TEST_CASE("GetRegionInfos without room for a name doesn't list the threads", "[windows_region_infos_cost]")
{
    HANDLE event = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    REQUIRE(event != nullptr);

    std::vector<HANDLE> threads;
    for (int i = 0; i < 64; ++i)
    {
        HANDLE thread = CreateThread(nullptr, 0, &WaitingThread, event, 0, nullptr);
        if (thread != nullptr)
            threads.push_back(thread);
    }

    const int calls = 500;
    auto start      = std::chrono::steady_clock::now();
    for (int i = 0; i < calls; ++i)
    {
        MiniDetour::MemoryManipulation::RegionInfos_t infos;
        MiniDetour::MemoryManipulation::GetRegionInfos(reinterpret_cast<void *>(&RegionInfosCostFunction), &infos);
        REQUIRE(infos.Rights != MiniDetour::MemoryManipulation::MemoryRights::mem_unset);
    }
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    SetEvent(event);
    for (auto thread : threads)
    {
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }
    CloseHandle(event);

    INFO(calls << " calls took " << elapsed.count() << " ms");
    CHECK(elapsed.count() < 250);
}

TEST_CASE("A heap region is still named", "[windows_region_infos_cost]")
{
    std::vector<uint8_t> buffer(sizeof(MiniDetourMemoryManipulationRegionInfos_t) + 256, 0);
    auto *regionInfos       = reinterpret_cast<MiniDetourMemoryManipulationRegionInfos_t *>(buffer.data());
    regionInfos->StructSize = buffer.size();

    // The region name is looked up from the start of the region, where the heap starts.
    MiniDetourMemoryManipulationGetRegionInfos(GetProcessHeap(), regionInfos);
    CHECK(std::string(regionInfos->ModuleName) == "[heap]");
}

#endif
