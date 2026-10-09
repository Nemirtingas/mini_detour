#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_OS_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <stddef.h>
#include <string>
#include <vector>

static std::string GetCurrentModulePathUtf8()
{
    std::wstring path(32768, L'\0');
    path.resize(GetModuleFileNameW(nullptr, &path[0], static_cast<DWORD>(path.size())));

    std::string utf8(WideCharToMultiByte(CP_UTF8, 0, path.c_str(), static_cast<int>(path.size()), nullptr, 0, nullptr, nullptr), '\0');
    WideCharToMultiByte(CP_UTF8, 0, path.c_str(), static_cast<int>(path.size()), &utf8[0], static_cast<int>(utf8.size()), nullptr, nullptr);
    return utf8;
}

static void RegionNameTestFunction()
{
}

// BUGS.md #25: when the module name exactly filled ModuleName, the terminating '\0' was written one byte past it.
TEST_CASE("Region name exactly filling the buffer doesn't overflow", "[region_name]")
{
    const std::string modulePath = GetCurrentModulePathUtf8();
    REQUIRE(!modulePath.empty());

    const size_t nameOffset  = offsetof(MiniDetourMemoryManipulationRegionInfos_t, ModuleName);
    const size_t nameSize    = modulePath.size();
    const uint8_t canary     = 0xAB;
    const size_t canarySize  = 16;
    std::vector<uint8_t> buffer(nameOffset + nameSize + canarySize + sizeof(MiniDetourMemoryManipulationRegionInfos_t), canary);

    auto *regionInfos = reinterpret_cast<MiniDetourMemoryManipulationRegionInfos_t *>(buffer.data());
    // StructSize leaves exactly nameSize bytes for ModuleName.
    regionInfos->StructSize = sizeof(MiniDetourMemoryManipulationRegionInfos_t) - sizeof(regionInfos->ModuleName) + nameSize;

    MiniDetourMemoryManipulationGetRegionInfos(reinterpret_cast<void *>(&RegionNameTestFunction), regionInfos);

    for (size_t i = 0; i < canarySize; ++i)
    {
        INFO("byte " << i << " after ModuleName");
        CHECK(buffer[nameOffset + nameSize + i] == canary);
    }

    // The name is truncated to fit with its terminating '\0'.
    const std::string name(regionInfos->ModuleName, strnlen(regionInfos->ModuleName, nameSize));
    CHECK(name.size() < nameSize);
    CHECK(modulePath.compare(0, name.size(), name) == 0);
}

TEST_CASE("Region name with enough space is complete", "[region_name]")
{
    const std::string modulePath = GetCurrentModulePathUtf8();

    std::vector<uint8_t> buffer(sizeof(MiniDetourMemoryManipulationRegionInfos_t) + modulePath.size() + 1, 0);
    auto *regionInfos       = reinterpret_cast<MiniDetourMemoryManipulationRegionInfos_t *>(buffer.data());
    regionInfos->StructSize = buffer.size();

    MiniDetourMemoryManipulationGetRegionInfos(reinterpret_cast<void *>(&RegionNameTestFunction), regionInfos);
    CHECK(std::string(regionInfos->ModuleName) == modulePath);
}

#endif
