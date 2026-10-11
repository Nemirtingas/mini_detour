#include "catch.hpp"
#include "test_utils.h"

#include <utility>
#include <vector>

#if defined(MINIDETOUR_OS_WINDOWS)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <dlfcn.h>
#endif

static void *MainModuleHandle()
{
#if defined(MINIDETOUR_OS_WINDOWS)
    return reinterpret_cast<void *>(GetModuleHandleA(nullptr));
#else
    return dlopen(nullptr, RTLD_NOW);
#endif
}

static int InputChecksFunction()
{
    return 1;
}

// GetRegionInfos computed the ModuleName size from StructSize: a C caller that didn't set it (0) made the size wrap
// around, and the module name was written past the structure.
TEST_CASE("GetRegionInfos with a too small StructSize doesn't write past the structure", "[c_api_input_checks]")
{
    const size_t structSize = sizeof(MiniDetourMemoryManipulationRegionInfos_t);
    std::vector<uint8_t> buffer(structSize + 256, 0xAB);
    auto regionInfos        = reinterpret_cast<MiniDetourMemoryManipulationRegionInfos_t *>(buffer.data());
    regionInfos->StructSize = 0;

    // An address inside the test executable: its region has a module name.
    MiniDetourMemoryManipulationGetRegionInfos(reinterpret_cast<void *>(&InputChecksFunction), regionInfos);

    CHECK(regionInfos->Rights == mem_unset);
    for (size_t i = structSize; i < buffer.size(); ++i)
    {
        INFO("Byte " << i << " after the structure was modified");
        REQUIRE(buffer[i] == 0xAB);
    }

    MiniDetourMemoryManipulationGetRegionInfos(reinterpret_cast<void *>(&InputChecksFunction), nullptr);
}

TEST_CASE("Hook functions refuse a null handle", "[c_api_input_checks]")
{
    MiniDetourHookTRestoreOnDestroy(nullptr, true);
    CHECK_FALSE(MiniDetourHookTCanHook(nullptr, reinterpret_cast<void *>(&InputChecksFunction)));
    CHECK(MiniDetourHookTHookFunction(nullptr, reinterpret_cast<void *>(&InputChecksFunction), reinterpret_cast<void *>(&InputChecksFunction)) == nullptr);
    CHECK(MiniDetourHookTRestoreFunction(nullptr) == nullptr);
    CHECK(MiniDetourHookTGetHookFunction(nullptr) == nullptr);
    CHECK(MiniDetourHookTGetOriginalFunction(nullptr) == nullptr);
    MiniDetourHookTFree(nullptr);

    CHECK_FALSE(MiniDetourHookTReplaceFunction(nullptr, reinterpret_cast<void *>(&InputChecksFunction)));
    CHECK_FALSE(MiniDetourHookTReplaceFunction(reinterpret_cast<void *>(&InputChecksFunction), nullptr));

    minidetour_hook_handle_t hook = MiniDetourHookTAlloc();
    REQUIRE(hook != nullptr);
    CHECK_FALSE(MiniDetourHookTCanHook(hook, nullptr));
    CHECK(MiniDetourHookTHookFunction(hook, nullptr, reinterpret_cast<void *>(&InputChecksFunction)) == nullptr);
    CHECK(MiniDetourHookTHookFunction(hook, reinterpret_cast<void *>(&InputChecksFunction), nullptr) == nullptr);
    MiniDetourHookTFree(hook);
}

// A moved from Hook_t has a null handle: using it crashed.
TEST_CASE("A moved from Hook_t can still be used", "[c_api_input_checks]")
{
    MiniDetour::Hook_t hook;
    MiniDetour::Hook_t other(std::move(hook));

    hook.RestoreOnDestroy(true);
    CHECK_FALSE(hook.CanHook(reinterpret_cast<void *>(&InputChecksFunction)));
    CHECK(hook.HookFunction(reinterpret_cast<void *>(&InputChecksFunction), reinterpret_cast<void *>(&InputChecksFunction)) == nullptr);
    CHECK(hook.RestoreFunction() == nullptr);
    CHECK(hook.GetHookFunction() == nullptr);
    CHECK(hook.GetOriginalFunction() == nullptr);
}

TEST_CASE("Module functions refuse a null module or null names", "[c_api_input_checks]")
{
    MiniDetour::ModuleManipulation::ExportReplaceParameter_t exportParameter{};
    exportParameter.ExportName       = nullptr;
    exportParameter.NewExportAddress = reinterpret_cast<void *>(&InputChecksFunction);

    MiniDetour::ModuleManipulation::IATReplaceParameter_t iatParameter{};
    iatParameter.IATModuleName = nullptr;
    iatParameter.IATName       = nullptr;
    iatParameter.NewIATAddress = reinterpret_cast<void *>(&InputChecksFunction);

    // Null module handle
    CHECK(MiniDetour::ModuleManipulation::GetAllExportedSymbols(nullptr, nullptr, 0) == 0);
    CHECK(MiniDetour::ModuleManipulation::GetAllIATSymbols(nullptr, nullptr, 0) == 0);
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleExports(nullptr, &exportParameter, 1) == 0);
    CHECK(exportParameter.ExportCallAddress == nullptr);
    CHECK(MiniDetour::ModuleManipulation::RestoreModuleExports(nullptr, &exportParameter, 1) == 0);
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleIATs(nullptr, &iatParameter, 1) == 0);
    CHECK(iatParameter.IATCallAddress == nullptr);
    CHECK(MiniDetour::ModuleManipulation::RestoreModuleIATs(nullptr, &iatParameter, 1) == 0);

    // Null array with entries
    void *module = MainModuleHandle();
    REQUIRE(module != nullptr);
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleExports(module, nullptr, 1) == 0);
    CHECK(MiniDetour::ModuleManipulation::RestoreModuleExports(module, nullptr, 1) == 0);
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleIATs(module, nullptr, 1) == 0);
    CHECK(MiniDetour::ModuleManipulation::RestoreModuleIATs(module, nullptr, 1) == 0);

    // Null names: the entry fails, without crashing.
    exportParameter.NewExportAddress = reinterpret_cast<void *>(&InputChecksFunction);
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleExports(module, &exportParameter, 1) == 0);
    CHECK(exportParameter.ExportCallAddress == nullptr);
    iatParameter.NewIATAddress = reinterpret_cast<void *>(&InputChecksFunction);
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleIATs(module, &iatParameter, 1) == 0);
    CHECK(iatParameter.IATCallAddress == nullptr);
}
