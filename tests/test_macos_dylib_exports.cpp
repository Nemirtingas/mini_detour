#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_APPLE)
#include <dlfcn.h>

#include <vector>

TEST_CASE("Exports of a non-cache dylib match dlsym addresses", "[macos_dylib_exports]")
{
    void *dylib = dlopen("./export_hook_test_library.dylib", RTLD_NOW);
    REQUIRE(dylib != nullptr);

    const size_t exportCount = MiniDetour::ModuleManipulation::GetAllExportedSymbols(dylib, nullptr, 0);
    REQUIRE(exportCount == 3);

    std::vector<MiniDetour::ModuleManipulation::ExportDetails_t> exports(exportCount);
    REQUIRE(MiniDetour::ModuleManipulation::GetAllExportedSymbols(dylib, exports.data(), exports.size()) == exportCount);

    for (auto const &symbol : exports)
    {
        REQUIRE(symbol.ExportName != nullptr);
        void *resolved = dlsym(dylib, symbol.ExportName);
        REQUIRE(resolved != nullptr);
        CHECK(symbol.ExportCallAddress == resolved);
    }

    dlclose(dylib);
}
#endif
