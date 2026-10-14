#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_APPLE)
#include <dlfcn.h>
#include <string.h>

#include <vector>

TEST_CASE("Exports of a shared cache image are listed from its symbol table", "[macos_shared_cache_exports]")
{
    void *libSystem = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW | RTLD_NOLOAD);
    REQUIRE(libSystem != nullptr);

    const size_t exportCount = MiniDetour::ModuleManipulation::GetAllExportedSymbols(libSystem, nullptr, 0);
    REQUIRE(exportCount > 0);

    std::vector<MiniDetour::ModuleManipulation::ExportDetails_t> exports(exportCount);
    REQUIRE(MiniDetour::ModuleManipulation::GetAllExportedSymbols(libSystem, exports.data(), exports.size()) == exportCount);

    size_t resolvableExportCount = 0;
    for (auto const &symbol : exports)
    {
        REQUIRE(symbol.ExportName != nullptr);

        void *resolved = dlsym(libSystem, symbol.ExportName);
        if (resolved != nullptr)
        {
            ++resolvableExportCount;
            CHECK(symbol.ExportCallAddress == resolved);
        }
    }

    CHECK(resolvableExportCount > 0);
    dlclose(libSystem);
}
#endif
