#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_APPLE)
#include <dlfcn.h>

// BUGS.md #35: when no loaded image matched the handle (dlopen(NULL) handle for example),
// the module functions dereferenced a null module base.
TEST_CASE("Module functions with a handle of no loaded image", "[macos_unknown_module]")
{
    void* h = dlopen(nullptr, RTLD_NOW);
    REQUIRE(h != nullptr);

    CHECK(MiniDetour::ModuleManipulation::GetAllExportedSymbols(h, nullptr, 0) == 0);

    MiniDetour::ModuleManipulation::ExportReplaceParameter_t exportReplace{ "main", nullptr, nullptr };
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleExports(h, &exportReplace, 1) == 0);
    CHECK(exportReplace.ExportCallAddress == nullptr);

    dlclose(h);
}
#endif
