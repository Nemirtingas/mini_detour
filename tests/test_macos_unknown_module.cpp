#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_APPLE)
// When no loaded image matched the handle, the module functions dereferenced a null module base.
TEST_CASE("Module functions with a handle of no loaded image", "[macos_unknown_module]")
{
    // Not a handle dlopen gave: no image matches it.
    int notAHandle = 0;
    void *h        = &notAHandle;

    CHECK(MiniDetour::ModuleManipulation::GetAllExportedSymbols(h, nullptr, 0) == 0);

    MiniDetour::ModuleManipulation::ExportReplaceParameter_t exportReplace{"main", nullptr, nullptr};
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleExports(h, &exportReplace, 1) == 0);
    CHECK(exportReplace.ExportCallAddress == nullptr);
}
#endif
