#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_LINUX)
#include <dlfcn.h>

static int MyPuts(const char *)
{
    return 0;
}

// An imported symbol (st_shndx == SHN_UNDEF) was accepted as an export and its .dynsym entry rewritten.
TEST_CASE("Export replace ignores imported symbols", "[export_skip_imports]")
{
    void *h = dlopen("./export_hook_test_library.so", RTLD_NOW);
    REQUIRE(h != nullptr);

    // The library imports puts but doesn't export it.
    MiniDetour::ModuleManipulation::ExportReplaceParameter_t exportDetails{"puts", (void *)&MyPuts, nullptr};
    auto replaced = MiniDetour::ModuleManipulation::ReplaceModuleExports(h, &exportDetails, 1);
    CHECK(replaced == 0);
    if (replaced != 0)
        MiniDetour::ModuleManipulation::RestoreModuleExports(h, &exportDetails, 1);

    // Real exports are still found.
    MiniDetour::ModuleManipulation::ExportReplaceParameter_t addDetails{"add", (void *)&MyPuts, nullptr};
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleExports(h, &addDetails, 1) == 1);
    CHECK(MiniDetour::ModuleManipulation::RestoreModuleExports(h, &addDetails, 1) == 1);

    dlclose(h);
}
#endif
