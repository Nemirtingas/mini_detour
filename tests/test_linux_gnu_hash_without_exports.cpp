#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_LINUX)
#include <dlfcn.h>

// BUGS.md #30: with no hashed symbol every GNU hash bucket is 0, and the symbol count was computed from chains[0 - symndx].
TEST_CASE("Module without exported symbols", "[gnu_hash_empty]")
{
    void *h = dlopen("./no_export_test_library.so", RTLD_NOW);
    REQUIRE(h != nullptr);

    CHECK(MiniDetour::ModuleManipulation::GetAllExportedSymbols(h, nullptr, 0) == 0);

    MiniDetour::ModuleManipulation::ExportDetails_t exportDetails[4];
    CHECK(MiniDetour::ModuleManipulation::GetAllExportedSymbols(h, exportDetails, 4) == 0);

    // Imports are still listed from the relocations.
    CHECK(MiniDetour::ModuleManipulation::GetAllIATSymbols(h, nullptr, 0) > 0);

    dlclose(h);
}
#endif
