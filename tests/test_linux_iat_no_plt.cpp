#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_LINUX)
#include <dlfcn.h>
#include <string.h>

static int MyPutsCalls = 0;

static int MyPuts(const char*)
{
    ++MyPutsCalls;
    return 1234;
}

// BUGS.md #34: imports of code built with -fno-plt are GLOB_DAT relocations in .rela.dyn, not JUMP_SLOT ones.
TEST_CASE("IAT hook of a -fno-plt import", "[iat_no_plt]")
{
    void* h = dlopen("./no_plt_test_library.so", RTLD_NOW);
    REQUIRE(h != nullptr);

    auto noPltPuts = reinterpret_cast<int (*)(const char*)>(dlsym(h, "no_plt_puts"));
    REQUIRE(noPltPuts != nullptr);

    MiniDetour::ModuleManipulation::IATDetails_t imports[32];
    auto importCount = MiniDetour::ModuleManipulation::GetAllIATSymbols(h, imports, 32);
    bool putsListed = false;
    for (size_t i = 0; i < importCount; ++i)
        putsListed |= strcmp(imports[i].ImportName, "puts") == 0;

    CHECK(putsListed);

    MiniDetour::ModuleManipulation::IATReplaceParameter_t iatReplace{};
    iatReplace.IATModuleName = "";
    iatReplace.IATName = "puts";
    iatReplace.NewIATAddress = (void*)&MyPuts;
    REQUIRE(MiniDetour::ModuleManipulation::ReplaceModuleIATs(h, &iatReplace, 1) == 1);
    CHECK(iatReplace.IATCallAddress == dlsym(RTLD_DEFAULT, "puts"));

    CHECK(noPltPuts("hooked") == 1234);
    CHECK(MyPutsCalls == 1);

    CHECK(MiniDetour::ModuleManipulation::RestoreModuleIATs(h, &iatReplace, 1) == 1);
    CHECK(noPltPuts("restored") != 1234);
    CHECK(MyPutsCalls == 1);

    dlclose(h);
}
#endif
