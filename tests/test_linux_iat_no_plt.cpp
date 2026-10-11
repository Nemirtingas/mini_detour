#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_LINUX)
#include <dlfcn.h>
#include <string.h>

static int MyPutsCalls = 0;

static int MyPuts(const char *)
{
    ++MyPutsCalls;
    return 1234;
}

// Imports of code built with -fno-plt are GLOB_DAT relocations in .rela.dyn, not JUMP_SLOT ones.
TEST_CASE("IAT hook of a -fno-plt import", "[iat_no_plt]")
{
    void *h = dlopen("./no_plt_test_library.so", RTLD_NOW);
    REQUIRE(h != nullptr);

    auto noPltPuts = reinterpret_cast<int (*)(const char *)>(dlsym(h, "no_plt_puts"));
    REQUIRE(noPltPuts != nullptr);

    MiniDetour::ModuleManipulation::IATDetails_t imports[32];
    auto importCount = MiniDetour::ModuleManipulation::GetAllIATSymbols(h, imports, 32);
    bool putsListed  = false;
    for (size_t i = 0; i < importCount; ++i)
        putsListed |= strcmp(imports[i].ImportName, "puts") == 0;

    CHECK(putsListed);

    MiniDetour::ModuleManipulation::IATReplaceParameter_t iatReplace{};
    iatReplace.IATModuleName = "";
    iatReplace.IATName       = "puts";
    iatReplace.NewIATAddress = (void *)&MyPuts;
    REQUIRE(MiniDetour::ModuleManipulation::ReplaceModuleIATs(h, &iatReplace, 1) == 1);
    // When a non-PIE executable takes the address of puts, its PLT entry becomes the canonical address returned by
    // dlsym(RTLD_DEFAULT). Depending on the architecture, the GOT holds that address or the libc definition.
    void *libc = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
    REQUIRE(libc != nullptr);
    CHECK((iatReplace.IATCallAddress == dlsym(RTLD_DEFAULT, "puts") || iatReplace.IATCallAddress == dlsym(libc, "puts")));
    dlclose(libc);

    CHECK(noPltPuts("hooked") == 1234);
    CHECK(MyPutsCalls == 1);

    CHECK(MiniDetour::ModuleManipulation::RestoreModuleIATs(h, &iatReplace, 1) == 1);
    CHECK(noPltPuts("restored") != 1234);
    CHECK(MyPutsCalls == 1);

    dlclose(h);
}
#endif
