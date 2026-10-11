#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_APPLE)
#include <dlfcn.h>
#include <string.h>

#include <vector>

extern "C" __attribute__((visibility("default"), noinline)) int MiniDetourExecutableExport(int a)
{
    return a + 1;
}

// Symbol values are link addresses. They were added to the load address, which is only right when
// __TEXT is linked at 0 (dylibs): an executable is linked at 0x100000000 and its exports were all wrong.
TEST_CASE("Exports of the main executable", "[macos_executable_exports]")
{
    Dl_info info;
    REQUIRE(dladdr((void *)&MiniDetourExecutableExport, &info) != 0);
    void *h = dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD);
    REQUIRE(h != nullptr);

    auto count = MiniDetour::ModuleManipulation::GetAllExportedSymbols(h, nullptr, 0);
    REQUIRE(count > 0);
    std::vector<MiniDetour::ModuleManipulation::ExportDetails_t> exports(count);
    exports.resize(MiniDetour::ModuleManipulation::GetAllExportedSymbols(h, exports.data(), exports.size()));

    void *found = nullptr;
    for (auto const &symbol : exports)
    {
        if (symbol.ExportName != nullptr && strcmp(symbol.ExportName, "MiniDetourExecutableExport") == 0)
            found = symbol.ExportCallAddress;
    }

    CHECK(found == (void *)&MiniDetourExecutableExport);
    dlclose(h);
}
#endif
