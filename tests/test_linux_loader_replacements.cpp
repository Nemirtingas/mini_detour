#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_LINUX)
#include <dlfcn.h>
#include <unistd.h>

#include <atomic>

// The replacement calls the real function, so the rest of the process keeps working while it is in place, and counts its
// calls: the library must not make any.
static std::atomic<int> g_DlinfoCalls(0);
static int (*g_Dlinfo)(void *, int, void *);

static int CountingDlinfo(void *handle, int request, void *info)
{
    ++g_DlinfoCalls;
    return g_Dlinfo(handle, request, info);
}

// Calls dlinfo through the imports of the executable, in a function of its own: in the test, the compiler can keep the
// import read before the replacement.
__attribute__((noinline)) static int CallDlinfo(void *handle, int request, void *info)
{
    return dlinfo(handle, request, info);
}

static pid_t LoaderReplacementsGetpid()
{
    return 12345;
}

// The library called dlinfo through the imports of the image linking it (the tests executable here): once it was
// replaced there, the library called the replacement to find the modules.
TEST_CASE("dlinfo replaced in the executable isn't called by the library", "[loader_replacements]")
{
    void *executable = dlopen(nullptr, RTLD_LAZY);
    REQUIRE(executable != nullptr);

    // Set before the replacement: another thread may call it as soon as it is written. Not &dlinfo: taking its address in
    // the (non PIE) executable makes its PLT entry the address of the function, which jumps through the replaced slot.
    g_Dlinfo = reinterpret_cast<int (*)(void *, int, void *)>(dlsym(RTLD_DEFAULT, "dlinfo"));
    REQUIRE(g_Dlinfo != nullptr);

    MiniDetour::ModuleManipulation::IATReplaceParameter_t loader{};
    loader.IATName       = "dlinfo";
    loader.NewIATAddress = reinterpret_cast<void *>(&CountingDlinfo);
    REQUIRE(MiniDetour::ModuleManipulation::ReplaceModuleIATs(executable, &loader, 1) == 1);

    // The replacement is called through the imports of the executable.
    g_DlinfoCalls = 0;
    void *linkMap = nullptr;
    CallDlinfo(executable, RTLD_DI_LINKMAP, &linkMap);
    const int testCalls = g_DlinfoCalls;

    // An import of the executable, replaced and restored.
    const pid_t pid = getpid();
    MiniDetour::ModuleManipulation::IATReplaceParameter_t parameter{};
    parameter.IATName       = "getpid";
    parameter.NewIATAddress = reinterpret_cast<void *>(&LoaderReplacementsGetpid);

    g_DlinfoCalls              = 0;
    const size_t replaced      = MiniDetour::ModuleManipulation::ReplaceModuleIATs(executable, &parameter, 1);
    const pid_t replacedGetpid = getpid();
    const size_t restored      = MiniDetour::ModuleManipulation::RestoreModuleIATs(executable, &parameter, 1);
    const int libraryCalls     = g_DlinfoCalls;

    REQUIRE(MiniDetour::ModuleManipulation::RestoreModuleIATs(executable, &loader, 1) == 1);

    CHECK(testCalls == 1);
    CHECK(libraryCalls == 0);
    CHECK(replaced == 1);
    CHECK(replacedGetpid == 12345);
    CHECK(restored == 1);
    CHECK(getpid() == pid);
    dlclose(executable);
}
#endif
