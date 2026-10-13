#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_APPLE)
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <atomic>
#include <vector>

static pid_t FakeGetPid()
{
    return 12345;
}

static void *ExecutableHandle()
{
    Dl_info info;
    if (dladdr(reinterpret_cast<void *>(&FakeGetPid), &info) == 0)
        return nullptr;

    return dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD);
}

static std::vector<MiniDetour::ModuleManipulation::IATDetails_t> GetImports(void *module)
{
    std::vector<MiniDetour::ModuleManipulation::IATDetails_t> imports(MiniDetour::ModuleManipulation::GetAllIATSymbols(module, nullptr, 0));
    imports.resize(MiniDetour::ModuleManipulation::GetAllIATSymbols(module, imports.data(), imports.size()));
    return imports;
}

static MiniDetour::ModuleManipulation::IATDetails_t const *FindImport(std::vector<MiniDetour::ModuleManipulation::IATDetails_t> const &imports, const char *name)
{
    for (auto const &import : imports)
    {
        if (import.ImportName != nullptr && strcmp(import.ImportName, name) == 0)
            return &import;
    }

    return nullptr;
}

// Import replacement wasn't implemented on macOS.
TEST_CASE("Imports of the main executable are listed", "[macos_imports]")
{
    void *executable = ExecutableHandle();
    REQUIRE(executable != nullptr);

    auto imports = GetImports(executable);
    REQUIRE(!imports.empty());

    auto getpidImport = FindImport(imports, "getpid");
    REQUIRE(getpidImport != nullptr);
    CHECK(strstr(getpidImport->ImportModuleName, "libSystem.B.dylib") != nullptr);
    CHECK(getpidImport->ImportCallAddress == dlsym(RTLD_DEFAULT, "getpid"));

    dlclose(executable);
}

// Whatever binding the toolchain used for the tests executable.
TEST_CASE("Imports of the main executable can be replaced", "[macos_imports]")
{
    void *executable = ExecutableHandle();
    REQUIRE(executable != nullptr);
    const pid_t pid = getpid();

    MiniDetour::ModuleManipulation::IATReplaceParameter_t wrongModule{};
    wrongModule.IATModuleName = "libNotLoaded.dylib";
    wrongModule.IATName       = "getpid";
    wrongModule.NewIATAddress = reinterpret_cast<void *>(&FakeGetPid);
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleIATs(executable, &wrongModule, 1) == 0);
    CHECK(wrongModule.IATCallAddress == nullptr);
    CHECK(getpid() == pid);

    MiniDetour::ModuleManipulation::IATReplaceParameter_t parameter{};
    parameter.IATModuleName = "libSystem.B.dylib";
    parameter.IATName       = "getpid";
    parameter.NewIATAddress = reinterpret_cast<void *>(&FakeGetPid);
    REQUIRE(MiniDetour::ModuleManipulation::ReplaceModuleIATs(executable, &parameter, 1) == 1);

    CHECK(getpid() == 12345);
    REQUIRE(parameter.IATCallAddress != nullptr);
    CHECK(reinterpret_cast<pid_t (*)()>(parameter.IATCallAddress)() == pid);

    CHECK(MiniDetour::ModuleManipulation::RestoreModuleIATs(executable, &parameter, 1) == 1);
    CHECK(parameter.NewIATAddress == reinterpret_cast<void *>(&FakeGetPid));
    CHECK(getpid() == pid);

    dlclose(executable);
}

// The replacements call the real functions, so the rest of the process keeps working while they are in place, and count
// their calls: the library must not make any.
static std::atomic<int> g_DyldCalls(0);
static void *(*g_Dlopen)(const char *, int);
static int (*g_Dlclose)(void *);
static void *(*g_Dlsym)(void *, const char *);

static void *CountingDlopen(const char *path, int mode)
{
    ++g_DyldCalls;
    return g_Dlopen(path, mode);
}

static int CountingDlclose(void *handle)
{
    ++g_DyldCalls;
    return g_Dlclose(handle);
}

static void *CountingDlsym(void *handle, const char *name)
{
    ++g_DyldCalls;
    return g_Dlsym(handle, name);
}

// Calls dlopen and dlclose through the imports of the executable, in a function of its own: in the test, the compiler can
// keep the imports read before the replacement.
__attribute__((noinline)) static void CallDlopenDlclose()
{
    void *libSystem = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW | RTLD_NOLOAD);
    if (libSystem != nullptr)
        dlclose(libSystem);
}

// The library called dlopen, dlclose and dlsym through the imports of the image linking it, the tests executable here:
// once they were replaced there, it called the replacements to find the images and the symbols.
TEST_CASE("dlopen, dlclose and dlsym replaced in the executable aren't called by the library", "[macos_imports]")
{
    void *executable = ExecutableHandle();
    REQUIRE(executable != nullptr);
    const size_t importCount = GetImports(executable).size();

    // Set before the replacements: another thread may call them as soon as they are written.
    // Asked to dyld: the address of an imported function can be the stub of the executable, which jumps through the
    // replaced slot.
    g_Dlopen  = reinterpret_cast<void *(*)(const char *, int)>(dlsym(RTLD_DEFAULT, "dlopen"));
    g_Dlclose = reinterpret_cast<int (*)(void *)>(dlsym(RTLD_DEFAULT, "dlclose"));
    g_Dlsym   = reinterpret_cast<void *(*)(void *, const char *)>(dlsym(RTLD_DEFAULT, "dlsym"));
    REQUIRE(g_Dlopen != nullptr);
    REQUIRE(g_Dlclose != nullptr);
    REQUIRE(g_Dlsym != nullptr);

    MiniDetour::ModuleManipulation::IATReplaceParameter_t dyld[3]{};
    const char *names[]  = {"dlopen", "dlclose", "dlsym"};
    void *replacements[] = {reinterpret_cast<void *>(&CountingDlopen), reinterpret_cast<void *>(&CountingDlclose), reinterpret_cast<void *>(&CountingDlsym)};
    for (size_t i = 0; i < 3; ++i)
    {
        dyld[i].IATModuleName = "libSystem.B.dylib";
        dyld[i].IATName       = names[i];
        dyld[i].NewIATAddress = replacements[i];
    }
    REQUIRE(MiniDetour::ModuleManipulation::ReplaceModuleIATs(executable, dyld, 3) == 3);

    // The replacements are called through the imports of the executable.
    g_DyldCalls = 0;
    CallDlopenDlclose();
    const int testCalls = g_DyldCalls;

    // The library finds the images (listing, replacing and restoring) and the symbols (lazy imports).
    MiniDetour::ModuleManipulation::IATReplaceParameter_t parameter{};
    parameter.IATModuleName = "libSystem.B.dylib";
    parameter.IATName       = "getpid";
    parameter.NewIATAddress = reinterpret_cast<void *>(&FakeGetPid);

    g_DyldCalls             = 0;
    const size_t listed     = GetImports(executable).size();
    const size_t replaced   = MiniDetour::ModuleManipulation::ReplaceModuleIATs(executable, &parameter, 1);
    const pid_t replacedPid = getpid();
    const size_t restored   = MiniDetour::ModuleManipulation::RestoreModuleIATs(executable, &parameter, 1);
    const int libraryCalls  = g_DyldCalls;

    REQUIRE(MiniDetour::ModuleManipulation::RestoreModuleIATs(executable, dyld, 3) == 3);

    CHECK(testCalls == 2);
    CHECK(libraryCalls == 0);
    CHECK(listed == importCount);
    CHECK(replaced == 1);
    CHECK(replacedPid == 12345);
    CHECK(restored == 1);
    dlclose(executable);
}

// Replaces getpid in a library calling it, before its first call, and checks the original function is the real one.
static void CheckLibraryImportReplacement(const char *libraryPath)
{
    // RTLD_LAZY: before macOS 12, the lazy pointers stay bound to the dyld stub until their first call.
    void *library = dlopen(libraryPath, RTLD_LAZY);
    REQUIRE(library != nullptr);
    auto importGetPid = reinterpret_cast<int (*)()>(dlsym(library, "ImportGetPid"));
    REQUIRE(importGetPid != nullptr);
    const pid_t pid = getpid();

    MiniDetour::ModuleManipulation::IATReplaceParameter_t parameter{};
    parameter.IATName       = "getpid";
    parameter.NewIATAddress = reinterpret_cast<void *>(&FakeGetPid);
    REQUIRE(MiniDetour::ModuleManipulation::ReplaceModuleIATs(library, &parameter, 1) == 1);
    CHECK(parameter.IATCallAddress == dlsym(RTLD_DEFAULT, "getpid"));

    CHECK(importGetPid() == 12345);
    REQUIRE(parameter.IATCallAddress != nullptr);
    CHECK(reinterpret_cast<pid_t (*)()>(parameter.IATCallAddress)() == pid);
    // Still replaced after the original was called.
    CHECK(importGetPid() == 12345);

    CHECK(MiniDetour::ModuleManipulation::RestoreModuleIATs(library, &parameter, 1) == 1);
    CHECK(importGetPid() == pid);

    dlclose(library);
}

// Before macOS 12, a lazy pointer leads to dyld's binding stub until the first call: returning it as the original
// function would make dyld bind the slot again, over the replacement, when it is called. dyld 4 (macOS 12) binds the
// lazy pointers when the image is loaded, even with RTLD_LAZY, so this only checks that lazy pointers are replaced
// there; the unbound case can only be seen on older versions.
TEST_CASE("Lazy imports can be replaced before their first call", "[macos_imports]")
{
    CheckLibraryImportReplacement("./macos_lazy_import_test_library.dylib");
}

TEST_CASE("Imports bound with chained fixups can be replaced", "[macos_imports]")
{
    CheckLibraryImportReplacement("./macos_chained_import_test_library.dylib");
}

// The replacement calls the real function, so the rest of the process keeps working while it is in place (all the
// shared cache images may call it), and counts its calls.
static std::atomic<int> g_FreeCalls(0);
static void (*g_Free)(void *);

static void CountingFree(void *pointer)
{
    ++g_FreeCalls;
    g_Free(pointer);
}

// operator delete is in libc++abi, which frees the memory through its import of free.
__attribute__((noinline)) static void NewThenDelete()
{
    void *volatile pointer = ::operator new(16);
    ::operator delete(pointer);
}

static int MacOSMajorVersion()
{
    char version[32] = {};
    size_t size      = sizeof(version);
    if (sysctlbyname("kern.osproductversion", version, &size, nullptr, 0) != 0)
        return 0;

    return atoi(version);
}

// Images of the shared cache were refused: their import pages can't be made writable without a copy (VM_PROT_COPY). Up
// to macOS 12 at least, each image has its own symbol pointers. From macOS 14 on, the stubs of the cache images go through
// slots shared by the whole cache: replacing free in libc++abi replaces it in libc++ too.
TEST_CASE("Imports of a shared cache library can be replaced", "[macos_imports]")
{
    void *libcxxabi = dlopen("/usr/lib/libc++abi.dylib", RTLD_NOW | RTLD_NOLOAD);
    void *libcxx    = dlopen("/usr/lib/libc++.1.dylib", RTLD_NOW | RTLD_NOLOAD);
    REQUIRE(libcxxabi != nullptr);
    REQUIRE(libcxx != nullptr);

    // Set before the replacement: another thread may call it as soon as it is written. Asked to the loader: &free can be
    // the stub of the executable.
    g_Free = reinterpret_cast<void (*)(void *)>(dlsym(RTLD_DEFAULT, "free"));
    REQUIRE(g_Free != nullptr);

    auto imports        = GetImports(libcxxabi);
    auto originalImport = FindImport(imports, "free");
    REQUIRE(originalImport != nullptr);
    CHECK(originalImport->ImportCallAddress == reinterpret_cast<void *>(g_Free));

    MiniDetour::ModuleManipulation::IATReplaceParameter_t parameter{};
    parameter.IATName       = "free";
    parameter.NewIATAddress = reinterpret_cast<void *>(&CountingFree);
    REQUIRE(MiniDetour::ModuleManipulation::ReplaceModuleIATs(libcxxabi, &parameter, 1) == 1);

    g_FreeCalls = 0;
    NewThenDelete();
    const int freeCalls      = g_FreeCalls;
    auto replacedImports     = GetImports(libcxxabi);
    auto libcxxImports       = GetImports(libcxx);
    auto replacedImport      = FindImport(replacedImports, "free");
    auto libcxxImport        = FindImport(libcxxImports, "free");
    void *replacedCall       = replacedImport != nullptr ? replacedImport->ImportCallAddress : nullptr;
    void *libcxxReplacedCall = libcxxImport != nullptr ? libcxxImport->ImportCallAddress : nullptr;

    CHECK(MiniDetour::ModuleManipulation::RestoreModuleIATs(libcxxabi, &parameter, 1) == 1);

    // Other threads can free memory too.
    CHECK(freeCalls >= 1);
    CHECK(parameter.IATCallAddress == reinterpret_cast<void *>(g_Free));
    CHECK(replacedCall == reinterpret_cast<void *>(&CountingFree));

    const int version = MacOSMajorVersion();
    INFO("macOS " << version);
    REQUIRE(libcxxImport != nullptr);
    if (version >= 14)
        CHECK(libcxxReplacedCall == reinterpret_cast<void *>(&CountingFree));
    else if (version <= 12)
        CHECK(libcxxReplacedCall == reinterpret_cast<void *>(g_Free));

    auto restoredImports = GetImports(libcxxabi);
    auto restoredImport  = FindImport(restoredImports, "free");
    REQUIRE(restoredImport != nullptr);
    CHECK(restoredImport->ImportCallAddress == reinterpret_cast<void *>(g_Free));

    dlclose(libcxx);
    dlclose(libcxxabi);
}

#endif
