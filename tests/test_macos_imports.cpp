#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_APPLE)
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>

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

static void InvalidArgumentDestructorReplacement()
{
}

// Images of the shared cache were refused. Their import pages can't be made writable without a copy (VM_PROT_COPY).
TEST_CASE("Imports of a shared cache library can be replaced", "[macos_imports]")
{
    void *libcxx = dlopen("/usr/lib/libc++.1.dylib", RTLD_NOW | RTLD_NOLOAD);
    REQUIRE(libcxx != nullptr);

    auto imports = GetImports(libcxx);
    REQUIRE(!imports.empty());

    // Nothing destroys a std::invalid_argument while it is replaced.
    const char *name    = "_ZNSt16invalid_argumentD1Ev";
    auto originalImport = FindImport(imports, name);
    REQUIRE(originalImport != nullptr);
    void *original = originalImport->ImportCallAddress;

    MiniDetour::ModuleManipulation::IATReplaceParameter_t parameter{};
    parameter.IATName       = name;
    parameter.NewIATAddress = reinterpret_cast<void *>(&InvalidArgumentDestructorReplacement);
    REQUIRE(MiniDetour::ModuleManipulation::ReplaceModuleIATs(libcxx, &parameter, 1) == 1);
    CHECK(parameter.IATCallAddress == original);

    auto replacedImport = FindImport(GetImports(libcxx), name);
    REQUIRE(replacedImport != nullptr);
    CHECK(replacedImport->ImportCallAddress == reinterpret_cast<void *>(&InvalidArgumentDestructorReplacement));

    CHECK(MiniDetour::ModuleManipulation::RestoreModuleIATs(libcxx, &parameter, 1) == 1);
    auto restoredImport = FindImport(GetImports(libcxx), name);
    REQUIRE(restoredImport != nullptr);
    CHECK(restoredImport->ImportCallAddress == original);

    dlclose(libcxx);
}

#endif
