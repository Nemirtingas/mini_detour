#define CATCH_CONFIG_RUNNER
#include "catch.hpp"
#include "test_utils.h"

#include <mini_detour/mini_detour.h>
#include <spdlog/spdlog-inl.h>
#include <iostream>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#if defined(MINIDETOUR_OS_WINDOWS)
#define EXPORT_HOOK_TEST_LIBRARY "./export_hook_test_library.dll"
#define LOAD_LIBRARY(filePath) ((void*)LoadLibraryA(filePath))
#define GET_LIBRARY_PROC(handle, name) ((void*)GetProcAddress((HMODULE)(handle), name))
#define FREE_LIBRARY(handle) FreeLibrary((HMODULE)handle)

#elif defined(MINIDETOUR_OS_LINUX)
#include <dlfcn.h>

#define EXPORT_HOOK_TEST_LIBRARY "./export_hook_test_library.so"
#define LOAD_LIBRARY(filePath) ((void*)dlopen(filePath, RTLD_LAZY))
#define GET_LIBRARY_PROC(handle, name) ((void*)dlsym((void*)(handle), name))
#define FREE_LIBRARY(handle) dlclose((void*)(handle))

#elif defined(MINIDETOUR_OS_APPLE)
#include <dlfcn.h>

#define EXPORT_HOOK_TEST_LIBRARY "./export_hook_test_library.dylib"
#define LOAD_LIBRARY(filePath) dlopen(filePath, RTLD_LAZY)
#define GET_LIBRARY_PROC(handle, name) ((void*)dlsym(handle, name))
#define FREE_LIBRARY(handle) dlclose(handle)

#endif

inline void* relative_addr_to_absolute(void* source_addr, int32_t rel_addr)
{
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(source_addr) + rel_addr + 5);
}

static void _EnterRecursiveThunk(void*& _pCode)
{
    uint8_t* pCode = reinterpret_cast<uint8_t*>(_pCode);
    while (1)
    {
        // Imported function: jmp [address]
        if (pCode[0] == 0xFF && pCode[1] == 0x25)
        {
#if defined(MINIDETOUR_ARCH_X64)
            // jmp [rip + disp32]: the pointer is relative to the next instruction (6 bytes).
            pCode = *reinterpret_cast<uint8_t**>(pCode + 6 + *reinterpret_cast<int32_t*>(pCode + 2));
#else
            // jmp [disp32]: absolute address of the pointer.
            pCode = **reinterpret_cast<uint8_t***>(pCode + 2);
#endif
        }
        // Incremental linking thunk: jmp rel32. A call (E8) is the start of a real function, not a thunk.
        else if (pCode[0] == 0xE9)
        {
            pCode = (uint8_t*)relative_addr_to_absolute(pCode, *(int32_t*)(pCode + 1));
        }
        else
        {
            break;
        }
    }

    _pCode = pCode;
}

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)
// BUGS.md #44: the helper decoded jmp [rip + disp32] (x64) as jmp [disp32] (x86), and followed calls.
TEST_CASE("Test thunk helper follows jmp [address]", "[test_thunk_helper]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());

    // The jump target, followed by nothing the helper follows.
    void* target = code.Data(64);
    code.Write(64, { 0xC3 }); // ret

#if defined(MINIDETOUR_ARCH_X64)
    // jmp [rip + 2]; the pointer is 2 bytes after the 6 bytes instruction.
    code.Write(0, { 0xFF, 0x25, 0x02, 0x00, 0x00, 0x00 });
    code.WriteValue<void*>(8, target);
#else
    // jmp [slot]
    code.Write(0, { 0xFF, 0x25 });
    code.WriteValue<void*>(2, code.Data(8));
    code.WriteValue<void*>(8, target);
#endif

    void* address = code.Data();
    _EnterRecursiveThunk(address);
    CHECK(address == target);

    // A call is a function start, not a thunk.
    code.Write(16, { 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3 });
    address = code.Data(16);
    _EnterRecursiveThunk(address);
    CHECK(address == code.Data(16));
}
#endif

// Value of an environment variable, empty when it isn't set (getenv is deprecated with MSVC).
static std::string ReadEnvironmentVariable(const char* name)
{
#if defined(_MSC_VER)
    char* value = nullptr;
    size_t size = 0;
    std::string result;
    if (_dupenv_s(&value, &size, name) == 0 && value != nullptr)
        result = value;

    free(value);
    return result;
#else
    const char* value = getenv(name);
    return value != nullptr ? value : "";
#endif
}

int main(int argc, char* argv[]) {
    // The library logs every hook and relocated instruction at the info level: tens of thousands of lines for the
    // whole suite. Only warnings and errors are shown, unless MINIDETOUR_TEST_LOG_LEVEL asks for more (info, debug...).
    const std::string logLevel = ReadEnvironmentVariable("MINIDETOUR_TEST_LOG_LEVEL");
    spdlog::set_level(logLevel.empty() ? spdlog::level::warn : spdlog::level::from_str(logLevel));

    int result = Catch::Session().run(argc, argv);

    // global clean-up...

    return result;
}

int MyAdd(int a, int b)
{
    return a - b;
}

TEST_CASE("List modules iat symbols", "[module_list_iat_symbols]") {
    MiniDetour::ModuleManipulation::IATDetails_t* iatSymbols;
    size_t iatSymbolsCount = 0;
#if defined(MINIDETOUR_OS_WINDOWS) || defined(MINIDETOUR_OS_LINUX)
    auto h = LOAD_LIBRARY(EXPORT_HOOK_TEST_LIBRARY);
    if (h != nullptr)
    {
        iatSymbolsCount = MiniDetour::ModuleManipulation::GetAllIATSymbols(h, nullptr, 0);

        iatSymbols = (MiniDetour::ModuleManipulation::IATDetails_t*)malloc(sizeof(MiniDetour::ModuleManipulation::IATDetails_t) * iatSymbolsCount);
        CHECK(MiniDetour::ModuleManipulation::GetAllIATSymbols(h, iatSymbols, iatSymbolsCount) == iatSymbolsCount);

        SPDLOG_INFO("Module: {}", EXPORT_HOOK_TEST_LIBRARY);
        for (size_t i = 0; i < iatSymbolsCount; ++i)
        {
            SPDLOG_INFO("  Import module: {}, Symbol: {}, [ordinal]{} at {}", iatSymbols[i].ImportModuleName, iatSymbols[i].ImportName == nullptr ? "" : iatSymbols[i].ImportName, iatSymbols[i].ImportOrdinal, iatSymbols[i].ImportCallAddress);
        }

        free(iatSymbols);
    }
#endif
}

TEST_CASE("List modules exported symbols", "[module_list_export_symbols]") {
    MiniDetour::ModuleManipulation::ExportDetails_t* exportedSymbols;
    size_t exportedSymbolsCount = 0;
    auto h = LOAD_LIBRARY(EXPORT_HOOK_TEST_LIBRARY);
    if (h != nullptr)
    {
        exportedSymbolsCount = MiniDetour::ModuleManipulation::GetAllExportedSymbols(h, nullptr, 0);
        CHECK(exportedSymbolsCount == 3);

        exportedSymbols = (MiniDetour::ModuleManipulation::ExportDetails_t*)malloc(sizeof(MiniDetour::ModuleManipulation::ExportDetails_t) * exportedSymbolsCount);
        CHECK(MiniDetour::ModuleManipulation::GetAllExportedSymbols(h, exportedSymbols, exportedSymbolsCount) == exportedSymbolsCount);

        SPDLOG_INFO("Module: {}", EXPORT_HOOK_TEST_LIBRARY);
        for (size_t i = 0; i < exportedSymbolsCount; ++i)
        {
            CHECK(GET_LIBRARY_PROC(h, exportedSymbols[i].ExportName) == exportedSymbols[i].ExportCallAddress);
            SPDLOG_INFO("  Symbol export: {}, [ordinal]{} at {} - {}", exportedSymbols[i].ExportName == nullptr ? "" : exportedSymbols[i].ExportName, exportedSymbols[i].ExportOrdinal, exportedSymbols[i].ExportCallAddress, GET_LIBRARY_PROC(h, exportedSymbols[i].ExportName));
        }

        free(exportedSymbols);
    }
}

#if defined(MINIDETOUR_OS_WINDOWS)
HMODULE WINAPI MyGetModuleHandleA(LPCSTR)
{
    return (HMODULE)0x99887766;
}
#elif defined(MINIDETOUR_OS_LINUX)
void* Mydlopen(const char*, int)
{
    return (void*)0x99887766;
}
#endif

TEST_CASE("Module IAT hook", "[module_iat_hook]") {
#if defined(MINIDETOUR_OS_WINDOWS)
    // GetModuleHandleA is now in the IAT.
    auto h = (void*)GetModuleHandleA(nullptr);
    MiniDetour::ModuleManipulation::IATReplaceParameter_t iatReplace{};

    iatReplace.IATModuleName = "kernel32.dll";
    iatReplace.IATName = "GetModuleHandleA";
    iatReplace.NewIATAddress = (void*)&MyGetModuleHandleA;
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleIATs(h, &iatReplace, 1) == 1);

    CHECK(GetModuleHandleA(nullptr) == (HMODULE)0x99887766);
    CHECK(reinterpret_cast<void*(WINAPI *)(void*)>(iatReplace.IATCallAddress)(nullptr) == h);

    CHECK(MiniDetour::ModuleManipulation::RestoreModuleIATs(h, &iatReplace, 1) == 1);
    CHECK(GetModuleHandleA(nullptr) == (HMODULE)h);
#elif defined(MINIDETOUR_OS_LINUX)
    // puts is now in the IAT.
    auto h = (void*)dlopen(nullptr, RTLD_LAZY);
    MiniDetour::ModuleManipulation::IATReplaceParameter_t iatReplace{};
    
    iatReplace.IATModuleName = "ld.so"; // ELF doesn't have a module tied to the IAT, its useless in this case.
    iatReplace.IATName = "dlopen";
    iatReplace.NewIATAddress = (void*)&Mydlopen;
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleIATs(h, &iatReplace, 1) == 1);
    
    CHECK(dlopen(nullptr, RTLD_LAZY) == (void*)0x99887766);
    CHECK(reinterpret_cast<void*(*)(void*, int)>(iatReplace.IATCallAddress)(nullptr, RTLD_LAZY) == h);
    
    CHECK(MiniDetour::ModuleManipulation::RestoreModuleIATs(h, &iatReplace, 1) == 1);
    CHECK(dlopen(nullptr, RTLD_LAZY) == (void*)h);
#endif
}

TEST_CASE("Module export hook", "[module_export_hook]") {
    SPDLOG_INFO("Test module export hook");
#if defined(MINIDETOUR_OS_WINDOWS) || defined(MINIDETOUR_OS_LINUX)
    auto h = LOAD_LIBRARY(EXPORT_HOOK_TEST_LIBRARY);
    if (h != nullptr)
    {
        int(*libraryAdd)(int a, int b) = nullptr;

        MiniDetour::ModuleManipulation::ExportReplaceParameter_t exportDetails {
            "add",
            (void*)&MyAdd,
            nullptr
        };

        CHECK(MiniDetour::ModuleManipulation::ReplaceModuleExports(h, &exportDetails, 1) == 1);
        libraryAdd = (decltype(libraryAdd))exportDetails.ExportCallAddress;
        if (libraryAdd != nullptr)
        {
            auto myAdd = ((decltype(libraryAdd))GET_LIBRARY_PROC(h, "add"));

            CHECK(libraryAdd(5, 3) == 8);
            CHECK(myAdd(5, 3) == 2);

            // Test restore
            CHECK(MiniDetour::ModuleManipulation::RestoreModuleExports(h, &exportDetails, 1) == 1);

            myAdd = ((decltype(libraryAdd))GET_LIBRARY_PROC(h, "add"));

            CHECK(libraryAdd(5, 3) == 8);
            CHECK(myAdd(5, 3) == 8);
        }

        FREE_LIBRARY(h);
    }
#elif defined(MINIDETOUR_OS_APPLE)
    //MacOS (MachO) not implemented.
#endif
}

int AbsoluteJumpWriteTest(int x)
{
    return x * 5;
}

TEST_CASE("Test absolute jump write", "[absolute_jump_write]") {
    SPDLOG_INFO("Test absolute jump write");
    auto allocSize = MiniDetour::MemoryManipulation::WriteAbsoluteJump(nullptr, nullptr);
    auto jumpAddress = (int(*)(int))MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, allocSize, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);
    CHECK(jumpAddress != nullptr);
    if (jumpAddress != nullptr)
    {
        if (MiniDetour::MemoryManipulation::WriteAbsoluteJump((void*)jumpAddress, (void*)&AbsoluteJumpWriteTest) &&
            MiniDetour::MemoryManipulation::MemoryProtect((void*)jumpAddress, allocSize, MiniDetour::MemoryManipulation::MemoryRights::mem_rx))
        {
            auto a1 = jumpAddress(2);
            auto a2 = jumpAddress(3);
            CHECK(a1 == 10);
            CHECK(a2 == 15);
            SPDLOG_INFO("Absolute jump write: {}, {}", a1, a2);
        }

        MiniDetour::MemoryManipulation::MemoryFree((void*)jumpAddress, allocSize);
    }
}

TEST_CASE("Memory mappings", "[vmmap]") {
    SPDLOG_INFO("Memory mappings with big enough name space");

    struct RegionInfos : MiniDetour::MemoryManipulation::RegionInfos_t
    {
        RegionInfos()
        {
            StructSize = sizeof(*this);
        }

        char extraNameSpace[384];
    };

    auto regionCount = MiniDetour::MemoryManipulation::GetAllRegions(nullptr, 0);
    std::vector<RegionInfos> regions(regionCount * 2);
    regionCount = MiniDetour::MemoryManipulation::GetAllRegions(regions.data(), regions.size());
    if (regionCount < regions.size())
        regions.resize(regionCount);

    char rights_str[5] = { '-', '-', '-', '-', '\0' };

    for (auto const& map : regions)
    {
        if (map.Rights != MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
        {
            if (map.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_r)
                rights_str[0] = 'r';
            else
                rights_str[0] = '-';

            if (map.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_w)
                rights_str[1] = 'w';
            else
                rights_str[1] = '-';

            if (map.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_x)
                rights_str[2] = 'x';
            else
                rights_str[2] = '-';

            rights_str[3] = '-';
        }
        else
        {
            rights_str[0] = 'f';
            rights_str[1] = 'r';
            rights_str[2] = 'e';
            rights_str[3] = 'e';
        }

        SPDLOG_INFO("[{:016X}-{:016X}]: [{}] {}", map.Start, map.End, rights_str, map.ModuleName);
    }
}

TEST_CASE("Memory mappings with name buffer too small", "[vmmap]") {
    SPDLOG_INFO("Memory mappings with small module name");

    struct RegionInfos : MiniDetour::MemoryManipulation::RegionInfos_t
    {
        RegionInfos()
        {
            StructSize = sizeof(*this);
        }

        char extraNameSpace[7];
    };

    auto regionCount = MiniDetour::MemoryManipulation::GetAllRegions(nullptr, 0);
    std::vector<RegionInfos> regions(regionCount * 2);
    regionCount = MiniDetour::MemoryManipulation::GetAllRegions(regions.data(), regions.size());
    if (regionCount < regions.size())
        regions.resize(regionCount);

    char rights_str[5] = { '-', '-', '-', '-', '\0' };

    for (auto const& map : regions)
    {
        if (map.Rights != MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
        {
            if (map.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_r)
                rights_str[0] = 'r';
            else
                rights_str[0] = '-';

            if (map.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_w)
                rights_str[1] = 'w';
            else
                rights_str[1] = '-';

            if (map.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_x)
                rights_str[2] = 'x';
            else
                rights_str[2] = '-';

            rights_str[3] = '-';
        }
        else
        {
            rights_str[0] = 'f';
            rights_str[1] = 'r';
            rights_str[2] = 'e';
            rights_str[3] = 'e';
        }

        SPDLOG_INFO("[{:016X}-{:016X}]: [{}] {}", map.Start, map.End, rights_str, map.ModuleName);
    }
}

TEST_CASE("Memory mappings with region buffer too small", "[vmmap]") {
    SPDLOG_INFO("Only 5 memory mappings without crash");

    std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> regions(5);
    auto regionCount = MiniDetour::MemoryManipulation::GetAllRegions(regions.data(), regions.size());
    if (regionCount < regions.size())
        regions.resize(regionCount);

    char rights_str[5] = { '-', '-', '-', '-', '\0' };

    for (auto const& map : regions)
    {
        if (map.Rights != MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
        {
            if (map.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_r)
                rights_str[0] = 'r';
            else
                rights_str[0] = '-';

            if (map.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_w)
                rights_str[1] = 'w';
            else
                rights_str[1] = '-';

            if (map.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_x)
                rights_str[2] = 'x';
            else
                rights_str[2] = '-';

            rights_str[3] = '-';
        }
        else
        {
            rights_str[0] = 'f';
            rights_str[1] = 'r';
            rights_str[2] = 'e';
            rights_str[3] = 'e';
        }

        SPDLOG_INFO("[{:016X}-{:016X}]: [{}] {}", map.Start, map.End, rights_str, map.ModuleName);
    }
}

TEST_CASE("Free memory mappings", "[vmmap]") {
    SPDLOG_INFO("Free memory mappings");
    auto regionCount = MiniDetour::MemoryManipulation::GetFreeRegions(nullptr, 0);
    std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> regions(regionCount * 2);
    regionCount = MiniDetour::MemoryManipulation::GetFreeRegions(regions.data(), regions.size());
    if (regionCount < regions.size())
        regions.resize(regionCount);

    char rights_str[5] = { '-', '-', '-', '-', '\0' };

    for (auto const& map : regions)
    {
        CHECK(map.Rights == MiniDetour::MemoryManipulation::MemoryRights::mem_unset);

        rights_str[0] = 'f';
        rights_str[1] = 'r';
        rights_str[2] = 'e';
        rights_str[3] = 'e';

        SPDLOG_INFO("[{:016X}-{:016X}]: [{}] {}", map.Start, map.End, rights_str, map.ModuleName);
    }
}

TEST_CASE("Memory allocation", "[mem alloc]") {
    const int alloc_size = 50;
    void* mem = MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);

    CHECK(mem != nullptr);

    MiniDetour::MemoryManipulation::MemoryFree(mem, alloc_size);
}

#ifndef MINIDETOUR_OS_APPLE

TEST_CASE("Memory protect", "[memprotect]") {
    MiniDetour::MemoryManipulation::MemoryRights old_rights;

    const int alloc_size = 50;
    void* mem = MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_none);

    CHECK(mem != nullptr);

#if defined(MINIDETOUR_OS_WINDOWS)
    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_r, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_none);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_w, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_r);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_x, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rw); // Windows doesn't have a pure w

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_x);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rw);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_wx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rx);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rwx); // Windows doesn't have a pure wx
#elif defined(MINIDETOUR_OS_LINUX)
    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_r, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_none);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_w, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_r);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_x, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_w);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_x);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rw);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_wx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rx);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_wx);
#elif defined(MINIDETOUR_OS_APPLE)
    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_r, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_none);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_w, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_r);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_x, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_w);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_x);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rw);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_wx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rx);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_wx);
#endif

    MiniDetour::MemoryManipulation::RegionInfos_t infos;
    MiniDetour::MemoryManipulation::GetRegionInfos(mem, &infos);
    CHECK(infos.Start != 0);
    CHECK(infos.End != 0);
    CHECK(infos.Rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);

    MiniDetour::MemoryManipulation::MemoryFree(mem, alloc_size);
}

// qemu user mode doesn't implement process_vm_readv/process_vm_writev (ENOSYS), used by SafeMemoryRead/Write on Linux.
// The tests then fall back to a less safe access: a plain copy, only done if the region has the needed right.
// The library keeps the real calls.
static bool SafeMemoryAccessUnsupported()
{
#if defined(MINIDETOUR_OS_LINUX)
    uint8_t value = 0;
    uint8_t copy = 0;
    errno = 0;
    return MiniDetour::MemoryManipulation::SafeMemoryRead(&value, &copy, 1) == 0 && errno == ENOSYS;
#else
    return false;
#endif
}

static bool TestMemoryAccess(void* address, size_t size, MiniDetour::MemoryManipulation::MemoryRights right)
{
    MiniDetour::MemoryManipulation::RegionInfos_t infos;
    MiniDetour::MemoryManipulation::GetRegionInfos(address, &infos);
    return infos.Rights != MiniDetour::MemoryManipulation::MemoryRights::mem_unset && (infos.Rights & right) == right &&
        reinterpret_cast<uintptr_t>(address) + size <= infos.End;
}

// True when the whole buffer was copied.
static bool TestSafeMemoryRead(void* address, uint8_t* buffer, size_t size)
{
    if (!SafeMemoryAccessUnsupported())
        return MiniDetour::MemoryManipulation::SafeMemoryRead(address, buffer, size) == size;

    if (!TestMemoryAccess(address, size, MiniDetour::MemoryManipulation::MemoryRights::mem_r))
        return false;

    memcpy(buffer, address, size);
    return true;
}

static bool TestSafeMemoryWrite(void* address, const uint8_t* buffer, size_t size)
{
    if (!SafeMemoryAccessUnsupported())
        return MiniDetour::MemoryManipulation::SafeMemoryWrite(address, buffer, size) == size;

    if (!TestMemoryAccess(address, size, MiniDetour::MemoryManipulation::MemoryRights::mem_w))
        return false;

    memcpy(address, buffer, size);
    return true;
}

TEST_CASE("Memory read/write", "[memread/memwrite]")
{
    if (SafeMemoryAccessUnsupported())
        WARN("process_vm_readv/writev not implemented (qemu user mode): checking the regions rights with a plain copy.");

    const int alloc_size = 50;
    void* mem = MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_r);
    uint8_t buffer[30];

    CHECK(mem != nullptr);

    CHECK(TestSafeMemoryWrite(mem, (const uint8_t*)"0123456789ABCDEFabcdef", 22) == false);

    MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);
    CHECK(TestSafeMemoryWrite(mem, (const uint8_t*)"0123456789ABCDEFabcdef", 22) == true);

    MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_r);
    CHECK(TestSafeMemoryRead(mem, buffer, 22) == true);

    CHECK(memcmp(buffer, "0123456789ABCDEFabcdef", 22) == 0);

    MiniDetour::MemoryManipulation::MemoryFree(mem, alloc_size);

    memset(buffer, 0, 30);
    CHECK(TestSafeMemoryRead(mem, buffer, 30) == false);
    CHECK(memcmp(buffer, "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0", 30) == 0);
}


bool Myputs_called = false;
MiniDetour::Hook_t puts_hook;

#ifdef MINIDETOUR_OS_WINDOWS
int __cdecl Myputs(const char* str)
#else
int Myputs(const char* str)
#endif
{
    Myputs_called = true;
    return puts_hook.GetOriginalFunction<decltype(puts)*>()(str);
};

// The volatile locals keep the hooked functions large enough to hold a jump once optimized: a + b alone is 4 bytes on x64.
int do_something(int a, int b)
{
    volatile int result = a + b;
    return result;
}

MiniDetour::Hook_t do_something_hook;
int Mydo_something(int a, int b)
{
    return a * b;
}

int do_something2(int a, int b)
{
    volatile int result = a - b;
    return result;
}

MiniDetour::Hook_t do_something_hook2;
int Mydo_something2(int a, int b)
{
    return a / b;
}

// Calls go through volatile pointers: optimized builds would otherwise inline or constant fold them, and never run the
// hooked code.
static int (*volatile do_something_ptr)(int, int)  = &do_something;
static int (*volatile do_something2_ptr)(int, int) = &do_something2;

TEST_CASE("Hook function", "[Hook function]") {

    puts("Unhooked Test");
    CHECK(Myputs_called == false);

    SPDLOG_INFO("Hooking puts...");
    CHECK(puts_hook.HookFunction((void*)&puts, (void*)&Myputs) != nullptr);

    SPDLOG_INFO("Calling original puts...");
	if(puts_hook.GetOriginalFunction<decltype(puts)*>() != nullptr)
	{
		puts_hook.GetOriginalFunction<decltype(puts)*>()("Hooked but call original");
	}
    CHECK(Myputs_called == false);
    
    SPDLOG_INFO("Calling puts...");
    puts("Hook Test");
    CHECK(Myputs_called == true);
    
    SPDLOG_INFO("Restoring puts...");
    CHECK(puts_hook.RestoreFunction() != nullptr);
    Myputs_called = false;
    
    SPDLOG_INFO("Calling puts...");
    puts("Unhooked Test");
    CHECK(Myputs_called == false);
    
    SPDLOG_INFO("Calling do_something...");
    CHECK(do_something_ptr(5, 8) == 13);

    SPDLOG_INFO("Hooking do_something...");
    CHECK(do_something_hook.HookFunction((void*)&do_something, (void*)Mydo_something) != nullptr);
    
    if (do_something_hook.GetOriginalFunction<void*>() != nullptr)
    {
        int r;
        SPDLOG_INFO("Calling original do_something...");
        r = do_something_hook.GetOriginalFunction<decltype(do_something)*>()(5, 8);
        CHECK(r == 13);

        SPDLOG_INFO("Calling do_something...");
        r = do_something_ptr(5, 8);
        CHECK(r == 40);

        SPDLOG_INFO("Restoring do_something...");
        CHECK(do_something_hook.RestoreFunction() != nullptr);

        SPDLOG_INFO("Calling do_something...");
        r = do_something_ptr(5, 8);
        CHECK(r == 13);
    }

    CHECK(do_something2_ptr(8, 4) == 4);
    CHECK(do_something_hook2.HookFunction((void*)&do_something2, (void*)Mydo_something2) != nullptr);

    if (do_something_hook2.GetOriginalFunction<void*>() != nullptr)
    {
        int r;

        SPDLOG_INFO("Calling original do_something2...");
        r = do_something_hook2.GetOriginalFunction<decltype(do_something2)*>()(8, 4);
        CHECK(r == 4);

        SPDLOG_INFO("Calling do_something2...");
        r = do_something2_ptr(8, 4);
        CHECK(r == 2);

        SPDLOG_INFO("Restoring do_something2...");
        CHECK(do_something_hook2.RestoreFunction() != nullptr);

        SPDLOG_INFO("Calling do_something2...");
        r = do_something2_ptr(8, 4);
        CHECK(r == 4);
    }
}

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)
void(*bkp)();

void nothing()
{
    SPDLOG_INFO("Called nothing.");
}

void my_test_func()
{
    SPDLOG_INFO("Called my_test_func");
    bkp();
}

TEST_CASE("Hook small function with call", "[Hook function]") {

    void* nothing_addr = (void*)nothing;

    _EnterRecursiveThunk(nothing_addr);

    // Executable copy of: push eax/rax; call nothing; pop eax/rax; ret
    // (the code used to be a string literal, modified in place in read-only data).
    // Allocated near nothing for the rel32 call, and before the hook so it outlives it.
    CodeBuffer code(4096, nothing_addr);
    REQUIRE(code.IsValid());
    code.Write(0, { 0x50, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0xC3 });
    auto test_func = code.As<void(*)()>();

    int32_t jump_addr = static_cast<int32_t>(reinterpret_cast<uint8_t*>(nothing_addr) - (reinterpret_cast<uint8_t*>(test_func) + 1 + 5));
    code.WriteValue<int32_t>(2, jump_addr);

    MiniDetour::Hook_t test_hook;

    SPDLOG_INFO("Calling test_func");
    test_func();

    (void*&)bkp = test_hook.HookFunction((void*)test_func, (void*)my_test_func);
    REQUIRE(bkp != nullptr);

    SPDLOG_INFO("Calling test_func");
    test_func();
}
#endif

#endif//MINIDETOUR_OS_APPLE