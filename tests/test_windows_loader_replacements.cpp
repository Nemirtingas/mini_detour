#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_OS_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <string.h>
#include <string>
#include <vector>

// The replacements call the real functions, so the rest of the process (the C runtime) keeps working while they are in
// place, and count their calls: the library must not make any.
static volatile LONG g_LoaderCalls = 0;
static BOOL(WINAPI *g_GetModuleHandleExA)(DWORD, LPCSTR, HMODULE *);
static FARPROC(WINAPI *g_GetProcAddress)(HMODULE, LPCSTR);
static DWORD(WINAPI *g_GetModuleFileNameW)(HMODULE, LPWSTR, DWORD);

static BOOL WINAPI CountingGetModuleHandleExA(DWORD flags, LPCSTR moduleName, HMODULE *module)
{
    InterlockedIncrement(&g_LoaderCalls);
    return g_GetModuleHandleExA(flags, moduleName, module);
}

static FARPROC WINAPI CountingGetProcAddress(HMODULE module, LPCSTR name)
{
    InterlockedIncrement(&g_LoaderCalls);
    return g_GetProcAddress(module, name);
}

static DWORD WINAPI CountingGetModuleFileNameW(HMODULE module, LPWSTR fileName, DWORD size)
{
    InterlockedIncrement(&g_LoaderCalls);
    return g_GetModuleFileNameW(module, fileName, size);
}

// Calls the three functions through the imports of the executable, in a function of its own: in the test, the compiler
// can keep an import read before the replacement. It also makes the executable import them.
static __declspec(noinline) void CallLoaderFunctions(HMODULE kernel32)
{
    HMODULE module = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, "kernel32.dll", &module);
    GetProcAddress(kernel32, "GetTickCount");
    wchar_t fileName[MAX_PATH];
    GetModuleFileNameW(kernel32, fileName, MAX_PATH);
}

static DWORD WINAPI LoaderReplacementsGetTickCount()
{
    return 1234;
}

// A loaded PE image importing GetTickCount without OriginalFirstThunk: its import slot is found by resolving the
// function with GetModuleHandleExA and GetProcAddress.
static std::vector<uint8_t> MakePeWithBoundImport(void *getTickCount)
{
    std::vector<uint8_t> image(4096, 0);

    auto *dosHeader     = reinterpret_cast<IMAGE_DOS_HEADER *>(image.data());
    dosHeader->e_magic  = IMAGE_DOS_SIGNATURE;
    dosHeader->e_lfanew = 0x80;

    auto *ntHeaders                                                                      = reinterpret_cast<IMAGE_NT_HEADERS *>(image.data() + dosHeader->e_lfanew);
    ntHeaders->Signature                                                                 = IMAGE_NT_SIGNATURE;
    ntHeaders->OptionalHeader.Magic                                                      = IMAGE_NT_OPTIONAL_HDR_MAGIC;
    ntHeaders->OptionalHeader.NumberOfRvaAndSizes                                        = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x200;
    ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size           = 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    auto *importDescriptor               = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(image.data() + 0x200);
    importDescriptor->OriginalFirstThunk = 0;
    importDescriptor->Name               = 0x300;
    importDescriptor->FirstThunk         = 0x400;

    strcpy(reinterpret_cast<char *>(image.data() + 0x300), "kernel32.dll");

    auto *addressTable = reinterpret_cast<void **>(image.data() + 0x400);
    addressTable[0]    = getTickCount;
    addressTable[1]    = nullptr;

    return image;
}

// The library called the loader functions through the imports of the image linking it (the tests executable here):
// once they were replaced there, it called the replacements to find import slots and to name the regions.
TEST_CASE("Loader functions replaced in the executable aren't called by the library", "[loader_replacements]")
{
    void *executable = GetModuleHandleA(nullptr);
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    REQUIRE(kernel32 != nullptr);
    void *getTickCount = (void *)GetProcAddress(kernel32, "GetTickCount");
    REQUIRE(getTickCount != nullptr);

    // Set before the replacements: another thread may call them as soon as they are written. Asked to the loader, as the
    // library does.
    g_GetModuleHandleExA = reinterpret_cast<decltype(g_GetModuleHandleExA)>(GetProcAddress(kernel32, "GetModuleHandleExA"));
    g_GetProcAddress     = reinterpret_cast<decltype(g_GetProcAddress)>(GetProcAddress(kernel32, "GetProcAddress"));
    g_GetModuleFileNameW = reinterpret_cast<decltype(g_GetModuleFileNameW)>(GetProcAddress(kernel32, "GetModuleFileNameW"));
    REQUIRE(g_GetModuleHandleExA != nullptr);
    REQUIRE(g_GetProcAddress != nullptr);
    REQUIRE(g_GetModuleFileNameW != nullptr);

    MiniDetour::ModuleManipulation::IATReplaceParameter_t loader[3]{};
    const char *names[]  = {"GetModuleHandleExA", "GetProcAddress", "GetModuleFileNameW"};
    void *replacements[] = {(void *)&CountingGetModuleHandleExA, (void *)&CountingGetProcAddress, (void *)&CountingGetModuleFileNameW};
    for (size_t i = 0; i < 3; ++i)
    {
        loader[i].IATModuleName = "kernel32.dll";
        loader[i].IATName       = names[i];
        loader[i].NewIATAddress = replacements[i];
    }
    REQUIRE(MiniDetour::ModuleManipulation::ReplaceModuleIATs(executable, loader, 3) == 3);

    // The replacements are called through the imports of the executable.
    InterlockedExchange(&g_LoaderCalls, 0);
    CallLoaderFunctions(kernel32);
    const LONG testCalls = g_LoaderCalls;

    // An import found through GetModuleHandleExA and GetProcAddress, and a region named with GetModuleHandleExA and
    // GetModuleFileNameW.
    auto image         = MakePeWithBoundImport(getTickCount);
    auto *addressTable = reinterpret_cast<void **>(image.data() + 0x400);
    MiniDetour::ModuleManipulation::IATReplaceParameter_t tickCount{};
    tickCount.IATModuleName = "kernel32.dll";
    tickCount.IATName       = "GetTickCount";
    tickCount.NewIATAddress = (void *)&LoaderReplacementsGetTickCount;

    struct RegionInfos : MiniDetour::MemoryManipulation::RegionInfos_t
    {
        RegionInfos() { StructSize = sizeof(*this); }

        char extraNameSpace[512];
    } infos;

    InterlockedExchange(&g_LoaderCalls, 0);
    const size_t replaced    = MiniDetour::ModuleManipulation::ReplaceModuleIATs(image.data(), &tickCount, 1);
    void *const replacedSlot = addressTable[0];
    const size_t restored    = MiniDetour::ModuleManipulation::RestoreModuleIATs(image.data(), &tickCount, 1);
    MiniDetour::MemoryManipulation::GetRegionInfos(reinterpret_cast<void *>(&LoaderReplacementsGetTickCount), &infos);
    const LONG libraryCalls = g_LoaderCalls;

    REQUIRE(MiniDetour::ModuleManipulation::RestoreModuleIATs(executable, loader, 3) == 3);

    CHECK(testCalls == 3);
    CHECK(libraryCalls == 0);
    CHECK(replaced == 1);
    CHECK(replacedSlot == (void *)&LoaderReplacementsGetTickCount);
    CHECK(restored == 1);
    CHECK(addressTable[0] == getTickCount);
    const std::string regionName = infos.ModuleName;
    INFO("Region name: " << regionName);
    CHECK(regionName.find("tests") != std::string::npos);
}

#endif
