#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_OS_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <string.h>
#include <vector>

static DWORD WINAPI MyGetTickCount()
{
    return 1234;
}

// A loaded PE image importing two kernel32 functions without OriginalFirstThunk (old linkers):
// the IAT only holds the addresses resolved by the loader.
static std::vector<uint8_t> MakePeWithBoundImports(void* getModuleHandle, void* getTickCount)
{
    std::vector<uint8_t> image(4096, 0);

    auto* dosHeader     = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    dosHeader->e_magic  = IMAGE_DOS_SIGNATURE;
    dosHeader->e_lfanew = 0x80;

    auto* ntHeaders                               = reinterpret_cast<IMAGE_NT_HEADERS*>(image.data() + dosHeader->e_lfanew);
    ntHeaders->Signature                          = IMAGE_NT_SIGNATURE;
    ntHeaders->OptionalHeader.Magic               = IMAGE_NT_OPTIONAL_HDR_MAGIC;
    ntHeaders->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x200;
    ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size           = 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    auto* importDescriptor               = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.data() + 0x200);
    importDescriptor->OriginalFirstThunk = 0;
    importDescriptor->Name               = 0x300;
    importDescriptor->FirstThunk         = 0x400;

    strcpy(reinterpret_cast<char*>(image.data() + 0x300), "kernel32.dll");

    auto* addressTable = reinterpret_cast<void**>(image.data() + 0x400);
    addressTable[0]    = getModuleHandle;
    addressTable[1]    = getTickCount;
    addressTable[2]    = nullptr;

    return image;
}

// BUGS.md #27: the import descriptors loop stopped on Characteristics == 0, which is OriginalFirstThunk:
// modules without it had no import at all.
TEST_CASE("Imports without OriginalFirstThunk", "[iat_without_original_thunk]")
{
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    REQUIRE(kernel32 != nullptr);
    void* getModuleHandle = (void*)GetProcAddress(kernel32, "GetModuleHandleA");
    void* getTickCount    = (void*)GetProcAddress(kernel32, "GetTickCount");

    auto image         = MakePeWithBoundImports(getModuleHandle, getTickCount);
    auto* addressTable = reinterpret_cast<void**>(image.data() + 0x400);

    CHECK(MiniDetour::ModuleManipulation::GetAllIATSymbols(image.data(), nullptr, 0) == 2);

    MiniDetour::ModuleManipulation::IATDetails_t imports[4];
    REQUIRE(MiniDetour::ModuleManipulation::GetAllIATSymbols(image.data(), imports, 4) == 2);
    CHECK(imports[1].ImportCallAddress == getTickCount);
    CHECK(strcmp(imports[1].ImportModuleName, "kernel32.dll") == 0);

    MiniDetour::ModuleManipulation::IATReplaceParameter_t iatReplace{};
    iatReplace.IATModuleName = "kernel32.dll";
    iatReplace.IATName       = "GetTickCount";
    iatReplace.NewIATAddress = (void*)&MyGetTickCount;
    REQUIRE(MiniDetour::ModuleManipulation::ReplaceModuleIATs(image.data(), &iatReplace, 1) == 1);
    CHECK(iatReplace.IATCallAddress == getTickCount);
    CHECK(addressTable[0] == getModuleHandle);
    CHECK(addressTable[1] == (void*)&MyGetTickCount);

    CHECK(MiniDetour::ModuleManipulation::RestoreModuleIATs(image.data(), &iatReplace, 1) == 1);
    CHECK(iatReplace.NewIATAddress == (void*)&MyGetTickCount);
    CHECK(addressTable[1] == getTickCount);
}

#endif
