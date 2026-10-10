#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_OS_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <vector>

// A PE image (DOS + NT headers) without any data directory.
static std::vector<uint8_t> MakePeWithoutDirectories()
{
    std::vector<uint8_t> image(4096, 0);

    auto *dosHeader     = reinterpret_cast<IMAGE_DOS_HEADER *>(image.data());
    dosHeader->e_magic  = IMAGE_DOS_SIGNATURE;
    dosHeader->e_cblp   = 0x90; // Usual DOS header values, they must not be read as an export/import directory.
    dosHeader->e_cp     = 3;
    dosHeader->e_ip     = 5;
    dosHeader->e_lfarlc = 0x40;
    dosHeader->e_lfanew = 0x80;

    auto *ntHeaders                               = reinterpret_cast<IMAGE_NT_HEADERS *>(image.data() + dosHeader->e_lfanew);
    ntHeaders->Signature                          = IMAGE_NT_SIGNATURE;
    ntHeaders->OptionalHeader.Magic               = IMAGE_NT_OPTIONAL_HDR_MAGIC;
    ntHeaders->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    return image;
}

// BUGS.md #22: a module without export (or import) directory had its DOS header parsed as the directory.
TEST_CASE("Module without export directory has no exports", "[pe_directories]")
{
    auto image = MakePeWithoutDirectories();

    CHECK(MiniDetour::ModuleManipulation::GetAllExportedSymbols(image.data(), nullptr, 0) == 0);

    MiniDetour::ModuleManipulation::ExportReplaceParameter_t exportReplace{"add", nullptr, nullptr};
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleExports(image.data(), &exportReplace, 1) == 0);
    CHECK(exportReplace.ExportCallAddress == nullptr);
}

TEST_CASE("Module without import directory has no imports", "[pe_directories]")
{
    auto image = MakePeWithoutDirectories();

    CHECK(MiniDetour::ModuleManipulation::GetAllIATSymbols(image.data(), nullptr, 0) == 0);

    MiniDetour::ModuleManipulation::IATReplaceParameter_t iatReplace{};
    iatReplace.IATModuleName = "kernel32.dll";
    iatReplace.IATName       = "GetModuleHandleA";
    CHECK(MiniDetour::ModuleManipulation::ReplaceModuleIATs(image.data(), &iatReplace, 1) == 0);
    CHECK(iatReplace.IATCallAddress == nullptr);
}

#endif
