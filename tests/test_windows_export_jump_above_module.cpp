#include "catch.hpp"

#include "test_utils.h"

#if defined(MINIDETOUR_OS_WINDOWS) && defined(MINIDETOUR_ARCH_X64)
#include <Windows.h>

static int TEST_CALL BelowModuleDetour()
{
    return 0;
}

// BUGS.md #23: the export trampoline only had to be within 2 GB of the module. A slot below the module base
// gives a negative RVA, which the unsigned export table turns into an address 4 GB above the module.
TEST_CASE("Export jump is placed above the module base", "[export_jump_rva]")
{
    HMODULE h = LoadLibraryA("./export_hook_test_library.dll");
    REQUIRE(h != nullptr);

    const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(h);

    // Hooking a function 256 MB below the module creates a jump region below it, with free slots
    // close enough to the module for a relative jump.
    uint8_t *belowModule = nullptr;
    for (uintptr_t address = moduleBase - 0x10000000; belowModule == nullptr && address < moduleBase; address += 0x10000)
        belowModule = static_cast<uint8_t *>(VirtualAlloc(reinterpret_cast<void *>(address), 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

    REQUIRE(belowModule != nullptr);

    // nop; mov eax, 1; ret
    const uint8_t function[] = {0x90, 0xB8, 1, 0, 0, 0, 0xC3};
    memcpy(belowModule, function, sizeof(function));
    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(belowModule, (void *)&BelowModuleDetour) != nullptr);

    // A detour that isn't representable as an RVA (below the module) needs a jump slot.
    CodeBuffer detour(4096);
    REQUIRE(detour.IsValid());
    // mov eax, 2; ret
    detour.Write(0, {0xB8, 2, 0, 0, 0, 0xC3});
    REQUIRE(reinterpret_cast<uintptr_t>(detour.Data()) < moduleBase);

    MiniDetour::ModuleManipulation::ExportReplaceParameter_t exportDetails{"add", detour.Data(), nullptr};
    REQUIRE(MiniDetour::ModuleManipulation::ReplaceModuleExports(h, &exportDetails, 1) == 1);

    auto add = reinterpret_cast<int (*)(int, int)>(GetProcAddress(h, "add"));
    CHECK(reinterpret_cast<uintptr_t>(add) > moduleBase);
    CHECK(reinterpret_cast<uintptr_t>(add) - moduleBase < 0x80000000);
    if (reinterpret_cast<uintptr_t>(add) > moduleBase && reinterpret_cast<uintptr_t>(add) - moduleBase < 0x80000000)
        CHECK(add(5, 3) == 2);

    CHECK(MiniDetour::ModuleManipulation::RestoreModuleExports(h, &exportDetails, 1) == 1);
    hook.RestoreFunction();
    VirtualFree(belowModule, 0, MEM_RELEASE);
    FreeLibrary(h);
}
#endif
