#include "catch.hpp"

#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_ARM) || defined(MINIDETOUR_ARCH_ARM64)

// Pc relative loads were copied as is into the trampoline, where they read another address.
// A hook must either be refused, or keep the original function working.

#if defined(MINIDETOUR_ARCH_ARM)
TEST_CASE("Hook a Thumb function starting with a pc relative load", "[arm_pc_relative]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());

    // ldr r0, [pc, #8] (reads offset 12); nop; nop; bx lr; nop; nop; .word 42
    code.Write(0, {0x02, 0x48, 0x00, 0xBF, 0x00, 0xBF, 0x70, 0x47, 0x00, 0xBF, 0x00, 0xBF});
    code.WriteValue<uint32_t>(12, 42);
    code.Write(64, {0x07, 0x20, 0x70, 0x47}); // movs r0, #7; bx lr

    auto function = reinterpret_cast<int (*)()>(reinterpret_cast<uintptr_t>(code.Data()) | 1);
    void *detour  = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(code.Data(64)) | 1);
#else
TEST_CASE("Hook an AArch64 function starting with a literal load", "[arm_pc_relative]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());

    code.WriteValue<uint32_t>(0, 0x58000040); // ldr x0, #8 (reads offset 8)
    code.WriteValue<uint32_t>(4, 0xD65F03C0); // ret
    code.WriteValue<uint64_t>(8, 42);
    code.WriteValue<uint32_t>(64, 0xD28000E0); // mov x0, #7
    code.WriteValue<uint32_t>(68, 0xD65F03C0); // ret

    auto function = code.As<int (*)()>();
    void *detour  = code.Data(64);
#endif

    REQUIRE(function() == 42);

    MiniDetour::Hook_t hook;
    auto original = reinterpret_cast<int (*)()>(hook.HookFunction((void *)function, detour));
    if (original != nullptr)
    {
        // Hooked: the relocated load must still read 42.
        CHECK(function() == 7);
        CHECK(original() == 42);
        CHECK(hook.RestoreFunction() != nullptr);
    }

    // Refused or restored: the function is unchanged.
    CHECK(function() == 42);
}

#endif
