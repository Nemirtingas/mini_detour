#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

using JccFunc_t = int(TEST_CALL *)(int);

static int TEST_CALL JccDetour(int)
{
    return 100;
}

static void CheckJccFunction(CodeBuffer &code)
{
    auto function = code.As<JccFunc_t>();
    REQUIRE(function(0) == 2);
    REQUIRE(function(1) == 1);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&JccDetour)) != nullptr);

    CHECK(function(0) == 100);
    CHECK(function(1) == 100);

    // The conditional jump relocated in the trampoline must keep its condition.
    auto original = hook.GetOriginalFunction<JccFunc_t>();
    CHECK(original(0) == 2);
    CHECK(original(1) == 1);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function(0) == 2);
    CHECK(function(1) == 1);
}

// A conditional jump in the relocated prologue was turned into an unconditional jump.
TEST_CASE("Relocate a short conditional jump", "[jcc_relocation]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());

    code.Write(
        0,
        {
            0x90, // 0:  nop (the relocated prologue must be at least 5 bytes)
            0x85,
            TEST_ARG0_TEST_SELF, // 1:  test arg0, arg0
            0x75,
            0x06, // 3:  jne 11
            0xB8,
            0x02,
            0x00,
            0x00,
            0x00, // 5:  mov eax, 2
            0xC3, // 10: ret
            0xB8,
            0x01,
            0x00,
            0x00,
            0x00, // 11: mov eax, 1
            0xC3, // 16: ret
        });

    CheckJccFunction(code);
}

TEST_CASE("Relocate a near conditional jump", "[jcc_relocation]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());

    code.Write(
        0,
        {
            0x85, TEST_ARG0_TEST_SELF, // 0:  test arg0, arg0
            0x0F, 0x85,
            0x06, 0x00,
            0x00, 0x00, // 2:  jne 14
            0xB8, 0x02,
            0x00, 0x00,
            0x00, // 8:  mov eax, 2
            0xC3, // 13: ret
            0xB8, 0x01,
            0x00, 0x00,
            0x00, // 14: mov eax, 1
            0xC3, // 19: ret
        });

    CheckJccFunction(code);
}

#endif
