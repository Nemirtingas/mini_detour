#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

using StateFunc_t = int (*)();

static int HookStateDetour()
{
    return 100;
}

static void WriteReturnConstant(CodeBuffer &code, size_t offset, int32_t value)
{
    code.Write(offset, {0xB8, 0, 0, 0, 0, 0xC3}); // mov eax, value ; ret
    code.WriteValue<int32_t>(offset + 1, value);
}

// BUGS.md #5: after RestoreFunction, GetOriginalFunction still returned the freed trampoline
// (which can be given to another hook) and GetHookFunction the old detour.
TEST_CASE("Restored hook doesn't expose its old trampoline", "[hook_state]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    WriteReturnConstant(code, 0, 1);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&HookStateDetour)) != nullptr);
    CHECK(hook.GetOriginalFunction() != nullptr);
    CHECK(hook.GetHookFunction() != nullptr);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(hook.GetOriginalFunction() == nullptr);
    CHECK(hook.GetHookFunction() == nullptr);
}

TEST_CASE("A restored hook object can hook again", "[hook_state]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    WriteReturnConstant(code, 0, 1);
    WriteReturnConstant(code, 32, 2);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&HookStateDetour)) != nullptr);
    CHECK(hook.RestoreFunction() != nullptr);

    REQUIRE(hook.HookFunction(code.Data(32), reinterpret_cast<void *>(&HookStateDetour)) != nullptr);
    CHECK(code.As<StateFunc_t>()() == 1);
    CHECK(code.As<StateFunc_t>(32)() == 100);
    CHECK(hook.GetOriginalFunction<StateFunc_t>()() == 2);
    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(code.As<StateFunc_t>(32)() == 2);
}

#endif
