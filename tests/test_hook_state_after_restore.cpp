#include "catch.hpp"
#include "test_utils.h"

static int HookStateDetour()
{
    return 100;
}

// After RestoreFunction, GetOriginalFunction still returned the freed trampoline
// (which can be given to another hook) and GetHookFunction the old detour.
TEST_CASE("Restored hook doesn't expose its old trampoline", "[hook_state]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    GeneratedCode::WriteReturnConstant(code, 0, 1);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)GeneratedCode::Function(code), reinterpret_cast<void *>(&HookStateDetour)) != nullptr);
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
    GeneratedCode::WriteReturnConstant(code, 0, 1);
    GeneratedCode::WriteReturnConstant(code, 32, 2);
    auto first  = GeneratedCode::Function(code);
    auto second = GeneratedCode::Function(code, 32);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)first, reinterpret_cast<void *>(&HookStateDetour)) != nullptr);
    CHECK(hook.RestoreFunction() != nullptr);

    REQUIRE(hook.HookFunction((void *)second, reinterpret_cast<void *>(&HookStateDetour)) != nullptr);
    CHECK(first() == 1);
    CHECK(second() == 100);
    CHECK(hook.GetOriginalFunction<int (*)()>()() == 2);
    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(second() == 2);
}
