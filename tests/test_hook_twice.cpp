#include "catch.hpp"
#include "test_utils.h"

static int HookTwiceDetour()
{
    return 100;
}

// Hooking a second function with an object already in use overwrote its state,
// so the first hook could never be restored.
TEST_CASE("A hook object in use refuses to hook another function", "[hook_twice]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    GeneratedCode::WriteReturnConstant(code, 0, 1);
    GeneratedCode::WriteReturnConstant(code, 32, 2);

    auto first  = GeneratedCode::Function(code);
    auto second = GeneratedCode::Function(code, 32);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)first, reinterpret_cast<void *>(&HookTwiceDetour)) != nullptr);
    CHECK(hook.HookFunction((void *)second, reinterpret_cast<void *>(&HookTwiceDetour)) == nullptr);

    CHECK(first() == 100);
    CHECK(second() == 2);
    CHECK(hook.GetOriginalFunction<int (*)()>()() == 1);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(first() == 1);
    CHECK(second() == 2);
}
