#include "catch.hpp"
#include "test_utils.h"

#include <utility>

static int HookMoveDetour()
{
    return 100;
}

// Move assigning a Hook_t overwrote its handle without freeing it,
// so the hook it held was never restored (and the handle leaked).
TEST_CASE("Move assigning over an active hook restores it", "[hook_move]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    GeneratedCode::WriteReturnConstant(code, 0, 1);
    auto function = GeneratedCode::Function(code);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)function, reinterpret_cast<void *>(&HookMoveDetour)) != nullptr);
    REQUIRE(function() == 100);

    hook = MiniDetour::Hook_t();
    CHECK(function() == 1);
}

TEST_CASE("Self move assignment keeps the hook", "[hook_move]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    GeneratedCode::WriteReturnConstant(code, 0, 1);
    auto function = GeneratedCode::Function(code);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)function, reinterpret_cast<void *>(&HookMoveDetour)) != nullptr);

    MiniDetour::Hook_t &sameHook = hook;
    hook                         = std::move(sameHook);
    CHECK(function() == 100);
    CHECK(hook.GetOriginalFunction<int (*)()>()() == 1);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 1);
}
