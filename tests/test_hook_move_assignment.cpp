#include "catch.hpp"
#include "test_utils.h"

#include <utility>

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

using MoveFunc_t = int (*)();

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
    code.Write(0, {0xB8, 1, 0, 0, 0, 0xC3}); // mov eax, 1 ; ret
    auto function = code.As<MoveFunc_t>();

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&HookMoveDetour)) != nullptr);
    REQUIRE(function() == 100);

    hook = MiniDetour::Hook_t();
    CHECK(function() == 1);
}

TEST_CASE("Self move assignment keeps the hook", "[hook_move]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    code.Write(0, {0xB8, 1, 0, 0, 0, 0xC3}); // mov eax, 1 ; ret
    auto function = code.As<MoveFunc_t>();

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&HookMoveDetour)) != nullptr);

    MiniDetour::Hook_t &sameHook = hook;
    hook                         = std::move(sameHook);
    CHECK(function() == 100);
    CHECK(hook.GetOriginalFunction<MoveFunc_t>()() == 1);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 1);
}

#endif
