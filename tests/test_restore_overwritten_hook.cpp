#include "catch.hpp"
#include "test_utils.h"

#if defined(TEST_HOOKS_CODE)

static int OverwrittenHookDetour()
{
    return 100;
}

// When another tool hooked over our hook, RestoreFunction rewrote the jump to the detour
// instead of redirecting it to the original code, so the detour stayed active.
TEST_CASE("Restoring a hook overwritten by someone else bypasses the detour", "[restore_overwritten]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    GeneratedCode::WriteReturnConstant(code, 0, 1);
    auto function = GeneratedCode::Function(code);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)function, reinterpret_cast<void *>(&OverwrittenHookDetour)) != nullptr);

    // Our hook is a relative jump to a jump going to the detour.
    void *ourJump = reinterpret_cast<void *>(GeneratedCode::RelativeJumpTarget(code.Data()));
    REQUIRE(ourJump != nullptr);

    // Another tool hooks the function: function -> its stub -> our jump.
    const size_t stubOffset = 64;
    GeneratedCode::WriteRelativeJump(code, stubOffset, ourJump);
    GeneratedCode::WriteRelativeJump(code, 0, code.Data(stubOffset));
    REQUIRE(function() == 100);

    CHECK(hook.RestoreFunction() != nullptr);

    // The other tool's hook still goes through our jump, which must now lead to the original code.
    CHECK(function() == 1);
}

#endif
