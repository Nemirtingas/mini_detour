#include "catch.hpp"

#include "test_utils.h"

static int TEST_CALL FreedMemoryDetour()
{
    return 7;
}

// Restoring a hook whose function memory was freed returned without releasing the hook,
// so the object stayed "hooked": its jump and trampoline leaked and it couldn't hook anything else.
TEST_CASE("Restore a hook on freed memory", "[restore_freed]")
{
    MiniDetour::Hook_t hook;

    {
        CodeBuffer_t code;
        REQUIRE(code.IsValid());
        GeneratedCode::WriteReturnConstant(code, 0, 42);
        REQUIRE(hook.HookFunction((void *)GeneratedCode::Function(code), (void *)&FreedMemoryDetour) != nullptr);
    }

    CHECK(hook.RestoreFunction() == nullptr);
    CHECK(hook.GetOriginalFunction() == nullptr);

    // The hook object can be used again.
    CodeBuffer_t other;
    REQUIRE(other.IsValid());
    GeneratedCode::WriteReturnConstant(other, 0, 43);
    auto function = GeneratedCode::Function<int(TEST_CALL *)()>(other);

    auto original = reinterpret_cast<int(TEST_CALL *)()>(hook.HookFunction((void *)function, (void *)&FreedMemoryDetour));
    REQUIRE(original != nullptr);
    CHECK(function() == 7);
    CHECK(original() == 43);
    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 43);
}
