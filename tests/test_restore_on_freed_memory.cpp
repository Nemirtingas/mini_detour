#include "catch.hpp"

#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

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
        CodeBuffer code;
        REQUIRE(code.IsValid());
        code.Write(0, {0x90, 0xB8, 42, 0, 0, 0, 0xC3}); // nop; mov eax, 42; ret
        REQUIRE(hook.HookFunction(code.Data(), (void *)&FreedMemoryDetour) != nullptr);
    }

    CHECK(hook.RestoreFunction() == nullptr);
    CHECK(hook.GetOriginalFunction() == nullptr);

    // The hook object can be used again.
    CodeBuffer other;
    REQUIRE(other.IsValid());
    other.Write(0, {0x90, 0xB8, 43, 0, 0, 0, 0xC3}); // nop; mov eax, 43; ret
    auto function = other.As<int(TEST_CALL *)()>();

    auto original = reinterpret_cast<int(TEST_CALL *)()>(hook.HookFunction((void *)function, (void *)&FreedMemoryDetour));
    REQUIRE(original != nullptr);
    CHECK(function() == 7);
    CHECK(original() == 43);
    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 43);
}

#endif
