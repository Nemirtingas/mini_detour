#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

using OverwrittenFunc_t = int (*)();

static int OverwrittenHookDetour()
{
    return 100;
}

static void WriteRelativeJump(CodeBuffer &code, size_t offset, void *destination)
{
    code.Write(offset, {0xE9, 0, 0, 0, 0});
    code.WriteValue<int32_t>(offset + 1, static_cast<int32_t>(reinterpret_cast<intptr_t>(destination) - reinterpret_cast<intptr_t>(code.Data(offset + 5))));
}

// When another tool hooked over our hook, RestoreFunction rewrote the jump to the detour
// instead of redirecting it to the original code, so the detour stayed active.
TEST_CASE("Restoring a hook overwritten by someone else bypasses the detour", "[restore_overwritten]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    code.Write(0, {0xB8, 1, 0, 0, 0, 0xC3}); // mov eax, 1 ; ret

    auto function = code.As<OverwrittenFunc_t>();

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&OverwrittenHookDetour)) != nullptr);
    REQUIRE(code.Data()[0] == 0xE9);

    // Our hook is a "jmp rel32" to a jump going to the detour.
    void *ourJump = code.Data(5 + *reinterpret_cast<int32_t *>(code.Data(1)));

    // Another tool hooks the function: function -> its stub -> our jump.
    const size_t stubOffset = 64;
    WriteRelativeJump(code, stubOffset, ourJump);
    WriteRelativeJump(code, 0, code.Data(stubOffset));
    REQUIRE(function() == 100);

    CHECK(hook.RestoreFunction() != nullptr);

    // The other tool's hook still goes through our jump, which must now lead to the original code.
    CHECK(function() == 1);
}

#endif
