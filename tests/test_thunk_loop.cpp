#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

using ThunkFunc_t = int (*)();

static int ThunkLoopDetour()
{
    return 100;
}

// The thunk chain was followed without any limit on x86 and x64: a jump to itself, or two thunks jumping to each
// other, never ended.
TEST_CASE("A thunk loop doesn't hang the hook", "[thunk_loop]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());

    code.Write(0, {0xE9, 0xFB, 0xFF, 0xFF, 0xFF}); // jmp $ (to itself)

    code.Write(32, {0xE9, 0x1B, 0x00, 0x00, 0x00}); // jmp 64
    code.Write(64, {0xE9, 0xDB, 0xFF, 0xFF, 0xFF}); // jmp 32

    // The result doesn't matter: these calls must return.
    MiniDetour::Hook_t selfLoop;
    selfLoop.CanHook(code.Data());

    MiniDetour::Hook_t twoThunksLoop;
    twoThunksLoop.CanHook(code.Data(32));
    twoThunksLoop.HookFunction(code.Data(32), reinterpret_cast<void *>(&ThunkLoopDetour));
    twoThunksLoop.RestoreFunction();
}

TEST_CASE("A short thunk chain is followed to the function", "[thunk_loop]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());

    code.Write(0, {0xE9, 0x1B, 0x00, 0x00, 0x00});  // jmp 32
    code.Write(32, {0xE9, 0x1B, 0x00, 0x00, 0x00}); // jmp 64
    code.Write(64, {0xB8, 7, 0, 0, 0, 0xC3});       // mov eax, 7 ; ret

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&ThunkLoopDetour)) != nullptr);

    // The function at the end of the chain is the one hooked.
    CHECK(code.As<ThunkFunc_t>(64)() == 100);
    CHECK(hook.GetOriginalFunction<ThunkFunc_t>()() == 7);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(code.As<ThunkFunc_t>(64)() == 7);
}

#endif
