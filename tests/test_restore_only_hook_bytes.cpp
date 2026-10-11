#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

static int TEST_CALL RestoreOnlyHookBytesDetour()
{
    return 100;
}

// The restore wrote back every byte read to find the relocatable code (up to the size of an absolute jump), although
// the hook only overwrote the bytes of its relative jump: a change made after them in the meantime was undone.
TEST_CASE("Restoring a hook only writes back the bytes it overwrote", "[restore_hook_bytes]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    // nop * 16 ; mov eax, 1 ; ret
    code.Write(0, {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xB8, 1, 0, 0, 0, 0xC3});

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&RestoreOnlyHookBytesDetour)) != nullptr);
    CHECK(code.As<int(TEST_CALL *)()>()() == 100);

    // Someone else patches the function after the hook's jump: clc instead of a nop.
    code.Write(8, {0xF8});

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(*code.Data(8) == 0xF8);
    CHECK(code.As<int(TEST_CALL *)()>()() == 1);
}

#endif
