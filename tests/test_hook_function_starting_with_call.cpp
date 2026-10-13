#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

using CallFunc_t = int (*)();

static int StartsWithCallDetour()
{
    return 100;
}

// A function starting with "call" was treated as a thunk, so the callee was hooked instead.
TEST_CASE("Hook a function starting with a call", "[call_prologue]")
{
    CodeBuffer_t code;
    REQUIRE(code.IsValid());

    const size_t calleeOffset = 32;
    code.Write(
        0,
        {
            0xE8,
            0,
            0,
            0,
            0, // 0: call callee
            0x83,
            0xC0,
            0x01, // 5: add eax, 1
            0xC3, // 8: ret
        });
    code.WriteValue<int32_t>(1, static_cast<int32_t>(calleeOffset - 5));
    code.Write(calleeOffset, {0xB8, 41, 0, 0, 0, 0xC3}); // callee: mov eax, 41 ; ret

    auto function = code.As<CallFunc_t>();
    auto callee   = code.As<CallFunc_t>(calleeOffset);
    REQUIRE(function() == 42);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&StartsWithCallDetour)) != nullptr);

    CHECK(function() == 100);
    CHECK(callee() == 41);
    CHECK(hook.GetOriginalFunction<CallFunc_t>()() == 42);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 42);
    CHECK(callee() == 41);
}

#endif
