#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

using TwiceFunc_t = int (*)();

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
    code.Write(0, {0xB8, 1, 0, 0, 0, 0xC3});  // mov eax, 1 ; ret
    code.Write(32, {0xB8, 2, 0, 0, 0, 0xC3}); // mov eax, 2 ; ret

    auto first  = code.As<TwiceFunc_t>();
    auto second = code.As<TwiceFunc_t>(32);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&HookTwiceDetour)) != nullptr);
    CHECK(hook.HookFunction(code.Data(32), reinterpret_cast<void *>(&HookTwiceDetour)) == nullptr);

    CHECK(first() == 100);
    CHECK(second() == 2);
    CHECK(hook.GetOriginalFunction<TwiceFunc_t>()() == 1);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(first() == 1);
    CHECK(second() == 2);
}

#endif
