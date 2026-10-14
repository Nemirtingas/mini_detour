#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_ARM64)
static int Arm64LiveIpDetour()
{
    return 100;
}

TEST_CASE("The trampoline return branch preserves a live IP register", "[arm64][hook]")
{
    CodeBuffer_t code;
    REQUIRE(code.IsValid());

    // movz x17, #1 ; movz w0, #1 ; add w0, w0, w17 ; ret
    code.Write(0, {0x31, 0x00, 0x80, 0xD2, 0x20, 0x00, 0x80, 0x52, 0x00, 0x00, 0x11, 0x0B, 0xC0, 0x03, 0x5F, 0xD6});
    auto function = code.As<int (*)()>();
    REQUIRE(function() == 2);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&Arm64LiveIpDetour)) != nullptr);
    CHECK(function() == 100);
    CHECK(hook.GetOriginalFunction<int (*)()>()() == 2);
    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 2);
}
#endif
