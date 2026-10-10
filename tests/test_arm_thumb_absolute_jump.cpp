#include "catch.hpp"

#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_ARM)

// BUGS.md #21: the Thumb absolute jump saved r0 and the address below sp without reserving the stack, where a signal
// handler could overwrite them. The detour reads the word just below sp: the jump left its address there.
TEST_CASE("Thumb absolute jump doesn't write below the stack pointer", "[arm_thumb_absolute_jump]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());

    code.Write(0, {0x00, 0xBF, 0x00, 0xBF, 0x2A, 0x20, 0x70, 0x47}); // nop; nop; movs r0, #42; bx lr
    code.Write(64, {0x5D, 0xF8, 0x04, 0x0C, 0x70, 0x47});            // ldr r0, [sp, #-4]; bx lr

    auto function = reinterpret_cast<uintptr_t (*)()>(ThumbAddress(code.Data()));
    void *detour  = ThumbAddress(code.Data(64));

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)function, detour) != nullptr);

    // The hooked function reaches the detour through the absolute jump of its jump slot.
    CHECK(function() != reinterpret_cast<uintptr_t>(detour));

    CHECK(hook.RestoreFunction() != nullptr);
}

#endif
