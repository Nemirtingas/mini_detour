#include "catch.hpp"

#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_ARM)

// The relative jump size was computed to the detour, but the jump goes to a jump slot allocated later.
// A detour within 2 KB gave a 2 bytes Thumb jump size while the jump to the slot needs 4 bytes: only 2 bytes were
// saved and relocated, and 4 bytes were written in a 2 bytes buffer.
TEST_CASE("Hook a Thumb function with a close detour", "[arm_thumb_hook]")
{
    // 64 KB: the function is at the start, so the jump slot, allocated next to the buffer, is far from it.
    CodeBuffer_t code(0x10000);
    REQUIRE(code.IsValid());

    code.Write(0, {0x00, 0xBF, 0x00, 0xBF, 0x2A, 0x20, 0x70, 0x47}); // nop; nop; movs r0, #42; bx lr
    code.Write(64, {0x07, 0x20, 0x70, 0x47});                        // movs r0, #7; bx lr

    auto function = reinterpret_cast<int (*)()>(ThumbAddress(code.Data()));
    void *detour  = ThumbAddress(code.Data(64));
    REQUIRE(function() == 42);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)function, detour) != nullptr);
    CHECK(function() == 7);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 42);
}

#endif
