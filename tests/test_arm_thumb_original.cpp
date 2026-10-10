#include "catch.hpp"

#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_ARM)

// BUGS.md #17: the mode of the trampoline jump back to the function was read from addresses whose mode bit was
// already cleared: a Thumb function trampoline ended with an ARM jump, run in Thumb mode.
TEST_CASE("Call the original of a hooked Thumb function", "[arm_thumb_original]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());

    code.Write(0, {0x00, 0xBF, 0x00, 0xBF, 0x2A, 0x20, 0x70, 0x47}); // nop; nop; movs r0, #42; bx lr
    code.Write(64, {0x07, 0x20, 0x70, 0x47});                        // movs r0, #7; bx lr

    auto function = reinterpret_cast<int (*)()>(ThumbAddress(code.Data()));

    MiniDetour::Hook_t hook;
    auto original = reinterpret_cast<int (*)()>(hook.HookFunction((void *)function, ThumbAddress(code.Data(64))));
    REQUIRE(original != nullptr);
    CHECK((reinterpret_cast<uintptr_t>(original) & 1) == 1);

    CHECK(function() == 7);
    CHECK(original() == 42);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 42);
}

#endif
