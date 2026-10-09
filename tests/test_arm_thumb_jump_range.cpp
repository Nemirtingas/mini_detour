#include "catch.hpp"

#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_ARM)

static void* ThumbAddress(void* address)
{
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(address) | 1);
}

// BUGS.md #20: a jump slot was usable if within the ARM branch range (+-32 MB), but a Thumb B.W only reaches
// +-16 MB: a free slot 16 to 32 MB away from a Thumb function was used and the jump was truncated.
TEST_CASE("Thumb hook with a jump region 20 MB away", "[arm_thumb_jump_range]")
{
    // A first hook creates a jump region next to its function, with free slots left.
    CodeBuffer first;
    REQUIRE(first.IsValid());
    first.Write(0, { 0x00, 0xBF, 0x00, 0xBF, 0x2A, 0x20, 0x70, 0x47 }); // nop; nop; movs r0, #42; bx lr
    first.Write(64, { 0x07, 0x20, 0x70, 0x47 });                        // movs r0, #7; bx lr
    MiniDetour::Hook_t firstHook;
    REQUIRE(firstHook.HookFunction(ThumbAddress(first.Data()), ThumbAddress(first.Data(64))) != nullptr);

    // A second function 20 MB away: in reach of that region for ARM, not for Thumb.
    CodeBuffer second(4096, first.Data(0x1400000));
    REQUIRE(second.IsValid());
    const uintptr_t distance = reinterpret_cast<uintptr_t>(second.Data()) - reinterpret_cast<uintptr_t>(first.Data());
    REQUIRE(distance > 0x1100000);
    REQUIRE(distance < 0x1E00000);

    second.Write(0, { 0x00, 0xBF, 0x00, 0xBF, 0x2B, 0x20, 0x70, 0x47 }); // nop; nop; movs r0, #43; bx lr
    second.Write(64, { 0x08, 0x20, 0x70, 0x47 });                        // movs r0, #8; bx lr
    auto function = reinterpret_cast<int (*)()>(ThumbAddress(second.Data()));

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void*)function, ThumbAddress(second.Data(64))) != nullptr);
    CHECK(function() == 8);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 43);
    CHECK(firstHook.RestoreFunction() != nullptr);
}

#endif
