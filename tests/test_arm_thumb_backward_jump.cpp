#include "catch.hpp"

#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_ARM)

static void* ThumbAddress(void* address)
{
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(address) | 1);
}

// The Thumb B.W encoder used rel_addr >> 31 as the sign bit: -1 for a backward jump, which set every bit of the
// opcode. Every hook whose jump slot was below the function jumped to a wrong address.
TEST_CASE("Thumb hook jumping backward to its jump slot", "[arm_thumb_backward_jump]")
{
    // A first hook creates a jump region next to its function, with free slots left.
    CodeBuffer first;
    REQUIRE(first.IsValid());
    first.Write(0, { 0x00, 0xBF, 0x00, 0xBF, 0x2A, 0x20, 0x70, 0x47 }); // nop; nop; movs r0, #42; bx lr
    first.Write(64, { 0x07, 0x20, 0x70, 0x47 });                        // movs r0, #7; bx lr
    MiniDetour::Hook_t firstHook;
    REQUIRE(firstHook.HookFunction(ThumbAddress(first.Data()), ThumbAddress(first.Data(64))) != nullptr);

    // A second function above, within 16 MB: it uses a free slot of that region (allocated next to the first
    // function, several pages below the second one).
    CodeBuffer second(4096, first.Data(0x100000));
    REQUIRE(second.IsValid());
    REQUIRE(reinterpret_cast<uintptr_t>(second.Data()) > reinterpret_cast<uintptr_t>(first.Data()) + 0x8000);
    REQUIRE(reinterpret_cast<uintptr_t>(second.Data()) - reinterpret_cast<uintptr_t>(first.Data()) < 0xF00000);

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
