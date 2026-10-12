#include "catch.hpp"

#include "test_utils.h"

#include <memory>
#include <vector>

#if defined(MINIDETOUR_ARCH_ARM)

// Destination of the Thumb B.W at address, 0 if there is none.
// B.W: 11110 S imm10, then 10 J1 1 J2 imm11. I1 = !(J1 ^ S), I2 = !(J2 ^ S), offset = S:I1:I2:imm10:imm11:0 from pc + 4.
static uintptr_t ThumbWideJumpTarget(const void *address)
{
    const uint16_t *opcode = static_cast<const uint16_t *>(address);
    if ((opcode[0] & 0xF800) != 0xF000 || (opcode[1] & 0xD000) != 0x9000)
        return 0;

    const uint32_t s     = (opcode[0] >> 10) & 1;
    const uint32_t i1    = ((opcode[1] >> 13) & 1) ^ s ^ 1;
    const uint32_t i2    = ((opcode[1] >> 11) & 1) ^ s ^ 1;
    const uint32_t imm   = (s << 24) | (i1 << 23) | (i2 << 22) | ((opcode[0] & 0x3FFu) << 12) | ((opcode[1] & 0x7FFu) << 1);
    const int32_t offset = static_cast<int32_t>(imm << 7) >> 7; // 25 bits sign extension
    return reinterpret_cast<uintptr_t>(address) + 4 + offset;
}

// The Thumb B.W encoder used rel_addr >> 31 as the sign bit: -1 for a backward jump, which set every bit of the
// opcode. Every hook whose jump slot was below the function jumped to a wrong address.
TEST_CASE("Thumb hook jumping backward to its jump slot", "[arm_thumb_backward_jump]")
{
    // A first hook creates a jump region next to its function, with free slots left.
    CodeBuffer first;
    REQUIRE(first.IsValid());
    first.Write(0, {0x00, 0xBF, 0x00, 0xBF, 0x2A, 0x20, 0x70, 0x47}); // nop; nop; movs r0, #42; bx lr
    first.Write(64, {0x07, 0x20, 0x70, 0x47});                        // movs r0, #7; bx lr
    MiniDetour::Hook_t firstHook;
    REQUIRE(firstHook.HookFunction(ThumbAddress(first.Data()), ThumbAddress(first.Data(64))) != nullptr);

    // The region is somewhere near the first function, above or below it: its address comes from the jump written.
    const uintptr_t firstSlot = ThumbWideJumpTarget(first.Data());
    REQUIRE(firstSlot != 0);

    // A second function above the region, within B.W range: it uses a free slot of that region, below it. The memory
    // just above the region can be taken (earlier tests), and the closest allocation then lands below it: buffers
    // placed below are kept while searching, so that the next attempts go elsewhere.
    std::vector<std::unique_ptr<CodeBuffer>> buffers;
    CodeBuffer *found = nullptr;
    for (uintptr_t hint = firstSlot + 0x10000; found == nullptr && buffers.size() < 16; hint += 0x10000)
    {
        buffers.emplace_back(new CodeBuffer(4096, reinterpret_cast<void *>(hint)));
        const uintptr_t address = reinterpret_cast<uintptr_t>(buffers.back()->Data());
        if (buffers.back()->IsValid() && address > firstSlot + 0x1000 && address - firstSlot < 0xF00000)
            found = buffers.back().get();
    }
    REQUIRE(found != nullptr);
    CodeBuffer &second = *found;

    second.Write(0, {0x00, 0xBF, 0x00, 0xBF, 0x2B, 0x20, 0x70, 0x47}); // nop; nop; movs r0, #43; bx lr
    second.Write(64, {0x08, 0x20, 0x70, 0x47});                        // movs r0, #8; bx lr
    auto function = reinterpret_cast<int (*)()>(ThumbAddress(second.Data()));

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)function, ThumbAddress(second.Data(64))) != nullptr);

    // The closest region with a free slot is the first one, below the function: the B.W jumps backward.
    const uintptr_t secondSlot = ThumbWideJumpTarget(second.Data());
    REQUIRE(secondSlot != 0);
    CHECK(secondSlot < reinterpret_cast<uintptr_t>(second.Data()));

    CHECK(function() == 8);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 43);
    CHECK(firstHook.RestoreFunction() != nullptr);
}

#endif
