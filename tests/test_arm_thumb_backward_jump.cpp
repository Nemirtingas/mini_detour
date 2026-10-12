#include "catch.hpp"

#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_ARM)
#include <sys/mman.h>

#include <vector>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

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

// Reserves size bytes exactly at address (nothing can be allocated there anymore), nullptr if they aren't free.
static void *ReserveAt(uintptr_t address, size_t size)
{
    void *reserved = mmap(reinterpret_cast<void *>(address), size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (reserved == MAP_FAILED)
        return nullptr;

    if (reserved != reinterpret_cast<void *>(address))
    {
        munmap(reserved, size);
        return nullptr;
    }

    return reserved;
}

// Start of size free bytes more than 16 MB (the B.W range) away from any executable memory, 0 if there are none: the
// jump regions of the earlier tests, next to their code, are out of range from there.
static uintptr_t FindIsolatedArea(size_t size)
{
    const uintptr_t range = 0x1000000 + 0x10000;

    std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> regions(MiniDetour::MemoryManipulation::GetAllRegions(nullptr, 0) * 2);
    for (auto &region : regions)
        region.StructSize = sizeof(region);
    regions.resize(MiniDetour::MemoryManipulation::GetAllRegions(regions.data(), regions.size()));

    for (auto const &free : regions)
    {
        if (free.Rights != MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
            continue;

        for (uintptr_t start = (free.Start + 0xFFFF) & ~static_cast<uintptr_t>(0xFFFF); start >= free.Start && free.End - start >= size; start += 0x100000)
        {
            bool isolated = true;
            for (auto const &code : regions)
            {
                if (code.Rights == MiniDetour::MemoryManipulation::MemoryRights::mem_unset || (code.Rights & MiniDetour::MemoryManipulation::MemoryRights::mem_x) == 0)
                    continue;

                // Distance between [start, start + size) and the code region.
                const uintptr_t distance = code.End <= start ? start - code.End : (code.Start >= start + size ? code.Start - (start + size) : 0);
                isolated &= distance > range;
            }

            if (isolated)
                return start;
        }
    }

    return 0;
}

// The Thumb B.W encoder used rel_addr >> 31 as the sign bit: -1 for a backward jump, which set every bit of the
// opcode. Every hook whose jump slot was below the function jumped to a wrong address.
TEST_CASE("Thumb hook jumping backward to its jump slot", "[arm_thumb_backward_jump]")
{
    const uintptr_t mb    = 0x100000;
    const size_t pageSize = MiniDetour::MemoryManipulation::PageSize();

    // [free: 4 MB][first function][reserved][second function][reserved], far from the earlier jump regions.
    // The jump region of the first hook is allocated next to the first function, below it: the closest free memory.
    // The second function, 1 MB above, then uses a free slot of that region, below it.
    const uintptr_t base = FindIsolatedArea(8 * mb);
    REQUIRE(base != 0);

    const uintptr_t firstAddress  = base + 4 * mb;
    const uintptr_t secondAddress = base + 5 * mb;
    void *lowBlocker              = ReserveAt(firstAddress + pageSize, secondAddress - firstAddress - pageSize);
    void *highBlocker             = ReserveAt(secondAddress + pageSize, 2 * mb);
    REQUIRE(lowBlocker != nullptr);
    REQUIRE(highBlocker != nullptr);

    CodeBuffer first(pageSize, reinterpret_cast<void *>(firstAddress));
    REQUIRE(first.Data() == reinterpret_cast<uint8_t *>(firstAddress));
    first.Write(0, {0x00, 0xBF, 0x00, 0xBF, 0x2A, 0x20, 0x70, 0x47}); // nop; nop; movs r0, #42; bx lr
    first.Write(64, {0x07, 0x20, 0x70, 0x47});                        // movs r0, #7; bx lr
    MiniDetour::Hook_t firstHook;
    REQUIRE(firstHook.HookFunction(ThumbAddress(first.Data()), ThumbAddress(first.Data(64))) != nullptr);

    const uintptr_t firstSlot = ThumbWideJumpTarget(first.Data());
    REQUIRE(firstSlot != 0);
    INFO("First function: " << (void *)firstAddress << ", its jump slot: " << (void *)firstSlot);
    REQUIRE(firstSlot < firstAddress);

    CodeBuffer second(pageSize, reinterpret_cast<void *>(secondAddress));
    REQUIRE(second.Data() == reinterpret_cast<uint8_t *>(secondAddress));
    second.Write(0, {0x00, 0xBF, 0x00, 0xBF, 0x2B, 0x20, 0x70, 0x47}); // nop; nop; movs r0, #43; bx lr
    second.Write(64, {0x08, 0x20, 0x70, 0x47});                        // movs r0, #8; bx lr
    auto function = reinterpret_cast<int (*)()>(ThumbAddress(second.Data()));

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)function, ThumbAddress(second.Data(64))) != nullptr);

    // The jump slot is below the function: the B.W jumps backward.
    const uintptr_t secondSlot = ThumbWideJumpTarget(second.Data());
    REQUIRE(secondSlot != 0);
    CHECK(secondSlot < secondAddress);

    CHECK(function() == 8);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 43);
    CHECK(firstHook.RestoreFunction() != nullptr);

    munmap(highBlocker, 2 * mb);
    munmap(lowBlocker, secondAddress - firstAddress - pageSize);
}

#endif
