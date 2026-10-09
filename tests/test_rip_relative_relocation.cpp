#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X64)

using RipFunc_t = uint64_t (*)();

static const size_t RipDataOffset     = 128;
static const uint64_t RipDataValue    = 0x1122334455667788ull;
static const uint64_t RipDetourResult = 0xDEADull;

static uint64_t RipRelativeDetour()
{
    return RipDetourResult;
}

static int32_t RipDisp(size_t nextInstructionOffset)
{
    return static_cast<int32_t>(RipDataOffset - nextInstructionOffset);
}

static void CheckRipFunction(CodeBuffer &code, uint64_t expected)
{
    code.WriteValue<uint64_t>(RipDataOffset, RipDataValue);

    auto function = code.As<RipFunc_t>();
    REQUIRE(function() == expected);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&RipRelativeDetour)) != nullptr);
    CHECK(function() == RipDetourResult);
    CHECK(hook.GetOriginalFunction<RipFunc_t>()() == expected);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == expected);
}

// BUGS.md #12: "mov reg, [rip + x]" was relocated as "movabs reg, address" (the address instead of the value),
// and registers other than rax/rcx/rdx/rbx produced invalid code.
TEST_CASE("Relocate mov rax, (rip + x)", "[rip_relocation]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    code.Write(0, {0x48, 0x8B, 0x05, 0, 0, 0, 0, 0xC3}); // mov rax, [rip + x] ; ret
    code.WriteValue<int32_t>(3, RipDisp(7));
    CheckRipFunction(code, RipDataValue);
}

TEST_CASE("Relocate mov eax, (rip + x)", "[rip_relocation]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    code.Write(0, {0x8B, 0x05, 0, 0, 0, 0, 0xC3}); // mov eax, [rip + x] ; ret
    code.WriteValue<int32_t>(2, RipDisp(6));
    CheckRipFunction(code, RipDataValue & 0xFFFFFFFFull);
}

TEST_CASE("Relocate mov r11, (rip + x)", "[rip_relocation]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    code.Write(0, {
        0x4C, 0x8B, 0x1D, 0, 0, 0, 0, // mov r11, [rip + x]
        0x4C, 0x89, 0xD8,             // mov rax, r11
        0xC3,                         // ret
    });
    code.WriteValue<int32_t>(3, RipDisp(7));
    CheckRipFunction(code, RipDataValue);
}

TEST_CASE("Relocate mov r12, (rip + x) (SIB encoding)", "[rip_relocation]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    code.Write(0, {
        0x41, 0x54,                   // push r12
        0x4C, 0x8B, 0x25, 0, 0, 0, 0, // mov r12, [rip + x]
        0x4C, 0x89, 0xE0,             // mov rax, r12
        0x41, 0x5C,                   // pop r12
        0xC3,                         // ret
    });
    code.WriteValue<int32_t>(5, RipDisp(9));
    CheckRipFunction(code, RipDataValue);
}

TEST_CASE("Relocate mov r13, (rip + x) (disp8 encoding)", "[rip_relocation]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    code.Write(0, {
        0x41, 0x55,                   // push r13
        0x4C, 0x8B, 0x2D, 0, 0, 0, 0, // mov r13, [rip + x]
        0x4C, 0x89, 0xE8,             // mov rax, r13
        0x41, 0x5D,                   // pop r13
        0xC3,                         // ret
    });
    code.WriteValue<int32_t>(5, RipDisp(9));
    CheckRipFunction(code, RipDataValue);
}

TEST_CASE("Relocate lea rax, (rip + x)", "[rip_relocation]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    code.Write(0, {0x48, 0x8D, 0x05, 0, 0, 0, 0, 0xC3}); // lea rax, [rip + x] ; ret
    code.WriteValue<int32_t>(3, RipDisp(7));
    CheckRipFunction(code, reinterpret_cast<uint64_t>(code.Data(RipDataOffset)));
}

#endif
