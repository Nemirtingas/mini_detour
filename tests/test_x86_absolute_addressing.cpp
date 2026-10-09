#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X86)

using AbsoluteFunc_t = int (*)();

static int AbsoluteAddressingDetour()
{
    return 100;
}

// BUGS.md #16: on x86, [disp32] (modrm mod=00 rm=101) is an absolute address that needs no relocation,
// but it was handled like x64 rip relative addressing and the hook was refused.
TEST_CASE("Hook a function reading an absolute address", "[x86_absolute]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());

    const size_t dataOffset = 64;
    code.Write(0, {0x8B, 0x05, 0, 0, 0, 0, 0xC3}); // mov eax, [data] ; ret
    code.WriteValue<uint32_t>(2, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(code.Data(dataOffset))));
    code.WriteValue<int32_t>(dataOffset, 1234);

    auto function = code.As<AbsoluteFunc_t>();
    REQUIRE(function() == 1234);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&AbsoluteAddressingDetour)) != nullptr);
    CHECK(function() == 100);
    CHECK(hook.GetOriginalFunction<AbsoluteFunc_t>()() == 1234);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 1234);
}

#endif
