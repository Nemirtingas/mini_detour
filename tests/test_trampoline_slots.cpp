#include "catch.hpp"
#include "test_utils.h"

#include <vector>

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

static int TrampolineSlotsDetour()
{
    return -1;
}

// BUGS.md #1: the trampoline allocator used one slot more than a page can hold,
// so the hook that landed in the last slot was written past the end of the page.
TEST_CASE("Many hooks use every trampoline slot without overflowing", "[trampoline_slots]")
{
    const size_t functionCount  = 300; // Several trampoline pages on every arch.
    const size_t functionStride = 16;

    CodeBuffer code(functionCount * functionStride);
    REQUIRE(code.IsValid());

    for (size_t i = 0; i < functionCount; ++i)
    {
        // mov eax, i ; ret
        code.Write(i * functionStride, {0xB8, 0, 0, 0, 0, 0xC3});
        code.WriteValue<int32_t>(i * functionStride + 1, static_cast<int32_t>(i));
    }

    std::vector<MiniDetour::Hook_t> hooks(functionCount);
    for (size_t i = 0; i < functionCount; ++i)
    {
        INFO("hook " << i);
        REQUIRE(hooks[i].HookFunction(code.Data(i * functionStride), reinterpret_cast<void *>(&TrampolineSlotsDetour)) != nullptr);
    }

    for (size_t i = 0; i < functionCount; ++i)
    {
        INFO("function " << i);
        CHECK(code.As<int (*)()>(i * functionStride)() == -1);
        CHECK(hooks[i].GetOriginalFunction<int (*)()>()() == static_cast<int>(i));
    }

    for (size_t i = 0; i < functionCount; ++i)
    {
        INFO("restore " << i);
        CHECK(hooks[i].RestoreFunction() != nullptr);
        CHECK(code.As<int (*)()>(i * functionStride)() == static_cast<int>(i));
    }
}

#endif
