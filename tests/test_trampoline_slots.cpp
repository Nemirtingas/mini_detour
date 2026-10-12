#include "catch.hpp"
#include "test_utils.h"

#include <vector>

#if defined(TEST_HOOKS_GENERATED_CODE)

static int TrampolineSlotsDetour()
{
    return -1;
}

// The trampoline allocator used one slot more than a page can hold,
// so the hook that landed in the last slot was written past the end of the page.
TEST_CASE("Many hooks use every trampoline slot without overflowing", "[trampoline_slots]")
{
    const size_t functionCount  = 300; // Several trampoline pages on every arch.
    const size_t functionStride = 16;

    CodeBuffer code(functionCount * functionStride);
    REQUIRE(code.IsValid());

    for (size_t i = 0; i < functionCount; ++i)
        GeneratedCode::WriteReturnConstant(code, i * functionStride, static_cast<uint16_t>(i));

    std::vector<MiniDetour::Hook_t> hooks(functionCount);
    for (size_t i = 0; i < functionCount; ++i)
    {
        INFO("hook " << i);
        REQUIRE(hooks[i].HookFunction((void *)GeneratedCode::Function(code, i * functionStride), reinterpret_cast<void *>(&TrampolineSlotsDetour)) != nullptr);
    }

    for (size_t i = 0; i < functionCount; ++i)
    {
        INFO("function " << i);
        CHECK(GeneratedCode::Function(code, i * functionStride)() == -1);
        CHECK(hooks[i].GetOriginalFunction<int (*)()>()() == static_cast<int>(i));
    }

    for (size_t i = 0; i < functionCount; ++i)
    {
        INFO("restore " << i);
        CHECK(hooks[i].RestoreFunction() != nullptr);
        CHECK(GeneratedCode::Function(code, i * functionStride)() == static_cast<int>(i));
    }
}

#endif
