#include "catch.hpp"

#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

static int TEST_CALL PageEndDetour()
{
    return 7;
}

// BUGS.md #15: the prologue was always read with an 80 bytes memcpy, past the end of the mapping
// for a small function at the end of its last page.
TEST_CASE("Hook a function at the end of a readable page", "[page_end]")
{
    const size_t pageSize = MiniDetour::MemoryManipulation::PageSize();

    CodeBuffer code(pageSize * 2);
    REQUIRE(code.IsValid());

    // nop; mov eax, 42; ret -- ends exactly at the end of the first page.
    const size_t functionOffset = pageSize - 7;
    code.Write(functionOffset, {0x90, 0xB8, 42, 0, 0, 0, 0xC3});

    // The next page can't be read.
    REQUIRE(MiniDetour::MemoryManipulation::MemoryProtect(code.Data(pageSize), pageSize, MiniDetour::MemoryManipulation::MemoryRights::mem_none));

    auto function = code.As<int(TEST_CALL *)()>(functionOffset);
    REQUIRE(function() == 42);

    MiniDetour::Hook_t hook;
    auto original = reinterpret_cast<int(TEST_CALL *)()>(hook.HookFunction((void *)function, (void *)&PageEndDetour));
    REQUIRE(original != nullptr);

    CHECK(function() == 7);
    CHECK(original() == 42);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 42);
}

#endif
