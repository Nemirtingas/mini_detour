#include "catch.hpp"
#include "test_utils.h"

#if defined(TEST_HOOKS_CODE)

static int TEST_CALL RestoreOnlyHookBytesDetour()
{
    return 100;
}

// The restore wrote back every byte read to find the relocatable code (up to the size of an absolute jump), although
// the hook only overwrote the bytes of its relative jump: a change made after them in the meantime was undone.
TEST_CASE("Restoring a hook only writes back the bytes it overwrote", "[restore_hook_bytes]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    // No-op instructions after the return value: room for an absolute jump.
    GeneratedCode::WriteReturnConstant(code, 0, 1, 32 / GeneratedCode::NopSize);
    auto function = GeneratedCode::Function<int(TEST_CALL *)()>(code);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)function, reinterpret_cast<void *>(&RestoreOnlyHookBytesDetour)) != nullptr);
    CHECK(function() == 100);

    // Someone else patches a no-op instruction after the hook's relative jump, within the size of an absolute jump.
#if defined(MINIDETOUR_ARCH_ARM)
    const size_t patchOffset = 4;
#else
    const size_t patchOffset = 8;
#endif
    GeneratedCode::WriteOtherNop(code, patchOffset);
    uint8_t patch[GeneratedCode::NopSize];
    memcpy(patch, code.Data(patchOffset), sizeof(patch));

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(memcmp(code.Data(patchOffset), patch, sizeof(patch)) == 0);
    CHECK(function() == 1);
}

#endif
