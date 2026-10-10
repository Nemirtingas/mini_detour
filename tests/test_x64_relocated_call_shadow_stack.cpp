#include "catch.hpp"

#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_WINDOWS) && defined(MINIDETOUR_ARCH_X64) && defined(_MSC_VER)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string.h>

// Hand-written code placed in the tests executable itself. The tests are linked with /CETCOMPAT: Windows then enables
// shadow stacks (on CPUs that have them) and kills the process on a return to this image that no call pushed. A return
// to allocated memory would be let through, so a CodeBuffer can't be used.
#pragma section(".mdcall", read, execute)
__declspec(allocate(".mdcall")) static unsigned char g_CallFirstCode[64];

static __declspec(noinline) int CallFirstCallee(int value)
{
    volatile int result = value + 1;
    return result;
}

static int CallFirstDetour(int)
{
    return 100;
}

static bool ShadowStackEnabled()
{
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY policy{};
    return GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &policy, sizeof(policy)) && policy.EnableUserShadowStack;
}

// A call in the relocated bytes was turned into "push return address ; jmp target": the target's ret then went back to
// an address no call had pushed, and the process was killed when shadow stacks (CET) are enabled.
TEST_CASE("A relocated call keeps the shadow stack consistent", "[x64_relocated_call]")
{
    if (!ShadowStackEnabled())
        WARN("Shadow stacks aren't enabled: the relocated call runs, but the shadow stack isn't checked.");

    // sub rsp, 28h ; call CallFirstCallee ; lea eax, [rax + rax * 2] ; add rsp, 28h ; ret
    uint8_t code[]              = {0x48, 0x83, 0xEC, 0x28, 0xE8, 0, 0, 0, 0, 0x8D, 0x04, 0x40, 0x48, 0x83, 0xC4, 0x28, 0xC3};
    const intptr_t displacement = reinterpret_cast<intptr_t>(&CallFirstCallee) - reinterpret_cast<intptr_t>(g_CallFirstCode + 9);
    REQUIRE(displacement == static_cast<int32_t>(displacement));
    const int32_t relative = static_cast<int32_t>(displacement);
    memcpy(code + 5, &relative, sizeof(relative));

    // The section is read-only once loaded (a write attribute is ignored).
    REQUIRE(MiniDetour::MemoryManipulation::MemoryProtect(g_CallFirstCode, sizeof(g_CallFirstCode), MiniDetour::MemoryManipulation::MemoryRights::mem_rw));
    memset(g_CallFirstCode, 0xCC, sizeof(g_CallFirstCode));
    memcpy(g_CallFirstCode, code, sizeof(code));
    REQUIRE(MiniDetour::MemoryManipulation::MemoryProtect(g_CallFirstCode, sizeof(g_CallFirstCode), MiniDetour::MemoryManipulation::MemoryRights::mem_rx));
    MiniDetour::MemoryManipulation::FlushInstructionCache(g_CallFirstCode, sizeof(g_CallFirstCode));

    auto function = reinterpret_cast<int (*)(int)>(&g_CallFirstCode[0]);
    REQUIRE(function(1) == 6);

    MiniDetour::Hook_t hook;
    auto original = reinterpret_cast<int (*)(int)>(hook.HookFunction(g_CallFirstCode, reinterpret_cast<void *>(&CallFirstDetour)));
    REQUIRE(original != nullptr);

    CHECK(function(1) == 100);
    CHECK(original(1) == 6);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function(1) == 6);
}

#endif
