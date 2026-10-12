#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X64)

#if defined(MINIDETOUR_OS_WINDOWS)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#endif

using PushFunc_t = int (*)();

static int PushReturnAddressDetour()
{
    return 100;
}

// Allocates executable memory whose address has its upper 32 bits cleared and bit 31 set.
static uint8_t *AllocBetween2And4GB(size_t size)
{
    for (uintptr_t address = 0x80000000; address < 0x100000000; address += 0x10000000)
    {
#if defined(MINIDETOUR_OS_WINDOWS)
        void *result = VirtualAlloc(reinterpret_cast<void *>(address), size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (result != nullptr)
            return static_cast<uint8_t *>(result);
#else
        void *result = mmap(reinterpret_cast<void *>(address), size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (result == reinterpret_cast<void *>(address))
            return static_cast<uint8_t *>(result);
        if (result != MAP_FAILED)
            munmap(result, size);
#endif
    }

    return nullptr;
}

static void FreeBetween2And4GB(uint8_t *memory, size_t size)
{
#if defined(MINIDETOUR_OS_WINDOWS)
    VirtualFree(memory, 0, MEM_RELEASE);
#else
    munmap(memory, size);
#endif
}

// A relocated call used to push its return address with "push imm32", which sign-extends its operand: a
// return address like 0x00000000_9xxxxxxx became 0xFFFFFFFF_9xxxxxxx. It is now a real call, kept as a regression test.
TEST_CASE("Relocated call returns to an address between 2 and 4 GB", "[x64_push]")
{
    const size_t size = 4096;
    // On macOS, the tests are linked with a small __PAGEZERO for it.
    uint8_t *code = AllocBetween2And4GB(size);
    REQUIRE(code != nullptr);

    const size_t calleeOffset = 32;
    const uint8_t function[]  = {
        0x90, // 0: nop (so the function isn't taken for a thunk)
        0xE8,
        calleeOffset - 6,
        0,
        0,
        0, // 1: call callee
        0x83,
        0xC0,
        0x01, // 6: add eax, 1
        0xC3, // 9: ret
    };
    const uint8_t callee[] = {0xB8, 41, 0, 0, 0, 0xC3}; // mov eax, 41 ; ret
    memcpy(code, function, sizeof(function));
    memcpy(code + calleeOffset, callee, sizeof(callee));

    auto functionPtr = reinterpret_cast<PushFunc_t>(code);
    REQUIRE(functionPtr() == 42);

    {
        MiniDetour::Hook_t hook;
        REQUIRE(hook.HookFunction(code, reinterpret_cast<void *>(&PushReturnAddressDetour)) != nullptr);

        CHECK(functionPtr() == 100);
        CHECK(hook.GetOriginalFunction<PushFunc_t>()() == 42);

        CHECK(hook.RestoreFunction() != nullptr);
    }

    CHECK(functionPtr() == 42);
    FreeBetween2And4GB(code, size);
}

#endif
