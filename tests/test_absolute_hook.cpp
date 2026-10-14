#include "catch.hpp"
#include "test_utils.h"

// On x86, a relative jump reaches the whole address space: a jump slot can always be used.
#if !defined(MINIDETOUR_ARCH_X86)

#if defined(MINIDETOUR_OS_WINDOWS)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#include <vector>

#if defined(MINIDETOUR_OS_LINUX) && !defined(MAP_FIXED_NOREPLACE)
#define MAP_FIXED_NOREPLACE 0x100000
#endif

// Reserves size bytes exactly at address (nothing can be allocated there anymore), false if they aren't free.
static bool ReserveAt(uintptr_t address, size_t size)
{
#if defined(MINIDETOUR_OS_WINDOWS)
    return VirtualAlloc(reinterpret_cast<void *>(address), size, MEM_RESERVE, PAGE_NOACCESS) == reinterpret_cast<void *>(address);
#else
#if defined(MINIDETOUR_OS_LINUX)
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE;
#else
    const int flags = MAP_PRIVATE | MAP_ANON | MAP_NORESERVE;
#endif
    void *reserved = mmap(reinterpret_cast<void *>(address), size, PROT_NONE, flags, -1, 0);
    if (reserved == MAP_FAILED)
        return false;

    if (reserved != reinterpret_cast<void *>(address))
    {
        munmap(reserved, size);
        return false;
    }

    return true;
#endif
}

static void Release(uintptr_t address, size_t size)
{
#if defined(MINIDETOUR_OS_WINDOWS)
    (void)size;
    VirtualFree(reinterpret_cast<void *>(address), 0, MEM_RELEASE);
#else
    munmap(reinterpret_cast<void *>(address), size);
#endif
}

static int AbsoluteHookDetour()
{
    return 100;
}

// When no jump slot can be placed in range, use an absolute jump if the architecture supports a safe trampoline.
TEST_CASE("A function with no free memory in range uses an absolute jump when safe", "[absolute_hook]")
{
#if defined(MINIDETOUR_ARCH_X64)
    const uint64_t range = 0x80000000; // jmp rel32
#elif defined(MINIDETOUR_ARCH_ARM64)
    const uint64_t range = 0x8000000; // b imm26
#else
    const uint64_t range = 0x1000000; // Thumb b.w
#endif
    // Reserved around the function: [below: range + margin][function: one allocation unit][above: range + margin].
    const uint64_t unit   = 0x10000; // Allocation granularity of Windows, a multiple of the page sizes.
    const uint64_t margin = 0x100000;
    const uint64_t side   = range + margin;

    std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> freeRegions(MiniDetour::MemoryManipulation::GetFreeRegions(nullptr, 0) * 2);
    freeRegions.resize(MiniDetour::MemoryManipulation::GetFreeRegions(freeRegions.data(), freeRegions.size()));

    uintptr_t function = 0;
    for (auto const &region : freeRegions)
    {
        const uint64_t start = (static_cast<uint64_t>(region.Start) + unit - 1) & ~(unit - 1);
        if (start >= region.End || region.End - start < 2 * side + unit)
            continue;

        // Both sides are reserved separately: a reservation can't be partly released on Windows.
        const uintptr_t candidate = static_cast<uintptr_t>(start + side);
        if (!ReserveAt(static_cast<uintptr_t>(start), static_cast<size_t>(side)))
            continue;

        if (!ReserveAt(candidate + unit, static_cast<size_t>(side)))
        {
            Release(static_cast<uintptr_t>(start), static_cast<size_t>(side));
            continue;
        }

        function = candidate;
        break;
    }
    REQUIRE(function != 0);

    {
        CodeBuffer_t code(static_cast<size_t>(unit), reinterpret_cast<void *>(function));
        REQUIRE(code.Data() == reinterpret_cast<uint8_t *>(function));
        // Room for an absolute jump.
        GeneratedCode::WriteReturnConstant(code, 0, 1, 32 / GeneratedCode::NopSize);
        auto target = GeneratedCode::Function(code);

        MiniDetour::Hook_t hook;
        auto original = reinterpret_cast<int (*)()>(hook.HookFunction((void *)target, reinterpret_cast<void *>(&AbsoluteHookDetour)));
#if defined(MINIDETOUR_ARCH_ARM64)
        // An out-of-range trampoline would need an indirect branch that clobbers a live register.
        CHECK(original == nullptr);
        CHECK(target() == 1);
#else
        REQUIRE(original != nullptr);

        // No relative jump: the start of the function is an absolute jump to the detour.
        CHECK(GeneratedCode::RelativeJumpTarget(code.Data()) == 0);
        CHECK(target() == 100);
        CHECK(original() == 1);

        CHECK(hook.RestoreFunction() != nullptr);
        CHECK(target() == 1);
#endif
    }

    Release(function - static_cast<uintptr_t>(side), static_cast<size_t>(side));
    Release(function + static_cast<uintptr_t>(unit), static_cast<size_t>(side));
}

#endif
