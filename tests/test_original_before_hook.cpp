#include "catch.hpp"

#include "test_utils.h"

#include <atomic>
#include <thread>

namespace
{
using ReturnFunc_t = int(TEST_CALL *)();

// The detour calls the original function through this pointer, like the detours of a real hook.
void *OriginalFunction = nullptr;
std::atomic<int> DetourCalls{0};
std::atomic<int> Recursions{0};
thread_local int DetourDepth = 0;

int TEST_CALL OriginalBeforeHookDetour()
{
    DetourCalls.fetch_add(1, std::memory_order_relaxed);
    // Called from itself: the pointer still held the hooked function. It would call itself until the stack overflows.
    if (DetourDepth > 0)
    {
        Recursions.fetch_add(1, std::memory_order_relaxed);
        return -1;
    }

    ++DetourDepth;
    auto original = reinterpret_cast<ReturnFunc_t>(*static_cast<void *volatile *>(&OriginalFunction));
    int result    = original() + 1000;
    --DetourDepth;
    return result;
}
} // namespace

// The original function was only returned once the hook was written, and the threads running again: a thread entering
// the detour before the caller stored it called the hooked function, then the detour again, until the stack overflowed.
TEST_CASE("The original function is set before the hook is written", "[original_before_hook]")
{
    static constexpr int iterations = 200;

    CodeBuffer_t code;
    REQUIRE(code.IsValid());
    GeneratedCode::WriteReturnConstant(code, 0, 7);
    auto function = GeneratedCode::Function<ReturnFunc_t>(code);

    int failures = 0;
    for (int n = 0; n < iterations; ++n)
    {
        OriginalFunction = reinterpret_cast<void *>(function);
        DetourCalls      = 0;

        std::atomic<bool> stop{false};
        std::atomic<bool> started{false};
        std::thread caller(
            [&]()
            {
                while (!stop.load(std::memory_order_relaxed))
                {
                    function();
                    started.store(true, std::memory_order_relaxed);
                }
            });

        while (!started.load())
            std::this_thread::yield();

        MiniDetour::Hook_t hook;
        void *result = hook.HookFunction(&OriginalFunction, reinterpret_cast<void *>(&OriginalBeforeHookDetour));
        if (result == nullptr || result != OriginalFunction || OriginalFunction == reinterpret_cast<void *>(function))
            ++failures;

        // Lets the caller go through the detour before stopping it.
        while (result != nullptr && DetourCalls.load() < 100)
            std::this_thread::yield();

        stop = true;
        caller.join();

        if (result != nullptr && function() != 1007)
            ++failures;

        hook.RestoreFunction();
        if (function() != 7)
            ++failures;
    }

    CHECK(failures == 0);
    CHECK(Recursions.load() == 0);
}

TEST_CASE("The function pointer keeps its value when the hook fails", "[original_before_hook]")
{
    CodeBuffer_t code;
    REQUIRE(code.IsValid());
    GeneratedCode::WriteReturnConstant(code, 0, 1);
    GeneratedCode::WriteReturnConstant(code, 32, 2);
    auto first  = GeneratedCode::Function<ReturnFunc_t>(code);
    auto second = GeneratedCode::Function<ReturnFunc_t>(code, 32);

    MiniDetour::Hook_t hook;
    void *original = reinterpret_cast<void *>(first);
    REQUIRE(hook.HookFunction(&original, reinterpret_cast<void *>(&OriginalBeforeHookDetour)) != nullptr);
    CHECK(original != reinterpret_cast<void *>(first));
    CHECK(original == hook.GetOriginalFunction());

    // A hook object in use refuses to hook another function.
    void *unchanged = reinterpret_cast<void *>(second);
    CHECK(hook.HookFunction(&unchanged, reinterpret_cast<void *>(&OriginalBeforeHookDetour)) == nullptr);
    CHECK(unchanged == reinterpret_cast<void *>(second));
}
