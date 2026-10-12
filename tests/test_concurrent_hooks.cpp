#include "catch.hpp"

#include "test_utils.h"

#include <atomic>
#include <thread>
#include <vector>

#if defined(TEST_HOOKS_GENERATED_CODE)

static int TEST_CALL ConcurrentDetour()
{
    return 1000;
}

// Hooks set from several threads shared the jump/trampoline slots and the pages holding them
// without any lock: two threads could get the same slot, or make a page read-only while the other wrote to it.
TEST_CASE("Hooks set from several threads", "[concurrent_hooks]")
{
    static constexpr int threadCount = 8;
    static constexpr int iterations  = 300;

    // All the functions share one page.
    CodeBuffer code;
    REQUIRE(code.IsValid());
    for (int i = 0; i < threadCount; ++i)
        GeneratedCode::WriteReturnConstant(code, i * 64, static_cast<uint16_t>(i));

    std::atomic<int> failures{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < threadCount; ++i)
    {
        threads.emplace_back(
            [&code, &failures, i]()
            {
                auto function = GeneratedCode::Function<int(TEST_CALL *)()>(code, i * 64);
                for (int n = 0; n < iterations; ++n)
                {
                    MiniDetour::Hook_t hook;
                    auto original = reinterpret_cast<int(TEST_CALL *)()>(hook.HookFunction((void *)function, (void *)&ConcurrentDetour));
                    if (original == nullptr || original() != i || function() != 1000)
                        ++failures;

                    if (hook.RestoreFunction() == nullptr || function() != i)
                        ++failures;
                }
            });
    }

    for (auto &thread : threads)
        thread.join();

    CHECK(failures == 0);
}

#endif
