#include "catch.hpp"
#include "test_utils.h"

#include <spdlog/spdlog.h>

static int RestoredAtExitDetour()
{
    return 100;
}

// The tests build logs with spdlog, including when the hook is restored at exit: create the spdlog registry
// (a function local static) before the hook so it is destroyed after it.
static bool g_LoggerCreated = spdlog::default_logger() != nullptr;
// Declared before the hook so it is destroyed after it.
static CodeBuffer_t g_RestoredAtExitCode;
static MiniDetour::Hook_t g_RestoredAtExitHook;

// Hooks still active at exit are restored by the destructor of their global Hook_t, which uses the
// library memory manager. That manager was a global too, possibly destroyed first (static destruction order).
// The failure (use after destruction) can't be observed reliably from a test: this test leaves a hook active
// so that the restore at exit is at least exercised (the process must exit cleanly).
TEST_CASE("Hook left active is restored at exit", "[restore_at_exit]")
{
    REQUIRE(g_RestoredAtExitCode.IsValid());
    GeneratedCode::WriteReturnConstant(g_RestoredAtExitCode, 0, 1);
    auto function = GeneratedCode::Function(g_RestoredAtExitCode);

    REQUIRE(g_RestoredAtExitHook.HookFunction((void *)function, reinterpret_cast<void *>(&RestoredAtExitDetour)) != nullptr);
    CHECK(function() == 100);
}
