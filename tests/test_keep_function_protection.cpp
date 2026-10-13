#include "catch.hpp"
#include "test_utils.h"

static int KeepProtectionDetour()
{
    return 100;
}

static MiniDetour::MemoryManipulation::MemoryRights CurrentRights(void *address)
{
    MiniDetour::MemoryManipulation::RegionInfos_t infos;
    MiniDetour::MemoryManipulation::GetRegionInfos(address, &infos);
    return infos.Rights;
}

// Apple Silicon never has writable and executable memory (W^X): there is no writable code to keep writable there.
#if !(defined(MINIDETOUR_OS_APPLE) && defined(MINIDETOUR_ARCH_ARM64))
// The hooked code was always left mem_rx: a JIT buffer (rwx) lost its write access when it was hooked or restored.
TEST_CASE("Hooking keeps the rights of writable code", "[keep_function_protection]")
{
    CodeBuffer_t code;
    REQUIRE(code.IsValid());
    GeneratedCode::WriteReturnConstant(code, 0, 1);
    auto function = GeneratedCode::Function(code);
    // A CodeBuffer_t is only readable and executable: make it writable code, like a JIT buffer.
    REQUIRE(MiniDetour::MemoryManipulation::MemoryProtect(code.Data(), 4096, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx));
    REQUIRE(CurrentRights(code.Data()) == MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)function, reinterpret_cast<void *>(&KeepProtectionDetour)) != nullptr);
    CHECK(function() == 100);
    CHECK(CurrentRights(code.Data()) == MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(function() == 1);
    CHECK(CurrentRights(code.Data()) == MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);
}

TEST_CASE("Replacing keeps the rights of writable code", "[keep_function_protection]")
{
    CodeBuffer_t code;
    REQUIRE(code.IsValid());
    // Room for an absolute jump.
    GeneratedCode::WriteReturnConstant(code, 0, 1, 32 / GeneratedCode::NopSize);
    auto function = GeneratedCode::Function(code);
    REQUIRE(MiniDetour::MemoryManipulation::MemoryProtect(code.Data(), 4096, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx));

    REQUIRE(MiniDetour::Hook_t::ReplaceFunction((void *)function, reinterpret_cast<void *>(&KeepProtectionDetour)));
    CHECK(function() == 100);
    CHECK(CurrentRights(code.Data()) == MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);
}

#endif

TEST_CASE("Hooking keeps read-only code read-only", "[keep_function_protection]")
{
    CodeBuffer_t code;
    REQUIRE(code.IsValid());
    GeneratedCode::WriteReturnConstant(code, 0, 1);
    REQUIRE(MiniDetour::MemoryManipulation::MemoryProtect(code.Data(), 4096, MiniDetour::MemoryManipulation::MemoryRights::mem_rx));

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction((void *)GeneratedCode::Function(code), reinterpret_cast<void *>(&KeepProtectionDetour)) != nullptr);
    CHECK(CurrentRights(code.Data()) == MiniDetour::MemoryManipulation::MemoryRights::mem_rx);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(CurrentRights(code.Data()) == MiniDetour::MemoryManipulation::MemoryRights::mem_rx);
}
