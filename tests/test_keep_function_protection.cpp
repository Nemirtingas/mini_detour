#include "catch.hpp"
#include "test_utils.h"

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

using ProtectionFunc_t = int (*)();

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

// The hooked code was always left mem_rx: a JIT buffer (rwx) lost its write access when it was hooked or restored.
TEST_CASE("Hooking keeps the rights of writable code", "[keep_function_protection]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    code.Write(0, {0xB8, 1, 0, 0, 0, 0xC3}); // mov eax, 1 ; ret
    // A CodeBuffer is only readable and executable: make it writable code, like a JIT buffer.
    REQUIRE(MiniDetour::MemoryManipulation::MemoryProtect(code.Data(), 4096, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx));
    REQUIRE(CurrentRights(code.Data()) == MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&KeepProtectionDetour)) != nullptr);
    CHECK(code.As<ProtectionFunc_t>()() == 100);
    CHECK(CurrentRights(code.Data()) == MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(code.As<ProtectionFunc_t>()() == 1);
    CHECK(CurrentRights(code.Data()) == MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);
}

TEST_CASE("Replacing keeps the rights of writable code", "[keep_function_protection]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    // mov eax, 1 ; nop * 16 ; ret: room for an absolute jump.
    code.Write(0, {0xB8, 1, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3});
    REQUIRE(MiniDetour::MemoryManipulation::MemoryProtect(code.Data(), 4096, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx));

    REQUIRE(MiniDetour::Hook_t::ReplaceFunction(code.Data(), reinterpret_cast<void *>(&KeepProtectionDetour)));
    CHECK(code.As<ProtectionFunc_t>()() == 100);
    CHECK(CurrentRights(code.Data()) == MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);
}

TEST_CASE("Hooking keeps read-only code read-only", "[keep_function_protection]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    code.Write(0, {0xB8, 1, 0, 0, 0, 0xC3}); // mov eax, 1 ; ret
    REQUIRE(MiniDetour::MemoryManipulation::MemoryProtect(code.Data(), 4096, MiniDetour::MemoryManipulation::MemoryRights::mem_rx));

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&KeepProtectionDetour)) != nullptr);
    CHECK(CurrentRights(code.Data()) == MiniDetour::MemoryManipulation::MemoryRights::mem_rx);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(CurrentRights(code.Data()) == MiniDetour::MemoryManipulation::MemoryRights::mem_rx);
}

#endif
