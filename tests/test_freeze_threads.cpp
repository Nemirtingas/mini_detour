#include "catch.hpp"
#include "test_utils.h"

// The other threads are suspended while hooks are written on Windows and macOS (not on Linux).
#if (defined(MINIDETOUR_OS_WINDOWS) || defined(MINIDETOUR_OS_APPLE)) && (defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64))

#if defined(MINIDETOUR_OS_WINDOWS)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

using FreezeFunc_t = int (*)();

static int FreezeThreadsDetour()
{
    return 100;
}

// Writes at offset a loop a thread can spin in: "jmp $" when spinInside is false, or "nop ; nop ; nop ; jmp -4"
// (the thread never leaves offsets 1 to 3) when it is true. The loop ends when StopSpinning is called: the jump then
// goes to the thread return written after it.
class SpinningThread
{
    CodeBuffer &_Code;
    size_t _JumpOffset;
    bool _Running;
#if defined(MINIDETOUR_OS_WINDOWS)
    HANDLE _Thread;
#else
    pthread_t _Thread;
#endif

  public:
    SpinningThread(CodeBuffer &code, size_t offset, bool spinInside)
        : _Code(code)
        , _Running(false)
    {
        if (spinInside)
        {
            code.Write(offset, {0x90, 0x90, 0x90, 0xEB, 0xFC});
            _JumpOffset = offset + 3;
        }
        else
        {
            code.Write(offset, {0xEB, 0xFE});
            _JumpOffset = offset;
        }

#if defined(MINIDETOUR_ARCH_X86)
        code.Write(_JumpOffset + 2, {0xC2, 0x04, 0x00}); // ret 4 (stdcall thread routine)
#else
        code.Write(_JumpOffset + 2, {0xC3}); // ret
#endif

#if defined(MINIDETOUR_OS_WINDOWS)
        _Thread  = CreateThread(nullptr, 0, code.As<LPTHREAD_START_ROUTINE>(offset), nullptr, 0, nullptr);
        _Running = _Thread != nullptr;
        // Leaves time for the thread to reach its loop.
        Sleep(100);
#else
        _Running = pthread_create(&_Thread, nullptr, code.As<void *(*)(void *)>(offset), nullptr) == 0;
        usleep(100 * 1000);
#endif
    }

    ~SpinningThread() { StopSpinning(); }

    bool IsValid() const { return _Running; }

    void StopSpinning()
    {
        if (!_Running)
            return;

        // A single byte write: the jump displacement now goes to the ret.
        // The thread still runs the buffer, so it stays executable while written (CodeBuffer::Write makes it read/write).
        uint8_t *displacement = _Code.Data(_JumpOffset + 1);
        MiniDetour::MemoryManipulation::MemoryProtect(displacement, 1, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);
        *displacement = 0x00;
        MiniDetour::MemoryManipulation::FlushInstructionCache(displacement, 1);
#if defined(MINIDETOUR_OS_WINDOWS)
        WaitForSingleObject(_Thread, INFINITE);
        CloseHandle(_Thread);
#else
        pthread_join(_Thread, nullptr);
#endif
        _Running = false;
    }
};

// Hooks were written while other threads could run the bytes being replaced: a thread in the middle of them then
// executed a part of the new jump.
TEST_CASE("A function can't be hooked while a thread runs its first bytes", "[freeze_threads]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());

    SpinningThread thread(code, 0, true);
    REQUIRE(thread.IsValid());

    const uint8_t original[] = {0x90, 0x90, 0x90, 0xEB, 0xFC};

    MiniDetour::Hook_t hook;
    CHECK(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&FreezeThreadsDetour)) == nullptr);
    CHECK(memcmp(code.Data(), original, sizeof(original)) == 0);

    CHECK_FALSE(MiniDetour::Hook_t::ReplaceFunction(code.Data(), reinterpret_cast<void *>(&FreezeThreadsDetour)));
    CHECK(memcmp(code.Data(), original, sizeof(original)) == 0);

    thread.StopSpinning();

    // Nothing runs the function anymore.
    CHECK(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&FreezeThreadsDetour)) != nullptr);
    CHECK(hook.RestoreFunction() != nullptr);
}

TEST_CASE("A function can be hooked while a thread runs other code", "[freeze_threads]")
{
    CodeBuffer code;
    REQUIRE(code.IsValid());
    code.Write(0, {0xB8, 1, 0, 0, 0, 0xC3}); // mov eax, 1 ; ret

    SpinningThread thread(code, 64, false);
    REQUIRE(thread.IsValid());

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&FreezeThreadsDetour)) != nullptr);
    CHECK(code.As<FreezeFunc_t>()() == 100);
    CHECK(hook.GetOriginalFunction<FreezeFunc_t>()() == 1);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(code.As<FreezeFunc_t>()() == 1);
}

#endif
