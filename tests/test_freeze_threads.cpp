#include "catch.hpp"
#include "test_utils.h"

// The other threads are suspended while hooks are written on Windows and macOS (not on Linux).
#if (defined(MINIDETOUR_OS_WINDOWS) || defined(MINIDETOUR_OS_APPLE)) && (defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64) || defined(MINIDETOUR_ARCH_ARM64))

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

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)
// Writes at offset a loop a thread can spin in: "jmp $" when spinInside is false, or "nop ; nop ; nop ; jmp -4"
// (the thread never leaves offsets 1 to 3) when it is true. The loop ends when StopSpinning is called: the jump then
// goes to the thread return written after it.
class SpinningThread_t
{
    CodeBuffer_t &_Code;
    size_t _JumpOffset;
    bool _Running;
#if defined(MINIDETOUR_OS_WINDOWS)
    HANDLE _Thread;
#else
    pthread_t _Thread;
#endif

  public:
    SpinningThread_t(CodeBuffer_t &code, size_t offset, bool spinInside)
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

    ~SpinningThread_t() { StopSpinning(); }

    bool IsValid() const { return _Running; }

    void StopSpinning()
    {
        if (!_Running)
            return;

        // A single byte write: the jump displacement now goes to the ret.
        // The thread still runs the buffer, so it stays executable while written (CodeBuffer_t::Write makes it read/write).
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
    CodeBuffer_t code;
    REQUIRE(code.IsValid());

    SpinningThread_t thread(code, 0, true);
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
    CodeBuffer_t code;
    REQUIRE(code.IsValid());
    code.Write(0, {0xB8, 1, 0, 0, 0, 0xC3}); // mov eax, 1 ; ret

    SpinningThread_t thread(code, 64, false);
    REQUIRE(thread.IsValid());

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&FreezeThreadsDetour)) != nullptr);
    CHECK(code.As<FreezeFunc_t>()() == 100);
    CHECK(hook.GetOriginalFunction<FreezeFunc_t>()() == 1);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(code.As<FreezeFunc_t>()() == 1);
}
#endif

// Not on macOS ARM64: a function in allocated memory can't be hooked there yet, its trampoline memory can't be made
// executable.
#if defined(MINIDETOUR_ARCH_ARM64) && defined(MINIDETOUR_OS_WINDOWS)
// Runs "loop: ldr w1, [x0] ; cbz w1, loop ; ret" with x0 pointing to a flag, until StopSpinning sets the flag: the loop
// is stopped through data, not by rewriting its code while it runs.
class FlagSpinningThread_t
{
    CodeBuffer_t _Code;
    volatile uint32_t _Stop;
    bool _Running;
    HANDLE _Thread;

  public:
    FlagSpinningThread_t()
        : _Stop(0)
        , _Running(false)
        , _Thread(nullptr)
    {
        if (!_Code.IsValid())
            return;

        _Code.Write(0, {0x01, 0x00, 0x40, 0xB9, 0xE1, 0xFF, 0xFF, 0x34, 0xC0, 0x03, 0x5F, 0xD6});
        _Thread  = CreateThread(nullptr, 0, _Code.As<LPTHREAD_START_ROUTINE>(), const_cast<uint32_t *>(&_Stop), 0, nullptr);
        _Running = _Thread != nullptr;
        // Leaves time for the thread to reach its loop.
        Sleep(100);
    }

    FlagSpinningThread_t(FlagSpinningThread_t const &)            = delete;
    FlagSpinningThread_t &operator=(FlagSpinningThread_t const &) = delete;

    ~FlagSpinningThread_t() { StopSpinning(); }

    bool IsValid() const { return _Running; }

    void StopSpinning()
    {
        if (!_Running)
            return;

        _Stop = 1;
        WaitForSingleObject(_Thread, INFINITE);
        CloseHandle(_Thread);
        _Running = false;
    }
};

// A hook writes a single 4 bytes aligned instruction (b to its jump slot): a thread can't be in the middle of it, so
// there is no ARM64 version of the test above. The other threads are still suspended, and their pc checked.
TEST_CASE("A function can be hooked while a thread runs other code", "[freeze_threads]")
{
    CodeBuffer_t code;
    REQUIRE(code.IsValid());
    code.Write(0, {0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6}); // mov w0, #1 ; ret

    FlagSpinningThread_t thread;
    REQUIRE(thread.IsValid());

    MiniDetour::Hook_t hook;
    REQUIRE(hook.HookFunction(code.Data(), reinterpret_cast<void *>(&FreezeThreadsDetour)) != nullptr);
    CHECK(code.As<FreezeFunc_t>()() == 100);
    CHECK(hook.GetOriginalFunction<FreezeFunc_t>()() == 1);

    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(code.As<FreezeFunc_t>()() == 1);
}
#endif

#if defined(MINIDETOUR_OS_WINDOWS)
static HANDLE g_ResumeOrderWorkers[2];
static volatile LONG g_ResumeOrderStop;
static volatile LONG g_ResumeOrderSuspendedSeen;
static BOOL(WINAPI *g_ResumeOrderCloseHandle)(HANDLE);
static LONG(NTAPI *g_ResumeOrderNtClose)(HANDLE);

static DWORD WINAPI ResumeOrderWorker(LPVOID)
{
    while (g_ResumeOrderStop == 0)
        Sleep(1);

    return 0;
}

// Tells if a worker is still suspended by the hook being written while CloseHandle runs.
static BOOL WINAPI ResumeOrderCloseHandleDetour(HANDLE handle)
{
    for (auto worker : g_ResumeOrderWorkers)
    {
        const DWORD previousCount = SuspendThread(worker);
        if (previousCount == (DWORD)-1)
            continue;

        if (previousCount > 0)
            InterlockedExchange(&g_ResumeOrderSuspendedSeen, 1);

        ResumeThread(worker);
    }

    // The detour already runs when the hook writing it resumes the threads, before HookFunction returns the original.
    if (g_ResumeOrderCloseHandle == nullptr)
        return g_ResumeOrderNtClose(handle) >= 0;

    return g_ResumeOrderCloseHandle(handle);
}

// The threads were resumed one by one, each thread handle closed right after: a hooked CloseHandle then ran while the
// next threads were still suspended, and its detour could wait for a lock one of them held.
TEST_CASE("Every thread is resumed before anything else runs", "[freeze_threads]")
{
    reinterpret_cast<FARPROC &>(g_ResumeOrderNtClose) = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose");
    REQUIRE(g_ResumeOrderNtClose != nullptr);
    g_ResumeOrderCloseHandle = nullptr;
    g_ResumeOrderStop        = 0;
    for (auto &worker : g_ResumeOrderWorkers)
    {
        worker = CreateThread(nullptr, 0, &ResumeOrderWorker, nullptr, 0, nullptr);
        REQUIRE(worker != nullptr);
    }

    // The hook is in place when the threads are resumed: its own write already goes through the detour.
    MiniDetour::Hook_t hook;
    g_ResumeOrderSuspendedSeen                          = 0;
    reinterpret_cast<void *&>(g_ResumeOrderCloseHandle) = hook.HookFunction(reinterpret_cast<void *>(&CloseHandle), reinterpret_cast<void *>(&ResumeOrderCloseHandleDetour));
    REQUIRE(g_ResumeOrderCloseHandle != nullptr);
    CHECK(hook.RestoreFunction() != nullptr);
    CHECK(g_ResumeOrderSuspendedSeen == 0);

    g_ResumeOrderStop = 1;
    for (auto worker : g_ResumeOrderWorkers)
    {
        WaitForSingleObject(worker, INFINITE);
        CloseHandle(worker);
    }
}
#endif

#endif
