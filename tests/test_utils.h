#ifndef MINI_DETOUR_TEST_UTILS_H
#define MINI_DETOUR_TEST_UTILS_H

#include <mini_detour/mini_detour.h>

#include <initializer_list>
#include <string.h>

// Executable memory used to build small hand-written functions in tests.
// The memory is never writable and executable at the same time: macOS on Apple Silicon refuses rwx pages. It is
// readable and executable, and only made writable while bytes are written.
class CodeBuffer
{
    uint8_t *_Data;
    size_t _Size;

    void _BeginWrite() { MiniDetour::MemoryManipulation::MemoryProtect(_Data, _Size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw); }

    void _EndWrite()
    {
        MiniDetour::MemoryManipulation::MemoryProtect(_Data, _Size, MiniDetour::MemoryManipulation::MemoryRights::mem_rx);
        MiniDetour::MemoryManipulation::FlushInstructionCache(_Data, _Size);
    }

  public:
    explicit CodeBuffer(size_t size = 4096, void *addressHint = nullptr)
        : _Data(static_cast<uint8_t *>(MiniDetour::MemoryManipulation::MemoryAlloc(addressHint, size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw)))
        , _Size(size)
    {
        if (_Data == nullptr)
            return;

        memset(_Data, 0xCC, _Size);
        if (!MiniDetour::MemoryManipulation::MemoryProtect(_Data, _Size, MiniDetour::MemoryManipulation::MemoryRights::mem_rx))
        {
            MiniDetour::MemoryManipulation::MemoryFree(_Data, _Size);
            _Data = nullptr;
        }
    }

    ~CodeBuffer()
    {
        if (_Data != nullptr)
            MiniDetour::MemoryManipulation::MemoryFree(_Data, _Size);
    }

    CodeBuffer(CodeBuffer const &)            = delete;
    CodeBuffer &operator=(CodeBuffer const &) = delete;

    bool IsValid() const { return _Data != nullptr; }

    uint8_t *Data(size_t offset = 0) { return _Data + offset; }

    template <typename T>
    T As(size_t offset = 0)
    {
        return reinterpret_cast<T>(_Data + offset);
    }

    // Writes bytes at offset, then makes the whole buffer readable and executable again.
    void Write(size_t offset, std::initializer_list<uint8_t> bytes)
    {
        _BeginWrite();
        size_t i = 0;
        for (auto b : bytes)
            _Data[offset + i++] = b;

        _EndWrite();
    }

    template <typename T>
    void WriteValue(size_t offset, T value)
    {
        _BeginWrite();
        memcpy(_Data + offset, &value, sizeof(value));
        _EndWrite();
    }
};

#if defined(MINIDETOUR_ARCH_X86)
// First integer argument in ecx on x86, so generated code doesn't depend on the stack layout.
#define TEST_CALL MINIDETOUR_CALL_FAST
#else
#define TEST_CALL
#endif

#endif // MINI_DETOUR_TEST_UTILS_H
