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

#if defined(MINIDETOUR_ARCH_ARM)
// Address to call Thumb code written by hand: with the Thumb bit set, the tests work in ARM and Thumb builds.
static inline void *ThumbAddress(void *address)
{
    return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(address) | 1);
}
#endif

// The tests that hook generated code run on every architecture, except ARM64 macOS: code in allocated memory can't be
// hooked there yet (the library needs pages that are writable and executable at the same time).
#if !(defined(MINIDETOUR_OS_APPLE) && defined(MINIDETOUR_ARCH_ARM64))
#define TEST_HOOKS_GENERATED_CODE

// Small functions written by hand for those tests, in the instruction set of the architecture.
namespace GeneratedCode
{
#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)
static const size_t NopSize = 1;
#elif defined(MINIDETOUR_ARCH_ARM)
static const size_t NopSize = 2;
#else
static const size_t NopSize = 4;
#endif

// Address to call the code written at data: Thumb code is called with the Thumb bit set.
static inline void *FunctionAddress(void *data)
{
#if defined(MINIDETOUR_ARCH_ARM)
    return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(data) | 1);
#else
    return data;
#endif
}

template <typename T = int (*)()>
static inline T Function(CodeBuffer &code, size_t offset = 0)
{
    return reinterpret_cast<T>(FunctionAddress(code.Data(offset)));
}

// Writes a function returning value, with nopCount no-op instructions before its return (room for the jumps written by
// some hooks). Returns its size.
//   x86/x64: mov eax, value ; nop... ; ret
//   Thumb:   movw r0, #value ; nop... ; bx lr (and a nop, so the function holds an absolute jump)
//   ARM64:   movz w0, #value ; nop... ; ret
static inline size_t WriteReturnConstant(CodeBuffer &code, size_t offset, uint16_t value, size_t nopCount = 0)
{
#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)
    code.Write(offset, {0xB8, static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8), 0, 0});
    size_t size = 5;
    for (size_t i = 0; i < nopCount; ++i)
        code.Write(offset + size++, {0x90});

    code.Write(offset + size++, {0xC3});
    return size;
#elif defined(MINIDETOUR_ARCH_ARM)
    // movw r0, #imm16: 11110 i 10 0100 imm4 | 0 imm3 0000 imm8, imm16 = imm4:i:imm3:imm8.
    code.WriteValue<uint16_t>(offset, static_cast<uint16_t>(0xF240 | ((value >> 1) & 0x0400) | (value >> 12)));
    code.WriteValue<uint16_t>(offset + 2, static_cast<uint16_t>(((value << 4) & 0x7000) | (value & 0xFF)));
    size_t size = 4;
    for (size_t i = 0; i < nopCount + 1; ++i, size += 2)
        code.WriteValue<uint16_t>(offset + size, 0xBF00); // nop

    code.WriteValue<uint16_t>(offset + size, 0x4770); // bx lr
    return size + 2;
#else
    code.WriteValue<uint32_t>(offset, 0x52800000 | (static_cast<uint32_t>(value) << 5)); // movz w0, #value
    size_t size = 4;
    for (size_t i = 0; i < nopCount; ++i, size += 4)
        code.WriteValue<uint32_t>(offset + size, 0xD503201F); // nop

    code.WriteValue<uint32_t>(offset + size, 0xD65F03C0); // ret
    return size + 4;
#endif
}

// Writes over a no-op instruction another instruction that does nothing either: a patch made by someone else.
static inline void WriteOtherNop(CodeBuffer &code, size_t offset)
{
#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)
    code.Write(offset, {0xF8}); // clc
#elif defined(MINIDETOUR_ARCH_ARM)
    code.WriteValue<uint16_t>(offset, 0x46C0); // mov r8, r8
#else
    code.WriteValue<uint32_t>(offset, 0xAA0903E9); // mov x9, x9
#endif
}

// Writes a relative jump to destination at offset: jmp rel32 (x86/x64), B.W (Thumb), B (ARM64).
static inline void WriteRelativeJump(CodeBuffer &code, size_t offset, void *destination)
{
    const intptr_t source = reinterpret_cast<intptr_t>(code.Data(offset));
    const intptr_t target = reinterpret_cast<intptr_t>(destination) & ~static_cast<intptr_t>(1);
#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)
    code.Write(offset, {0xE9});
    code.WriteValue<int32_t>(offset + 1, static_cast<int32_t>(target - (source + 5)));
#elif defined(MINIDETOUR_ARCH_ARM)
    // B.W: 11110 S imm10 | 10 J1 1 J2 imm11, J1 = !I1 ^ S, J2 = !I2 ^ S, offset = S:I1:I2:imm10:imm11:0 from pc + 4.
    const uint32_t relative = static_cast<uint32_t>(target - (source + 4));
    const uint32_t s        = (relative >> 24) & 1;
    const uint32_t j1       = (((relative >> 23) & 1) ^ 1) ^ s;
    const uint32_t j2       = (((relative >> 22) & 1) ^ 1) ^ s;
    code.WriteValue<uint16_t>(offset, static_cast<uint16_t>(0xF000 | (s << 10) | ((relative >> 12) & 0x3FF)));
    code.WriteValue<uint16_t>(offset + 2, static_cast<uint16_t>(0x9000 | (j1 << 13) | (j2 << 11) | ((relative >> 1) & 0x7FF)));
#else
    code.WriteValue<uint32_t>(offset, 0x14000000 | ((static_cast<uint32_t>(target - source) >> 2) & 0x03FFFFFF));
#endif
}

// Destination of the relative jump at address (as written by WriteRelativeJump), 0 if there is none.
static inline uintptr_t RelativeJumpTarget(const void *address)
{
    const uintptr_t source = reinterpret_cast<uintptr_t>(address);
#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)
    const uint8_t *opcode = static_cast<const uint8_t *>(address);
    if (opcode[0] != 0xE9)
        return 0;

    int32_t relative;
    memcpy(&relative, opcode + 1, sizeof(relative));
    return source + 5 + relative;
#elif defined(MINIDETOUR_ARCH_ARM)
    const uint16_t *opcode = static_cast<const uint16_t *>(address);
    if ((opcode[0] & 0xF800) != 0xF000 || (opcode[1] & 0xD000) != 0x9000)
        return 0;

    const uint32_t s     = (opcode[0] >> 10) & 1;
    const uint32_t i1    = ((opcode[1] >> 13) & 1) ^ s ^ 1;
    const uint32_t i2    = ((opcode[1] >> 11) & 1) ^ s ^ 1;
    const uint32_t imm   = (s << 24) | (i1 << 23) | (i2 << 22) | ((opcode[0] & 0x3FFu) << 12) | ((opcode[1] & 0x7FFu) << 1);
    const int32_t offset = static_cast<int32_t>(imm << 7) >> 7; // 25 bits sign extension
    return source + 4 + offset;
#else
    uint32_t opcode;
    memcpy(&opcode, address, sizeof(opcode));
    if ((opcode & 0xFC000000) != 0x14000000)
        return 0;

    const int64_t offset = static_cast<int64_t>(static_cast<int32_t>(opcode << 6) >> 6) * 4; // 26 bits sign extension
    return source + offset;
#endif
}
} // namespace GeneratedCode
#endif

#if defined(MINIDETOUR_ARCH_X86)
// First integer argument in ecx on x86, so generated code doesn't depend on the stack layout.
#define TEST_CALL MINIDETOUR_CALL_FAST
#else
#define TEST_CALL
#endif

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)
// Register holding the first integer argument: ecx (Windows x64 / x86 fastcall) or edi (System V x64).
#if defined(MINIDETOUR_ARCH_X64) && !defined(MINIDETOUR_OS_WINDOWS)
#define TEST_ARG0_TEST_SELF 0xFF // test edi, edi
#else
#define TEST_ARG0_TEST_SELF 0xC9 // test ecx, ecx
#endif
#endif

#endif // MINI_DETOUR_TEST_UTILS_H
