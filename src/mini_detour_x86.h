#ifndef MINI_DETOUR_X86_H
#define MINI_DETOUR_X86_H

inline void *relative_addr_to_absolute(void *source_addr, int32_t rel_addr)
{
    return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(source_addr) + rel_addr + 5);
}

inline intptr_t absolute_addr_to_relative(void *opcode_addr, void *destination_addr)
{
    return reinterpret_cast<uint8_t *>(destination_addr) - reinterpret_cast<uint8_t *>(opcode_addr) - 5;
}

static bool _AddressesAreRelativeJumpable(void *source, void *dest)
{
    uintptr_t min_addr = reinterpret_cast<uintptr_t>(std::min(source, dest));
    uintptr_t max_addr = reinterpret_cast<uintptr_t>(std::max(source, dest));
    return (max_addr - min_addr) <= 0x7FFFFFF0;
}

#pragma pack(push, 1)

// Struct used by the memory manager to allocate trampolines
struct memory_t
{
    uint8_t used;
    uint8_t data[32]; // Max absolute jump size is 6 bytes
};

struct AbsJump
{
    static inline size_t WriteOpcodes(void *buffer, void *jump_destination, int /*source_mode*/, int /*dest_mode*/)
    {
        uint8_t _code[6]{
            0x68, // PUSH
            0x00,
            0x00,
            0x00,
            0x00, // ABS ADDR
            0xC3, // RET
        };

        *reinterpret_cast<void **>(&_code[1]) = jump_destination;
        memcpy(buffer, _code, GetMaxOpcodeSize());
        return GetMaxOpcodeSize();
    }

    static constexpr size_t GetOpcodeSize(void */*jump_destination*/, int /*source_mode*/, int /*dest_mode*/)
    {
        // PUSH
        // ABS ADDR
        // RET
        return 6;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        // PUSH
        // ABS ADDR
        // RET
        return 6;
    }
};

struct RelJump
{
    static inline size_t WriteOpcodes(void *buffer, void *source, void *jump_destination, int /*source_mode*/, int /*dest_mode*/)
    {
        uint8_t code[5] = {
            0xE9, // JMP
            0x00,
            0x00,
            0x00,
            0x00, // REL ADDR
        };

        *reinterpret_cast<int32_t *>(&code[1]) = absolute_addr_to_relative(source, jump_destination);
        memcpy(buffer, code, GetMaxOpcodeSize());

        return GetMaxOpcodeSize();
    }

    static constexpr size_t GetOpcodeSize(void */*source*/, void */*jump_destination*/, int /*source_mode*/, int /*dest_mode*/)
    {
        // E9          | JMP
        // XX XX XX XX | REL ADDR
        return 5;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        // E9          | JMP
        // XX XX XX XX | REL ADDR
        return 5;
    }
};

struct CpuPush
{
    static size_t WriteOpcodes(void *source, uint32_t value)
    {
        uint8_t code[5] = {
            0x68, // PUSH
            0x00,
            0x00,
            0x00,
            0x00, // IMM32
        };

        *reinterpret_cast<uint32_t *>(&code[1]) = value;
        memcpy(source, code, 5);

        return 5;
    }

    static constexpr size_t GetOpcodeSize(uint32_t /*value*/)
    {
        // 68          | PUSH
        // XX XX XX XX | IMM32
        return 5;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        // 68          | PUSH
        // XX XX XX XX | IMM32
        return 5;
    }
};

#pragma pack(pop)

// Returns true if the instruction is a conditional jump (Jcc rel8 / Jcc rel32) and gives its condition code.
// jrcxz/jecxz and loop also are relative jumps but have no rel32 form, they are not handled.
static bool _GetJccConditionCode(cs_insn const &instruction, uint8_t &conditionCode)
{
    uint8_t const *opcode = instruction.detail->x86.opcode;
    if (opcode[0] >= 0x70 && opcode[0] <= 0x7F)
    {
        conditionCode = opcode[0] & 0x0F;
        return true;
    }

    if (opcode[0] == 0x0F && opcode[1] >= 0x80 && opcode[1] <= 0x8F)
    {
        conditionCode = opcode[1] & 0x0F;
        return true;
    }

    return false;
}

// The code mode is carried by the address on ARM (Thumb bit): x86 has a single mode.
static inline int _GetCodeMode(void */*address*/)
{
    return 0;
}

// Address of the code bytes, without the mode.
static inline void *_GetCodeAddress(void *address)
{
    return address;
}

// Address to call code written in the given mode.
static inline void *_GetCallAddress(void *code, int /*mode*/)
{
    return code;
}

static inline cs_err _InitDisasm(CodeDisasm &disasm, int /*mode*/)
{
    return disasm.Init(cs_arch::CS_ARCH_X86, (cs_mode)(cs_mode::CS_MODE_32 | CodeDisasm::RuntimeEndianness()));
}

static void _EnterRecursiveThunk(void *&_pCode)
{
    uint8_t *pCode = reinterpret_cast<uint8_t *>(_pCode);
    while (1)
    {
        // If its an imported function.      CALL                JUMP
        if (pCode[0] == 0xFF && (/*pCode[1] == 0x15 ||*/ pCode[1] == 0x25))
        {
            // Get the real imported function address
            pCode = **reinterpret_cast<uint8_t ***>(pCode + 2); // 2 opcodes + 4 absolute address ptr
        }
        else if (pCode[0] == 0xe9) // jmp rel32, a call (0xe8) is real code and must not be followed
        {
            pCode = (uint8_t *)relative_addr_to_absolute(pCode, *(int32_t *)(pCode + 1));
        }
        else
        {
            break;
        }
    }

    _pCode = pCode;
}

static size_t _GetRelocatableSize(void *pCode, size_t &relocatedOriginalCodeSize, bool ignore_relocation, CodeDisasm &disasm, size_t wanted_relocatable_size)
{
    uint8_t code_buffer[80];
    const uint8_t *code_iterator = code_buffer;
    size_t code_size             = 0;
    uint64_t code_addr           = reinterpret_cast<uint64_t>(pCode);

    code_size = _ReadCode(pCode, code_buffer, sizeof(code_buffer));

    relocatedOriginalCodeSize = 0;

    size_t relocatable_size = 0;
    while (relocatable_size < wanted_relocatable_size)
    {
        if (!disasm.Disasm(&code_iterator, &code_size, &code_addr))
            break;

        if (disasm.IsInstructionTerminating())
        {
            if (ignore_relocation) // Last instruction, overwrite it if we're ignoring relocations
            {
                relocatable_size += disasm.GetInstruction().size;
            }
            else if (disasm.GetJumpType() == 3)
            {
                uint8_t conditionCode;
                if (disasm.GetInstruction().id == X86_INS_JMP)
                {
                    relocatedOriginalCodeSize += disasm.GetInstruction().size;
                    relocatable_size += disasm.GetInstruction().size;
                }
                else if (_GetJccConditionCode(disasm.GetInstruction(), conditionCode))
                {
                    // Jcc rel8 over the not taken jump + not taken jump + taken jump
                    relocatedOriginalCodeSize += 2 + 2 * AbsJump::GetMaxOpcodeSize();
                    relocatable_size += disasm.GetInstruction().size;
                }
            }
            else if (disasm.GetJumpType() == 5)
            {
                relocatedOriginalCodeSize += disasm.GetInstruction().size;
                relocatable_size += disasm.GetInstruction().size;
            }

#ifdef USE_SPDLOG
            SPDLOG_INFO("Can't relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
            break;
        }

        // On x86, modrm mod=00 rm=101 is an absolute [disp32] address: there is no instruction pointer
        // relative addressing, so the instruction can be copied as is.

#ifdef USE_SPDLOG
        SPDLOG_INFO("Can relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
        relocatable_size += disasm.GetInstruction().size;
    }

    return relocatable_size;
}

static size_t _RelocateCode(void *pCode, void *pTrampoline, CodeDisasm &disasm, size_t wanted_relocatable_size, int /*func_mode*/)
{
    uint8_t code_buffer[80];
    const uint8_t *code_iterator = code_buffer;
    size_t code_size             = 0;
    uint64_t code_addr           = reinterpret_cast<uint64_t>(pCode);
    uint8_t *pTrampolineCode     = reinterpret_cast<uint8_t *>(pTrampoline);

    code_size = _ReadCode(pCode, code_buffer, sizeof(code_buffer));

    size_t relocatedSize     = 0;
    void *originalCodeTarget = nullptr;
    while (relocatedSize < wanted_relocatable_size)
    {
        if (!disasm.Disasm(&code_iterator, &code_size, &code_addr))
            break;

        if (disasm.IsInstructionTerminating())
        {
            uint8_t conditionCode;
            if (disasm.GetJumpType() == 3 && disasm.GetInstruction().id == X86_INS_JMP)
            {
                relocatedSize += disasm.GetInstruction().size;
                originalCodeTarget = reinterpret_cast<void *>(disasm.GetInstruction().detail->x86.operands[0].imm);
                break;
            }
            else if (disasm.GetJumpType() == 3 && _GetJccConditionCode(disasm.GetInstruction(), conditionCode))
            {
                // Jcc taken          ; short jump over the not taken path
                // JMP not_taken      ; absolute jump to the instruction after the Jcc
                // taken: JMP target  ; absolute jump to the Jcc target (written below)
                relocatedSize += disasm.GetInstruction().size;
                *pTrampolineCode++ = 0x70 | conditionCode;
                *pTrampolineCode++ = static_cast<uint8_t>(AbsJump::GetMaxOpcodeSize());
                pTrampolineCode += AbsJump::WriteOpcodes(reinterpret_cast<void *>(pTrampolineCode), reinterpret_cast<void *>(code_addr), 0, 0);
                originalCodeTarget = reinterpret_cast<void *>(disasm.GetInstruction().detail->x86.operands[0].imm);
                break;
            }
            else if (disasm.GetJumpType() == 5)
            {
                relocatedSize += disasm.GetInstruction().size;
                pTrampolineCode += CpuPush::WriteOpcodes(
                    reinterpret_cast<void *>(pTrampolineCode),
                    static_cast<uint32_t>(code_addr) // Where to return
                );
                originalCodeTarget = reinterpret_cast<void *>(disasm.GetInstruction().detail->x86.operands[0].imm);
                break;
            }

#ifdef USE_SPDLOG
            SPDLOG_INFO("Can't relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
            break;
        }

#ifdef USE_SPDLOG
        SPDLOG_INFO("Can relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
        memcpy(pTrampolineCode, (void *)disasm.GetInstruction().address, disasm.GetInstruction().size);
        relocatedSize += disasm.GetInstruction().size;
        pTrampolineCode += disasm.GetInstruction().size;
    }

    if (originalCodeTarget == nullptr)
        originalCodeTarget = reinterpret_cast<void *>(code_addr);

    AbsJump::WriteOpcodes(reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(pTrampolineCode)), originalCodeTarget, 0, 0);

    return relocatedSize;
}

#endif // MINI_DETOUR_X86_H
