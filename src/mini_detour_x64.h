#ifndef MINI_DETOUR_X64_H
#define MINI_DETOUR_X64_H

// 64bits abs jump
// 6 - 14 Bytes absolute jmp
// 68 XX XX XX XX          PUSH LOW 32 bits QWORD
// OPTIONAL
// C7 44 24 04 XX XX XX XX MOV DWORD PTR[rsp + 0x4], HIGH 32 bits QWORD
// C3                      RET

// 12 Bytes absolute jmp
// 48 B8 XX XX XX XX XX XX XX XX MOVABS RAX, absolute addr
// 50                            PUSH RAX
// C3                            RET

// 13 Bytes absolute jmp
// 49 BB XX XX XX XX XX XX XX XX MOVABS R11, absolute addr
// 41 53                         PUSH R11
// C3                            RET

// Safe 14 Bytes absolute x64 jmp
// FF 25 00 00 00 00       JMP [RIP+6]
// XX XX XX XX XX XX XX XX Address to jump to

inline void *relative_addr_to_absolute(void *source_addr, int32_t rel_addr)
{
    return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(source_addr) + rel_addr + 5);
}

inline intptr_t absolute_addr_to_relative(void *opcode_addr, void *destination_addr)
{
    return reinterpret_cast<uint8_t *>(destination_addr) - reinterpret_cast<uint8_t *>(opcode_addr) - 5;
}

bool _AddressesAreRelativeJumpable(void *source, void *dest)
{
    uintptr_t min_addr = reinterpret_cast<uintptr_t>(std::min(source, dest));
    uintptr_t max_addr = reinterpret_cast<uintptr_t>(std::max(source, dest));
    return (max_addr - min_addr) <= 0x7FFFFFF0;
}

bool _AddressIsRepresentableAsRva(void *moduleBase, void *address)
{
    uintptr_t base = reinterpret_cast<uintptr_t>(moduleBase);
    uintptr_t addr = reinterpret_cast<uintptr_t>(address);

    return addr >= base && (addr - base) <= UINT32_MAX;
}

#pragma pack(push, 1)

// Struct used by the memory manager to allocate trampolines
struct memory_t
{
    uint8_t used;
    uint8_t data[64]; // Max absolute jump size is 14 bytes
};

struct AbsJump
{
    static inline size_t WriteOpcodes(void *buffer, void *jump_destination, int source_mode, int dest_mode)
    {
        uint8_t _code[14]{
            0xFF,
            0x25, // JMP
            0x00,
            0x00,
            0x00,
            0x00, // RIP OFFSET (RIP + 0)
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00, // ABS_ADDR
        };

        *reinterpret_cast<void **>(&_code[6]) = jump_destination;
        memcpy(buffer, _code, GetMaxOpcodeSize());
        return GetMaxOpcodeSize();
    }

    static inline size_t GetOpcodeSize(void *jump_destination, int source_mode, int dest_mode)
    {
        // JMP
        // RIP OFFSET (RIP + 0)
        // ABS_ADDR
        return 14;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        // JMP
        // RIP OFFSET (RIP + 0)
        // ABS_ADDR
        return 14;
    }
};

struct RelJump
{
    static inline size_t WriteOpcodes(void *buffer, void *source, void *jump_destination, int source_mode, int dest_mode)
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

    static inline size_t GetOpcodeSize(void *source, void *jump_destination, int source_mode, int dest_mode)
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
    // push imm32 sign-extends its operand to 64 bits.
    static constexpr bool _FitsInSignExtendedImm32(uint64_t value)
    {
        return static_cast<int64_t>(static_cast<int32_t>(value)) == static_cast<int64_t>(value);
    }

    static size_t WriteOpcodes(void *source, uint64_t value)
    {
        uint8_t code[13] = {
            0x68, // PUSH
            0x00,
            0x00,
            0x00,
            0x00, // IMM32
            0xC7,
            0x44,
            0x24,
            0x04, // mov DWORD PTR [rsp + 4], HIGH IMM32
            0x00,
            0x00,
            0x00,
            0x00,
        };

        *reinterpret_cast<uint32_t *>(&code[1]) = static_cast<uint32_t>(value);

        if (!_FitsInSignExtendedImm32(value))
        {
            *reinterpret_cast<uint32_t *>(&code[9]) = static_cast<uint32_t>(value >> 32);
            memcpy(source, code, 13);
            return 13;
        }

        memcpy(source, code, 5);

        return 5;
    }

    static constexpr size_t GetOpcodeSize(uint64_t value)
    {
        // 68          | PUSH
        // LL LL LL LL | LOW IMM32
        // C7 44 24 04 | MOV DWORD PTR [rsp + 4], HIGH IMM32
        // HH HH HH HH
        return (_FitsInSignExtendedImm32(value) ? 5 : 13);
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        // 68          | PUSH
        // LL LL LL LL | LOW IMM32
        // C7 44 24 04 | mov DWORD PTR [rsp + 4], HIGH IMM32
        // HH HH HH HH
        return 13;
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

void _EnterRecursiveThunk(void *&_pCode)
{
    uint8_t *pCode = reinterpret_cast<uint8_t *>(_pCode);
    while (1)
    {
        // If its an imported function.      CALL                JUMP
        if (pCode[0] == 0xFF && (/*pCode[1] == 0x15 ||*/ pCode[1] == 0x25))
        {
            // Get the real imported function address
            pCode = *reinterpret_cast<uint8_t **>(pCode + 6 + *(int32_t *)(pCode + 2)); // 2 opcodes + 4 relative address ptr
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

// Gets the encoding number (0-15) of a 64 bits or 32 bits general purpose register.
static bool _GetRegisterNumber(x86_reg reg, uint8_t &number, bool &is64)
{
    static const x86_reg registers64[] = {
        X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX, X86_REG_RSP, X86_REG_RBP, X86_REG_RSI, X86_REG_RDI,
        X86_REG_R8,  X86_REG_R9,  X86_REG_R10, X86_REG_R11, X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
    };
    static const x86_reg registers32[] = {
        X86_REG_EAX, X86_REG_ECX, X86_REG_EDX,  X86_REG_EBX,  X86_REG_ESP,  X86_REG_EBP,  X86_REG_ESI,  X86_REG_EDI,
        X86_REG_R8D, X86_REG_R9D, X86_REG_R10D, X86_REG_R11D, X86_REG_R12D, X86_REG_R13D, X86_REG_R14D, X86_REG_R15D,
    };

    for (uint8_t i = 0; i < 16; ++i)
    {
        if (registers64[i] == reg || registers32[i] == reg)
        {
            number = i;
            is64   = registers64[i] == reg;
            return true;
        }
    }

    return false;
}

// Max size of the code written by _WriteRipRelativeLoad: movabs reg, imm64 (10) + mov reg, [reg] (up to 4)
static constexpr size_t _RipRelativeLoadMaxSize = 14;

// Matches "mov reg, [rip + disp]" and "lea reg, [rip + disp]", the only rip relative instructions we can relocate.
static bool _GetRipRelativeLoad(cs_insn const &instruction, uint8_t &reg, bool &is64, bool &dereference, uint64_t &address)
{
    auto const &x86 = instruction.detail->x86;

    if (instruction.id != X86_INS_MOV && instruction.id != X86_INS_LEA)
        return false;

    if (x86.op_count != 2 || x86.operands[0].type != X86_OP_REG || x86.operands[1].type != X86_OP_MEM || x86.operands[1].mem.base != X86_REG_RIP ||
        x86.operands[1].mem.index != X86_REG_INVALID)
        return false;

    if (!_GetRegisterNumber(x86.operands[0].reg, reg, is64))
        return false;

    // rsp would be used as a temporary register and a 32 bits lea doesn't zero the upper bits like movabs does.
    if (reg == 4 || (instruction.id == X86_INS_LEA && !is64))
        return false;

    dereference = instruction.id == X86_INS_MOV;
    address     = instruction.address + instruction.size + x86.operands[1].mem.disp;
    return true;
}

// Writes "movabs reg, address" and, for a mov, "mov reg, [reg]".
static size_t _WriteRipRelativeLoad(uint8_t *code, uint8_t reg, bool is64, bool dereference, uint64_t address)
{
    uint8_t *start   = code;
    uint8_t lowReg   = reg & 7;
    uint8_t extended = reg >= 8 ? 1 : 0;

    *code++ = 0x48 | extended; // REX.W + REX.B
    *code++ = 0xB8 + lowReg;   // movabs reg, imm64
    memcpy(code, &address, sizeof(address));
    code += sizeof(address);

    if (dereference)
    {
        uint8_t rex = (is64 ? 0x48 : 0x40) | (extended << 2) | extended; // REX.W + REX.R + REX.B
        if (rex != 0x40)
            *code++ = rex;

        *code++ = 0x8B; // mov reg, [reg]
        if (lowReg == 5)
        {// rbp/r13 base needs a displacement: [reg + 0]
            *code++ = 0x40 | (lowReg << 3) | lowReg;
            *code++ = 0x00;
        }
        else if (lowReg == 4)
        {// r12 base needs a SIB byte
            *code++ = (lowReg << 3) | lowReg;
            *code++ = 0x24;
        }
        else
        {
            *code++ = (lowReg << 3) | lowReg;
        }
    }

    return code - start;
}

size_t _GetRelocatableSize(void *pCode, size_t &relocatedOriginalCodeSize, bool ignore_relocation, CodeDisasm &disasm, size_t wanted_relocatable_size)
{
    // MOD-REG-R/M Byte
    //  7 6    5 4 3    2 1 0 - bits
    //[ MOD ][  REG  ][  R/M  ]
    static constexpr auto mod_mask   = 0xC0;
    static constexpr auto rm_mask    = 0x07; // Register or memory mask
    static constexpr auto modrm_mask = mod_mask | rm_mask;

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

        if ((disasm.GetInstruction().detail->x86.modrm & modrm_mask) == 0x05)
        { // Relative addressing opcode
            if (!ignore_relocation)
            {
                uint8_t reg;
                bool is64;
                bool dereference;
                uint64_t address;
                if (_GetRipRelativeLoad(disasm.GetInstruction(), reg, is64, dereference, address))
                {
                    relocatedOriginalCodeSize += _RipRelativeLoadMaxSize;
                    relocatable_size += disasm.GetInstruction().size;
                }
                else
                {
#ifdef USE_SPDLOG
                    SPDLOG_INFO("Can't relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
                }
                break;
            }
        }

#ifdef USE_SPDLOG
        SPDLOG_INFO("Can relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
        relocatable_size += disasm.GetInstruction().size;
    }

    return relocatable_size;
}

size_t _RelocateCode(void *pCode, void *pTrampoline, CodeDisasm &disasm, size_t wanted_relocatable_size)
{
    // MOD-REG-R/M Byte
    //  7 6    5 4 3    2 1 0 - bits
    //[ MOD ][  REG  ][  R/M  ]
    static constexpr auto mod_mask   = 0xC0;
    static constexpr auto rm_mask    = 0x07; // Register or memory mask
    static constexpr auto modrm_mask = mod_mask | rm_mask;

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
                    code_addr // Where to return
                );
                originalCodeTarget = reinterpret_cast<void *>(disasm.GetInstruction().detail->x86.operands[0].imm);
                break;
            }

#ifdef USE_SPDLOG
            SPDLOG_INFO("Can't relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
            break;
        }

        if ((disasm.GetInstruction().detail->x86.modrm & modrm_mask) == 0x05)
        { // Relative addressing opcode
            uint8_t reg;
            bool is64;
            bool dereference;
            uint64_t address;
            if (_GetRipRelativeLoad(disasm.GetInstruction(), reg, is64, dereference, address))
            {
                relocatedSize += disasm.GetInstruction().size;
                pTrampolineCode += _WriteRipRelativeLoad(pTrampolineCode, reg, is64, dereference, address);
                originalCodeTarget = reinterpret_cast<void *>(disasm.GetInstruction().address + disasm.GetInstruction().size);

                break;
            }

#ifdef USE_SPDLOG
            SPDLOG_INFO("Can't relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
            return 0;
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

#endif // MINI_DETOUR_X64_H
