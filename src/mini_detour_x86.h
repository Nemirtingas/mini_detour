#ifndef MINI_DETOUR_X86_H
#define MINI_DETOUR_X86_H

inline void* relative_addr_to_absolute(void* source_addr, int32_t rel_addr)
{
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(source_addr) + rel_addr + 5);
}

inline intptr_t absolute_addr_to_relative(void* opcode_addr, void* destination_addr)
{
    return reinterpret_cast<uint8_t*>(destination_addr) - reinterpret_cast<uint8_t*>(opcode_addr) - 5;
}

bool addresses_are_relative_jumpable(void* source, void* dest)
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
    static inline size_t WriteOpcodes(void* buffer, void* source, void* jump_destination, int source_mode, int dest_mode)
    {
        uint8_t _code[6]{
          0x68,                   // PUSH
          0x00, 0x00, 0x00, 0x00, // ABS ADDR
          0xC3,                   // RET
        };

        *reinterpret_cast<void**>(&_code[1]) = jump_destination;
        memcpy(buffer, _code, GetMaxOpcodeSize());
        return GetMaxOpcodeSize();
    }

    static constexpr size_t GetOpcodeSize(void* jump_destination, int source_mode, int dest_mode)
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
    static inline size_t WriteOpcodes(void* buffer, void* source, void* jump_destination, int source_mode, int dest_mode)
    {
        uint8_t code[5] =
        {
            0xE9,                   // JMP
            0x00, 0x00, 0x00, 0x00, // REL ADDR
        };
        
        *reinterpret_cast<int32_t*>(&code[1]) = absolute_addr_to_relative(source, jump_destination);
        memcpy(buffer, code, GetMaxOpcodeSize());

        return GetMaxOpcodeSize();
    }

    static constexpr size_t GetOpcodeSize(void* source, void* jump_destination, int source_mode, int dest_mode)
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
    static size_t WriteOpcodes(void* source, uint32_t value)
    {
        uint8_t code[5] =
        {
            0x68,                   // PUSH
            0x00, 0x00, 0x00, 0x00, // IMM32
        };

        *reinterpret_cast<uint32_t*>(&code[1]) = value;
        memcpy(source, code, 5);

        return 5;
    }

    static constexpr size_t GetOpcodeSize(uint32_t value)
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

void _EnterRecursiveThunk(void*& _pCode)
{
    uint8_t* pCode = reinterpret_cast<uint8_t*>(_pCode);
    while (1)
    {
        // If its an imported function.      CALL                JUMP
        if (pCode[0] == 0xFF && (/*pCode[1] == 0x15 ||*/ pCode[1] == 0x25))
        {
            // Get the real imported function address
            pCode = **reinterpret_cast<uint8_t***>(pCode + 2); // 2 opcodes + 4 absolute address ptr
        }
        else if (pCode[0] == 0xe8 || pCode[0] == 0xe9)
        {
            pCode = (uint8_t*)relative_addr_to_absolute(pCode, *(int32_t*)(pCode + 1));
        }
        else
        {
            break;
        }
    }

    _pCode = pCode;
}

size_t _GetRelocatableSize(void* pCode, void*& jump_destination, size_t& jump_destination_size, JumpType_e& jump_type, bool ignore_relocation, CodeDisasm& disasm, size_t wanted_relocatable_size)
{
    // MOD-REG-R/M Byte
    //  7 6    5 4 3    2 1 0 - bits
    //[ MOD ][  REG  ][  R/M  ]
    static constexpr auto mod_mask = 0xC0;
    static constexpr auto rm_mask = 0x07; // Register or memory mask
    static constexpr auto modrm_mask = mod_mask | rm_mask;

    uint8_t code_buffer[80];
    const uint8_t* code_iterator = code_buffer;
    size_t code_size = 80;
    uint64_t code_addr = reinterpret_cast<uint64_t>(pCode);

    memcpy(code_buffer, pCode, 80);

    jump_destination = nullptr;
    jump_destination_size = 0;

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
                jump_destination = reinterpret_cast<void*>(disasm.GetInstruction().detail->x86.operands[0].imm);
                jump_destination_size += disasm.GetInstruction().size;
                relocatable_size += jump_destination_size;
                jump_type = JumpType_e::Jump;
            }
            else if (disasm.GetJumpType() == 5)
            {
                jump_destination = reinterpret_cast<void*>(disasm.GetInstruction().detail->x86.operands[0].imm);
                jump_destination_size += disasm.GetInstruction().size;
                relocatable_size += jump_destination_size;
                jump_type = JumpType_e::Call;
            }

#ifdef USE_SPDLOG
            SPDLOG_INFO("Can't relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
            break;
        }

        if ((disasm.GetInstruction().detail->x86.modrm & modrm_mask) == 0x05)
        {// Relative addressing opcode
            if (!ignore_relocation)
            {
#ifdef USE_SPDLOG
                SPDLOG_INFO("Can't relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
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

#endif // MINI_DETOUR_X86_H
