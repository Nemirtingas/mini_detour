#ifndef MINI_DETOUR_ARM64_H
#define MINI_DETOUR_ARM64_H

// AArch64 // Need to align code on 4 bytes address (opcode are 4bytes fixed length)

// Registers 	Description
// X0 – X7     argumentsand return value
// X8 – X18    temporary registers
// X19 – X28   callee - saved registers
// X29         frame pointer
// X30         link register
// SP          stack pointer

// ldr x8, #8 // 48 00 00 58 : Load value at PointerCode + 8 into x8
// br  x8     // 00 01 1F D6 : Branch to value in x8
// XX XX XX XX XX XX XX XX // Value at PointerCode + 8

// movz // Load 16 bits imm into register with zero padding

// movk // Load 16 bits imm into register with shift
// movk R, #IMM16, Shift

// movz :
// Byte 1
// 11010010 : d2
// 100XXXXX : X : 5 bits IMM16
// XXXXXXXX : X: 8 bits IMM16
// XXXYYYYY : X: 3bits IMM16 Y : 5 bits register select

// Load 0xcdef89ab45670123 into x0 :
// 11110010

// movk x0, #0x0123, lsl 0
// movk x0, #0x4567, lsl 16
// movk x0, #0x89ab, lsl 32
// movk x0, #0xcdef, lsl 48

inline void* relative_addr_to_absolute(void* source_addr, int32_t rel_addr)
{
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(source_addr) + rel_addr);
}

inline intptr_t absolute_addr_to_relative(void* opcode_addr, void* destination_addr)
{
    SPDLOG_INFO("opcode addr: {}, destination addr: {}", opcode_addr, destination_addr);
    return static_cast<uint8_t*>(destination_addr) - static_cast<uint8_t*>(opcode_addr);
}

bool addresses_are_relative_jumpable(void* source, void* dest)
{
    uintptr_t min_addr = reinterpret_cast<uintptr_t>(std::min(source, dest));
    uintptr_t max_addr = reinterpret_cast<uintptr_t>(std::max(source, dest));
    return (max_addr - min_addr) <= 0x7FFFFFC;

    //intptr_t addr = reinterpret_cast<intptr_t>(source) - reinterpret_cast<intptr_t>(dest);
    //return addr >= -134217728 && addr <= 134217724; // 26 bits signed integer range
}

#pragma pack(push, 1)

// Struct used by the memory manager to allocate trampolines
struct memory_t
{
    uint8_t used;
    uint8_t padding[3]; // arm is aligned on 4 bytes
    uint8_t data[48]; // Max absolute jump size is 20 bytes
};

struct AbsJump
{
    static inline size_t WriteOpcodes(void* buffer, void* jump_destination, int source_mode, int dest_mode)
    {
        uint32_t movz;     // movz x17, 0
        uint32_t movk16;   // movk x17, 0, lsl 16
        uint32_t movk32;   // movk x17, 0, lsl 32
        uint32_t movk48;   // movk x17, 0, lsl 48
        uint32_t br;       // br x17

        uintptr_t i_addr = reinterpret_cast<uintptr_t>(jump_destination);
        movz   = 0xd2800011 | uint32_t(i_addr & 0xffff) << 5;
        movk16 = 0xf2a00011 | uint32_t((i_addr >> 16) & 0xffff) << 5;
        movk32 = 0xf2c00011 | uint32_t((i_addr >> 32) & 0xffff) << 5;
        movk48 = 0xf2e00011 | uint32_t((i_addr >> 48) & 0xffff) << 5;
        br = 0xd61f0220;

        uint32_t* opcode = reinterpret_cast<uint32_t*>(buffer);

        switch (GetOpcodeSize(jump_destination, source_mode, dest_mode))
        {
            case 20:
                opcode[0] = movz;
                opcode[1] = movk16;
                opcode[2] = movk32;
                opcode[3] = movk48;
                opcode[4] = br;
                return 20;

            case 16:
                opcode[0] = movz;
                opcode[1] = movk16;
                opcode[2] = movk32;
                opcode[3] = br;
                return 16;

            case 12:
                opcode[0] = movz;
                opcode[1] = movk16;
                opcode[2] = br;
                return 12;

            case 8:
                opcode[0] = movz;
                opcode[1] = br;
                return 8;
        }

        return 0;
    }

    // Variable jump size
    static inline size_t GetOpcodeSize(void* jump_destination, int source_mode, int dest_mode)
    {
        uintptr_t i_addr = (uintptr_t)jump_destination;
        // Need 4 instructions to fill 64bits
        if ((i_addr & 0xffff000000000000) != 0)
            return 20;

        // Need 3 instructions to fill 48bits
        if ((i_addr & 0xffff00000000) != 0)
            return 16;

        // Need 2 instructions to fill 32bits
        if ((i_addr & 0xffff0000) != 0)
            return 12;

        // Need 1 instruction to fill 16bits
        return 8;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        // movz 16 bits
        // movk 16 bits << 16
        // movk 16 bits << 32
        // movk 16 bits << 48
        // 
        return 20;
    }
};

struct RelJump
{
    static inline size_t WriteOpcodes(void* buffer, void* source, void* jump_destination, int source_mode, int dest_mode)
    {
        union
        {
            struct {
                int32_t rel_addr : 26;
                int32_t pad : 6;
            };
            int32_t addr;
        } v{};

        v.rel_addr = (reinterpret_cast<uintptr_t>(jump_destination) - reinterpret_cast<uintptr_t>(source)) / 4;

        *reinterpret_cast<uint32_t*>(buffer) = 0x14000000 | v.addr;

        return 4;
    }

    static constexpr size_t GetOpcodeSize(void* source, void* jump_destination, int source_mode, int dest_mode)
    {
        return 4;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        return 4;
    }
};

struct CpuPush
{
    static size_t WriteOpcodes(void* source, uint64_t value)
    {
        return 0;
    }

    static constexpr size_t GetOpcodeSize(uint32_t value)
    {
        return 0;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        return 0;
    }
};
#pragma pack(pop)


void _EnterRecursiveThunk(void*& _pCode)
{
    // TODO
    // Common PLT format:
    // adrp    x16, #0x9e01f
    // ldr     x17, [x16, #2168]
    // add     x16, x16, #0x878
    // br      x17
}

size_t _GetRelocatableSize(void* pCode, void*& jump_destination, size_t& jump_destination_size, JumpType_e& jump_type, bool ignore_relocation, CodeDisasm& disasm, size_t wanted_relocatable_size)
{
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
            {// Don't handle arm64 jump/call relocation.
                //jump_destination = reinterpret_cast<void*>(disasm.GetInstruction().detail->x86.operands[0].imm);
                //jump_destination_size += disasm.GetInstruction().size;
                //relocatable_size += jump_destination_size;
            }

#ifdef USE_SPDLOG
            SPDLOG_INFO("Can't relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
            break;
        }

        uint32_t c = *reinterpret_cast<const uint32_t*>(disasm.GetInstruction().bytes) & 0x9F000000;
        if (c == 0x10000000 || c == 0x90000000)
        {// adr || adrp
            if (ignore_relocation) // Last instruction, overwrite it if we're ignoring relocations
                relocatable_size += disasm.GetInstruction().size;

#ifdef USE_SPDLOG
            SPDLOG_INFO("Can't relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
            break;
        }

#ifdef USE_SPDLOG
        SPDLOG_INFO("Can relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
        relocatable_size += disasm.GetInstruction().size;
    }

    return relocatable_size;
}

#endif//MINI_DETOUR_ARM64_H
