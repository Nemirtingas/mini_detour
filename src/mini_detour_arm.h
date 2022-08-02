#ifndef MINI_DETOUR_ARM_H
#define MINI_DETOUR_ARM_H

inline uint8_t* relative_addr_to_absolute(int32_t rel_addr, uint8_t* source_addr)
{
    // TODO
    return source_addr + rel_addr;
}

inline int32_t absolute_addr_to_relative(void* opcode_addr, void* destination_addr)
{
    SPDLOG_INFO("opcode addr: {}, destination addr: {}", opcode_addr, destination_addr);
    return reinterpret_cast<uint8_t*>(destination_addr) - reinterpret_cast<uint8_t*>(opcode_addr);
}

bool addresses_are_relative_jumpable(void* source, void* dest)
{
    uintptr_t min_addr = reinterpret_cast<uintptr_t>(std::min(source, dest));
    uintptr_t max_addr = reinterpret_cast<uintptr_t>(std::max(source, dest));
    return (max_addr - min_addr) <= 0x1FFFFFC;
}

#pragma pack(push, 1)

// Struct used by the memory manager to allocate trampolines
struct memory_t
{
    uint8_t used;
    uint8_t padding[3]; // arm is aligned on 4 bytes
    uint8_t data[40]; // Max absolute jump size is 20 bytes
};

//uint32_t arm_get_cpsr()
//{
//    uint32_t res;
//    __asm ("MRS %[result], CPSR"
//        : [result] "=r" (res)
//    );
//    return res;
//}
//
//bool is_thumb_mode()
//{
//    return arm_get_cpsr() & 0x10;
//}

struct AbsJump
{
    static inline size_t WriteOpcodes(void* source, void* jump_destination, int source_mode, int dest_mode)
    {
        uint32_t addr = reinterpret_cast<uint32_t>(jump_destination) | (dest_mode ? 1 : 0);
        if (source_mode)
        {
            uint16_t* opcode = reinterpret_cast<uint16_t*>(source);

            // https://developer.arm.com/documentation/ddi0406/c/Application-Level-Architecture/Instruction-Details/Alphabetical-list-of-instructions/MOV--immediate-?lang=en
            // https://developer.arm.com/documentation/ddi0406/c/Application-Level-Architecture/Instruction-Details/Alphabetical-list-of-instructions/MOVT?lang=en

            uint16_t addr16 = uint16_t(addr);

            opcode[0] = 0xf84d;
            opcode[1] = 0x0c08; // str r0, [sp, #-8]
            
            opcode[2] = 0xf240 | ((addr16 & 0x800) >> 1) | ((addr16 & 0xf000) >> 12); // movw r0, imm16
            opcode[3] = (addr16 & 0xff) | ((addr16 & 0x700) << 4); // movw r0, imm16

            addr16 = uint16_t(addr >> 16);
            opcode[4] = 0xf2C0 | ((addr16 & 0x800) >> 1) | ((addr16 & 0xf000) >> 12); // movt r0, addr & 0xffff0000
            opcode[5] = (addr16 & 0xff) | ((addr16 & 0x700) << 4); // movt r0, addr & 0xffff0000

            opcode[6] = 0xb401; // push {r0}

            opcode[7] = 0xf85d;
            opcode[8] = 0x0c04; // ldr r0, [sp, #-4]

            opcode[9] = 0xbd00; // pop {pc}

            //opcode[0] = 0xf8df; // ldr pc, [pc, #2]
            //opcode[1] = 0xf002; // ldr pc, [pc, #2]
            //*reinterpret_cast<uint32_t*>(&opcode[2]) = addr;

            return 20;
        }
        else
        {
            uint32_t* opcode = reinterpret_cast<uint32_t*>(source);

            opcode[0] = 0xe51ff004; // ldr pc, [pc, #-4]
            opcode[1] = reinterpret_cast<uint32_t>(jump_destination);

            return 8;
        }
    }

    static inline size_t GetOpcodeSize(void* jump_destination, int source_mode, int dest_mode)
    {
        return source_mode ? 20 : 8;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        return 20;
    }
};

struct RelJump
{
    static inline size_t WriteOpcodes(void* source, void* jump_destination, int source_mode, int dest_mode)
    {
        int32_t rel_addr = static_cast<int32_t>(reinterpret_cast<uintptr_t>(jump_destination) - reinterpret_cast<uintptr_t>(source));
        if (source_mode)
        {
            uint16_t* opcode = reinterpret_cast<uint16_t*>(source);

            if (rel_addr >= -2044 && rel_addr <= 2050)
            {// 2 bytes opcode
                union
                {
                    struct {
                        int16_t rel_addr : 11;
                        int16_t pad : 5;
                    };
                    int16_t addr;
                } v{};

                v.rel_addr = (rel_addr / 2) - 2;
                opcode[0] = 0xe000 | v.addr;
                return 2;
            }
            else
            {
                rel_addr -= 4; // -4 because ARM Instruction Pointer is always 2 instructions ahead
                uint16_t S = rel_addr >> 31;
                uint16_t imm11 = (rel_addr >> 1) & 0x07ff;
                uint16_t imm10 = (rel_addr >> 12) & 0x03ff;
                uint16_t I1 = (rel_addr >> 23) & 1;
                uint16_t I2 = (rel_addr >> 22) & 1;
                uint16_t J1 = (!I1) ^ S;
                uint16_t J2 = (!I2) ^ S;
                
                /*
                 * -------------------------------------------------
                 * |15|14|13|12|11|10|09 08 07 06 05 04 03 02 01 00|
                 * | 1| 1| 1| 1| 0| S|         imm10               |
                 * |-----------------------------------------------|
                 * |15|14|13|12|11|10 09 08 07 06 05 04 03 02 01 00|
                 * | 1| 0|J1| 1|J2|            imm11               |
                 * -------------------------------------------------
                 * 
                 * I1 = !(J1 ^ S)
                 * I2 = !(J2 ^ S)
                 * imm32 = S:I1:I2:imm10:imm11:0
                 */

                opcode[0] = 0xf000 | (S << 10) | imm10;
                opcode[1] = 0x9000 | (J1 << 13) | (J2 << 11) | imm11;
                return 4;
            }
        }
        else
        {
            union
            {
                struct {
                    int32_t rel_addr : 24;
                    int32_t pad : 8;
                };
                int32_t addr;
            } v{};

            v.rel_addr = (rel_addr / 4) - 2;

            *reinterpret_cast<uint32_t*>(source) = 0xea000000 | v.addr;
        }

        return 4;
    }

    static inline size_t GetOpcodeSize(void* source, void* jump_destination, int source_mode, int dest_mode)
    {
        if (source_mode)
        {
            int32_t rel_addr = static_cast<int32_t>(reinterpret_cast<uintptr_t>(jump_destination) - reinterpret_cast<uintptr_t>(source));
            if (rel_addr >= -2044 && rel_addr <= 2050)
                return 2;
        }
        
        return 4;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        return 4;
    }
};
#pragma pack(pop)

void _EnterRecursiveThunk(void*& pCode)
{
    // TODO
}

size_t _GetRelocatableSize(void* pCode, void*& jump_destination, size_t& jump_destination_size, bool ignore_relocation, CodeDisasm& disasm, size_t wanted_relocatable_size)
{
    uint8_t code_buffer[80];
    const uint8_t* code_iterator = code_buffer;
    size_t code_size = 80;
    uint64_t code_addr = reinterpret_cast<uint64_t>(pCode);

    memcpy(code_buffer, reinterpret_cast<void*>(code_addr), 80);

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

#endif//MINI_DETOUR_ARM_H
