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

inline void *relative_addr_to_absolute(void *source_addr, int32_t rel_addr)
{
    return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(source_addr) + rel_addr);
}

inline intptr_t absolute_addr_to_relative(void *opcode_addr, void *destination_addr)
{
    SPDLOG_INFO("opcode addr: {}, destination addr: {}", opcode_addr, destination_addr);
    return static_cast<uint8_t *>(destination_addr) - static_cast<uint8_t *>(opcode_addr);
}

bool _AddressesAreRelativeJumpable(void *source, void *dest)
{
    uintptr_t min_addr = reinterpret_cast<uintptr_t>(std::min(source, dest));
    uintptr_t max_addr = reinterpret_cast<uintptr_t>(std::max(source, dest));
    return (max_addr - min_addr) <= 0x7FFFFFC;

    // intptr_t addr = reinterpret_cast<intptr_t>(source) - reinterpret_cast<intptr_t>(dest);
    // return addr >= -134217728 && addr <= 134217724; // 26 bits signed integer range
}

// An export table entry holds a 32 bits RVA: the address must be above the module base, within 4 GB.
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
    uint8_t padding[3]; // arm is aligned on 4 bytes
    uint8_t data[48];   // Max absolute jump size is 20 bytes
};

struct AbsJump
{
    static inline size_t WriteOpcodes(void *buffer, void *jump_destination, int source_mode, int dest_mode)
    {
        uint32_t movz;   // movz x17, 0
        uint32_t movk16; // movk x17, 0, lsl 16
        uint32_t movk32; // movk x17, 0, lsl 32
        uint32_t movk48; // movk x17, 0, lsl 48
        uint32_t br;     // br x17

        uintptr_t i_addr = reinterpret_cast<uintptr_t>(jump_destination);
        movz             = 0xd2800011 | uint32_t(i_addr & 0xffff) << 5;
        movk16           = 0xf2a00011 | uint32_t((i_addr >> 16) & 0xffff) << 5;
        movk32           = 0xf2c00011 | uint32_t((i_addr >> 32) & 0xffff) << 5;
        movk48           = 0xf2e00011 | uint32_t((i_addr >> 48) & 0xffff) << 5;
        br               = 0xd61f0220;

        uint32_t *opcode = reinterpret_cast<uint32_t *>(buffer);

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
    static inline size_t GetOpcodeSize(void *jump_destination, int source_mode, int dest_mode)
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
    static inline size_t WriteOpcodes(void *buffer, void *source, void *jump_destination, int source_mode, int dest_mode)
    {
        union
        {
            struct
            {
                int32_t rel_addr : 26;
                int32_t pad : 6;
            };
            int32_t addr;
        } v{};

        v.rel_addr = (reinterpret_cast<uintptr_t>(jump_destination) - reinterpret_cast<uintptr_t>(source)) / 4;

        *reinterpret_cast<uint32_t *>(buffer) = 0x14000000 | v.addr;

        return 4;
    }

    static constexpr size_t GetOpcodeSize(void *source, void *jump_destination, int source_mode, int dest_mode) { return 4; }

    static constexpr size_t GetMaxOpcodeSize() { return 4; }
};

#pragma pack(pop)

// Follows PLT entries to the function they jump to, read from their GOT entry:
//   [bti c]; adrp x16, page; ldr x17, [x16, #offset]; add x16, x16, #offset; br x17
// The code mode is carried by the address on ARM (Thumb bit): ARM64 has a single mode.
static inline int _GetCodeMode(void * /*address*/)
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
    return disasm.Init(cs_arch::CS_ARCH_ARM64, (cs_mode)(cs_mode::CS_MODE_ARM | CodeDisasm::RuntimeEndianness()));
}

void _EnterRecursiveThunk(void *&_pCode)
{
    // A longer chain is most likely a loop.
    for (int i = 0; i < 8; ++i)
    {
        const uint32_t *code = reinterpret_cast<const uint32_t *>(_pCode);
        if (code[0] == 0xD503245F) // bti c
            ++code;

        if ((code[0] & 0x9F00001F) != 0x90000010 || (code[1] & 0xFFC003FF) != 0xF9400211 || code[3] != 0xD61F0220)
            return;

        // adrp: signed 21 bits page count, immhi (bits 5-23) and immlo (bits 29-30).
        int64_t pages = static_cast<int64_t>((((code[0] >> 5) & 0x7FFFF) << 2) | ((code[0] >> 29) & 3));
        if (pages & (int64_t(1) << 20))
            pages -= int64_t(1) << 21;

        const uintptr_t page     = (reinterpret_cast<uintptr_t>(code) & ~uintptr_t(0xFFF)) + static_cast<uintptr_t>(pages * 0x1000);
        const uintptr_t gotEntry = page + ((code[1] >> 10) & 0xFFF) * 8;
        _pCode                   = *reinterpret_cast<void **>(gotEntry);
    }
}

// adr, adrp and the literal loads (LDR, LDRSW, PRFM, SIMD LDR) compute their address from pc.
static bool _UsesInstructionPointer(cs_insn const &instruction)
{
    const uint32_t raw = *reinterpret_cast<const uint32_t *>(instruction.bytes);
    const uint32_t adr = raw & 0x9F000000;
    return adr == 0x10000000 || adr == 0x90000000 || (raw & 0x3B000000) == 0x18000000;
}

size_t _GetRelocatableSize(void *pCode, size_t &relocatedOriginalCodeSize, bool ignore_relocation, CodeDisasm &disasm, size_t wanted_relocatable_size)
{
    uint8_t code_buffer[80];
    const uint8_t *code_iterator = code_buffer;
    size_t code_size             = 0;
    uint64_t code_addr           = reinterpret_cast<uint64_t>(pCode);

    code_size = _ReadCode(reinterpret_cast<void *>(code_addr), code_buffer, sizeof(code_buffer));

    size_t relocatable_size = 0;
    while (relocatable_size < wanted_relocatable_size)
    {
        if (!disasm.Disasm(&code_iterator, &code_size, &code_addr))
            break;

        if (disasm.IsInstructionTerminating())
        {
            if (ignore_relocation) // Last instruction, overwrite it if we're ignoring relocations
            {
                relocatedOriginalCodeSize += disasm.GetInstruction().size;
                relocatable_size += disasm.GetInstruction().size;
            }
            else if (disasm.GetJumpType() == 3)
            { // Don't handle arm64 jump/call relocation.
            }

#ifdef USE_SPDLOG
            SPDLOG_INFO("Can't relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
            break;
        }

        if (_UsesInstructionPointer(disasm.GetInstruction()))
        {
            if (ignore_relocation) // Last instruction, overwrite it if we're ignoring relocations
            {
                relocatedOriginalCodeSize += disasm.GetInstruction().size;
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

#ifdef USE_SPDLOG
        SPDLOG_INFO("Can relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
        relocatedOriginalCodeSize += disasm.GetInstruction().size;
        relocatable_size += disasm.GetInstruction().size;
    }

    return relocatable_size;
}

size_t _RelocateCode(void *pCode, void *pTrampoline, CodeDisasm &disasm, size_t wanted_relocatableSize, int /*func_mode*/)
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
    while (relocatedSize < wanted_relocatableSize)
    {
        if (!disasm.Disasm(&code_iterator, &code_size, &code_addr))
            break;

        if (disasm.IsInstructionTerminating())
        {
#ifdef USE_SPDLOG
            SPDLOG_INFO("Can't relocate \"{} {}\"", disasm.GetInstruction().mnemonic, disasm.GetInstruction().op_str);
#endif
            break;
        }

        if (_UsesInstructionPointer(disasm.GetInstruction()))
        {
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

#endif // MINI_DETOUR_ARM64_H
