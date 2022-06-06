#ifndef MINI_DETOUR_ARM64_H
#define MINI_DETOUR_ARM64_H

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
private:
    uint32_t movz;     // movz r8, 0
    uint32_t movk16;   // movk r8, 0, 16
    uint32_t movk32;   // movk r8, 0, 32
    uint32_t movk48;   // movk r8, 0, 48
    uint32_t br;       // br x8
    size_t opcode_size;

public:
    AbsJump() :
        movz(0xd2800008),
        movk16(0xf2a00008),
        movk32(0xf2c00008),
        movk48(0xf2e00008),
        br(0xd61f0100),
        opcode_size(0)
    {}

    inline void* GetAddr()
    {
        uint64_t i_addr = 0;

        i_addr |= static_cast<uint64_t>(movz >> 11) & 0xffff;
        i_addr |= static_cast<uint64_t>(movk16 & 0x001fffe) << 5;
        i_addr |= static_cast<uint64_t>(movk32 & 0x001fffe) << 21;
        i_addr |= static_cast<uint64_t>(movk48 & 0x001fffe) << 37;

        return (void*)i_addr;
    }

    inline void SetAddr(void* addr)
    {
        uintptr_t i_addr = (uintptr_t)addr;

        //XXXYYYYY: X: 3bits IMM16 Y: 5 bits register select
        //XXXXXXXX: X: 8 bits IMM16
        //100XXXXX: X: 5 bits IMM16
        //11010010: d2

        SPDLOG_INFO("{}", addr);
        //movz = (movz & 0xffffe0001f) | uint32_t(i_addr & 0xffff) << 5;
        //movk16 = (movk16 & 0xffffe0001f) | uint32_t((i_addr >> 16) & 0xffff) << 5;
        //movk32 = (movk32 & 0xffffe0001f) | uint32_t((i_addr >> 32) & 0xffff) << 5;
        //movk48 = (movk48 & 0xffffe0001f) | uint32_t((i_addr >> 48) & 0xffff) << 5;
        movz = 0xd2800008 | uint32_t(i_addr & 0xffff) << 5;
        movk16 = 0xf2a00008 | uint32_t((i_addr >> 16) & 0xffff) << 5;
        movk32 = 0xf2c00008 | uint32_t((i_addr >> 32) & 0xffff) << 5;
        movk48 = 0xf2e00008 | uint32_t((i_addr >> 48) & 0xffff) << 5;

        opcode_size = GetOpcodeSize(addr);
    }

    inline void WriteOpcodes(void* addr)
    {
        assert(opcode_size != 0);

        uint32_t* opcode = (uint32_t*)addr;

        switch (opcode_size)
        {
            case 20:
                opcode[0] = movz;
                opcode[1] = movk16;
                opcode[2] = movk32;
                opcode[3] = movk48;
                opcode[4] = br;
                break;

            case 16:
                opcode[0] = movz;
                opcode[1] = movk16;
                opcode[2] = movk32;
                opcode[3] = br;
                break;

            case 12:
                opcode[0] = movz;
                opcode[1] = movk16;
                opcode[2] = br;
                break;

            case 8:
                opcode[0] = movz;
                opcode[1] = br;
                break;
        }
    }

    inline size_t GetOpcodeSize()
    {
        return opcode_size;
    }

    // Variable jump size
    static inline size_t GetOpcodeSize(void* addr)
    {
        uintptr_t i_addr = (uintptr_t)addr;
        if ((i_addr & 0xffff000000000000) != 0)
            return 20;

        if ((i_addr & 0xffff00000000) != 0)
            return 16;

        if ((i_addr & 0xffff0000) != 0)
            return 12;

        if ((i_addr & 0xffff) != 0)
            return 8;

        return 0;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        return
            sizeof(AbsJump::movz) +
            sizeof(AbsJump::movk16) +
            sizeof(AbsJump::movk32) +
            sizeof(AbsJump::movk48) +
            sizeof(AbsJump::br);
    }
};

struct RelJump
{
private:
    uint32_t b; // 0x14 B (branch)
                // 26 bits relative address * 4 (rel addr 1 => offset 4)

public:
    RelJump() :
        b{}
    {}

    inline int32_t GetAddr()
    {
        if ((b & 0xFC) != 0x14)
            return 0;

        union
        {
            struct {
                int32_t rel_addr : 26;
                int32_t pad : 6;
            };
            int32_t addr;
        } v{};

        v.rel_addr = b & 0x3FFFFFFF;

        return v.addr * 4;
    }

    inline void SetAddr(int32_t addr)
    {
        union
        {
            struct {
                int32_t rel_addr : 26;
                int32_t pad : 6;
            };
            int32_t addr;
        } v{};

        assert((addr % 4) == 0);
        //  134217724 Max int26_t value * 4 because jump is 4 bytes aligned
        // -134217728 Min int26_t value * 4 because jump is 4 bytes aligned
        assert((addr <= 134217724 && addr >= -134217728));

        v.rel_addr = addr / 4;

        b = 0x14000000 | v.addr;

        SPDLOG_INFO("{:08x} {}", b, v.addr);
    }

    inline void WriteOpcodes(void* addr)
    {
        memcpy(addr, &b, GetOpcodeSize(addr));
    }

    inline size_t GetOpcodeSize()
    {
        return sizeof(b);
    }

    static inline size_t GetOpcodeSize(void* addr)
    {
        return sizeof(b);
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        return sizeof(RelJump::b);
    }
};
#pragma pack(pop)

////////////////////////////////////////////////////
/// Tiny disasm
bool is_opcode_terminating_function(void* pCode)
{
    uint32_t opcode = *(uint32_t*)pCode;

    switch (opcode & 0xFFFFFC1F)
    {
        case 0xd61f0000: // br
        case 0xd63f0000: // blr
        case 0xd65f0000: // ret
            return 4;
    }
    switch (opcode & 0xFC000000)
    {
        case 0x14000000: // b
        case 0x94000000: // bl
            return 4;
    }
    switch (opcode & 0xFF000000)
    {
        case 0x34000000: // cbzw
        case 0x35000000: // cbnzw
        case 0xB4000000: // cbzx
        case 0xB5000000: // cbnzx
        case 0x54000000: // b_cond
            return 4;
    }
    switch (opcode & 0x7F000000)
    {
        case 0x36000000: // tbz
        case 0x37000000: // tbnz
            return 4;
    }
    switch (opcode)
    {
        case 0xd69f03e0: // eret
        case 0xd6bf03e0: // drps
            return 4;
    }

    return false;
}

int is_opcode_filler(void* pCode)
{
    if (*(uint32_t*)pCode == 0xD503201F)
        return 4; // nop | hint

    return 0;
}

int read_opcode(void* _pCode, void** relocation)
{
    uint32_t* pCode = (uint32_t*)_pCode;

    int code_len = is_opcode_filler(pCode);
    if (code_len != 0)
    {
        SPDLOG_INFO("Filler");
        return code_len;
    }

    switch (*pCode & 0x9F000000)
    {
        case 0x10000000: // adr
        case 0x90000000: // adrp
            SPDLOG_INFO("adr|adrp {:08x}", *pCode);
            return 0;// Don't relocate code relative opcodes
    }

    return 4; // arm opcodes are 4 bytes long
}

///////////////////////////////////////////
// Tiny asm

inline uint8_t* relative_addr_to_absolute(int32_t rel_addr, uint8_t* source_addr)
{
    return source_addr + rel_addr;
}

inline intptr_t absolute_addr_to_relative(void* opcode_addr, void* destination_addr)
{
    SPDLOG_INFO("opcode addr: {}, destination addr: {}", opcode_addr, destination_addr);
    return static_cast<uint8_t*>(destination_addr) - static_cast<uint8_t*>(opcode_addr);
}

void enter_recursive_thunk(void*& pCode)
{
    // TODO
}

size_t get_relocatable_size(void* pCode, void** tmp_relocation, bool ignore_relocation, size_t wanted_relocatable_size)
{
    *tmp_relocation = nullptr;
    size_t relocatable_size = 0;
    while (relocatable_size < wanted_relocatable_size)
    {
        int opcode_size = read_opcode(pCode, tmp_relocation);
        //  Unknown opcode, break now
        if (opcode_size == 0 || is_opcode_terminating_function(pCode))
        {
            SPDLOG_INFO("Terminating or unknown");
            break;
        }

        if (!ignore_relocation && *tmp_relocation != nullptr)
        {
            break;
        }

        pCode = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(pCode) + opcode_size);
        relocatable_size += opcode_size;
    }

    return relocatable_size;
}

bool addresses_are_relative_jumpable(void* source, void* dest)
{
    uintptr_t min_addr = reinterpret_cast<uintptr_t>(std::min(source, dest));
    uintptr_t max_addr = reinterpret_cast<uintptr_t>(std::max(source, dest));
    return (max_addr - min_addr) <= 0x7FFFFFC;

    //intptr_t addr = reinterpret_cast<intptr_t>(source) - reinterpret_cast<intptr_t>(dest);
    //return addr >= -134217728 && addr <= 134217724; // 26 bits signed integer range
}

#endif//MINI_DETOUR_ARM64_H
