#ifndef MINI_DETOUR_ARM_H
#define MINI_DETOUR_ARM_H

#pragma pack(push, 1)

// Struct used by the memory manager to allocate trampolines
struct memory_t
{
    uint8_t used;
    uint8_t padding[3]; // arm is aligned on 4 bytes
    uint8_t data[32]; // Max absolute jump size is 12 bytes
};

struct AbsJump
{
private:


public:
    static constexpr uint8_t code[] = {
    };

    AbsJump()
    {}

    inline void* GetAddr()
    {
        return abs_addr;
    }

    inline void SetAddr(void* addr)
    {

    }

    inline size_t GetOpcodeSize(void* addr)
    {
        return 4;
    }
};

struct RelJump
{
private:
    int32_t b : 8; // 0xea B (branch)
    int32_t rel_addr : 24; // relative address * 4

public:
    static constexpr uint8_t code[] = { 0xE9,
                                        0x00, 0x00, 0x00, 0x00 };

    RelJump() :
        b(0xea),
        rel_addr(0x000000)
    {}


    inline int32_t GetAddr()
    {
        return rel_addr * 4;
    }

    inline void SetAddr(int32_t addr)
    {
        assert((addr % 4) == 0);
        rel_addr = addr / 4;
    }

    inline size_t GetOpcodeSize(void* addr)
    {
        return 4;
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
    // TODO
    return source_addr + rel_addr + 5;
}

inline int32_t absolute_addr_to_relative(void* opcode_addr, void* destination_addr)
{
    SPDLOG_INFO("opcode addr: {}, destination addr: {}", opcode_addr, destination_addr);
    return reinterpret_cast<uint8_t*>(destination_addr) - reinterpret_cast<uint8_t*>(opcode_addr);
}

void enter_recursive_thunk(uint8_t*& pCode)
{
    // TODO
}

size_t get_relocatable_size(void* pCode, void** tmp_relocation, size_t wanted_relocatable_size)
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

        if (*tmp_relocation != nullptr)
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
    return (max_addr - min_addr) <= 0x1FFFFFC;
}

#endif//MINI_DETOUR_ARM_H
