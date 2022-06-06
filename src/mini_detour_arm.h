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

uint32_t arm_get_cpsr()
{
    uint32_t res;
    __asm ("MRS %[result], CPSR"
        : [result] "=r" (res)
    );
    return res;
}

bool is_thumb_mode()
{
    return arm_get_cpsr() & 0x10;
}

struct AbsJump
{
private:
    uint32_t ldr;   // LDR PC, =value_at_relative_address
    void* abs_addr; // Absolute address to load in PC (Pointer Code)

public:

    AbsJump():
        ldr{}, 
        abs_addr{}
    {}

    inline void* GetAddr()
    {
        return abs_addr;
    }

    inline void SetAddr(void* addr)
    {
        abs_addr = addr;
    }

    inline void WriteOpcodes(void* addr)
    {
        uint32_t* opcode = (uint32_t*)addr;
        bool is_thumb = is_thumb_mode();
        //bool is_thumb = reinterpret_cast<uint32_t>(addr) & 1;
        SPDLOG_INFO("Writing opcodes in {} mode", is_thumb ? "thumb" : "arm");

        ldr = is_thumb ? 0x04f05ff8 : 0xe51ff004; // ldr pc, [pc, #-4]

        opcode[0] = ldr;
        opcode[1] = reinterpret_cast<uint32_t>(abs_addr) | (is_thumb ? 1 : 0);
    }

    inline size_t GetOpcodeSize()
    {
        return sizeof(ldr) + sizeof(abs_addr);
    }

    static inline size_t GetOpcodeSize(void* addr)
    {
        return sizeof(ldr) + sizeof(abs_addr);
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        return sizeof(AbsJump::ldr) + sizeof(AbsJump::abs_addr);
    }
};

struct RelJump
{
private:
    uint32_t arm_b;   // 0xea B (branch)
                      // 24 bits relative address * 4 (rel addr 1 => offset 4)
                      // relative address translation: 
                      //   addr 0 -> rel addr -2
                      //   addr 4 -> rel addr -1
                      //   addr 8 -> rel addr  0

    uint32_t thumb_b; // 0xe7 B (branch)
                      // 

public:
    RelJump() :
        arm_b{}
    {}


    inline int32_t GetAddr()
    {
        if ((arm_b & 0xFF) != 0xea)
            return 0;

        union
        {
            struct {
                int32_t rel_addr : 24;
                int32_t pad : 8;
            };
            int32_t addr;
        } v;

        v.addr = 0;
        v.rel_addr = (arm_b & 0x00FFFFFFF) + 2;

        return v.addr * 4;
    }

    inline void SetAddr(int32_t addr)
    {
        union
        {
            struct {
                int32_t rel_addr : 24;
                int32_t pad : 8;
            };
            int32_t addr;
        } v;

        //  33554436 = (Max int24_t value( 8388607) + 2 because of addr translation) * 4
        // -33554424 = (Min int24_t value(-8388608) + 2 because of addr translation) * 4
        assert((addr <= 33554436 && addr >= -33554424));

        v.addr = 0;
        v.rel_addr = (addr / 4) - 2;
        
        arm_b = 0xea000000 | v.addr;

        SPDLOG_INFO("{:08x} {}", arm_b, v.addr);
    }

    inline void WriteOpcodes(void* addr)
    {
        memcpy(addr, &arm_b, GetOpcodeSize(addr));
    }

    inline size_t GetOpcodeSize()
    {
        return sizeof(arm_b);
    }

    static inline size_t GetOpcodeSize(void* addr)
    {
        return sizeof(arm_b);
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        return sizeof(RelJump::arm_b);
    }
};
#pragma pack(pop)

////////////////////////////////////////////////////
/// Tiny disasm
bool is_opcode_terminating_function(void* pCode, bool is_thumb)
{
    return false;
}

int is_opcode_filler(void* pCode, bool is_thumb)
{
    return 0;
}

int read_opcode(void* _pCode, void** relocation, bool is_thumb)
{
    uint32_t* pCode = (uint32_t*)_pCode;

    int code_len = is_opcode_filler(pCode, is_thumb);
    if (code_len != 0)
    {
        SPDLOG_INFO("Filler");
        return code_len;
    }

    return is_thumb ? 2 : 4; // This is not true, some thumbv2 are 4 bytes long
}

///////////////////////////////////////////
// Tiny asm

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

void enter_recursive_thunk(void*& pCode)
{
    // TODO
}

size_t get_relocatable_size(void*& _pCode, void** tmp_relocation, bool ignore_relocation, size_t wanted_relocatable_size)
{
    bool is_thumb = reinterpret_cast<uintptr_t>(_pCode) & 1;
    _pCode = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(_pCode) & ~1);

    void* pCode = _pCode;

    *tmp_relocation = nullptr;
    size_t relocatable_size = 0;
    while (relocatable_size < wanted_relocatable_size)
    {
        int opcode_size = read_opcode(pCode, tmp_relocation, is_thumb);
        //  Unknown opcode, break now
        if (opcode_size == 0 || is_opcode_terminating_function(pCode, is_thumb))
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
    return (max_addr - min_addr) <= 0x1FFFFFC;
}

#endif//MINI_DETOUR_ARM_H
