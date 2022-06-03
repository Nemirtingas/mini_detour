#include <mini_detour/mini_detour.h>

#include <assert.h>
#include <string.h>

#include <algorithm>
#include <limits>
#include <utility>
#include <type_traits> // std::move
#include <fstream>
#include <string>
#include <vector>

#ifdef USE_SPDLOG
#include <spdlog/spdlog-inl.h>
#else
#define SPDLOG_DEBUG(...)
#define SPDLOG_ERROR(...)
#define SPDLOG_INFO(...)
#endif

#if defined(WIN64) || defined(_WIN64) || defined(__MINGW64__) || defined(WIN32) || defined(_WIN32) || defined(__MINGW32__)
#define MINIDETOUR_OS_WINDOWS

#if defined(_M_IX86)
#define MINIDETOUR_ARCH_X86
#elif defined(_M_AMD64)
#define MINIDETOUR_ARCH_X64
#elif defined(_M_ARM)
#define MINIDETOUR_ARCH_ARM
#elif defined(_M_ARM64)
#define MINIDETOUR_ARCH_ARM64
#else
#error "Unhandled arch"
#endif
#elif defined(__linux__) || defined(linux)
#define MINIDETOUR_OS_LINUX

#if defined(__i386__) || defined(__i386) || defined(i386)
#define MINIDETOUR_ARCH_X86
#elif defined(__x86_64__) || defined(__x86_64) || defined(__amd64) || defined(__amd64__)
#define MINIDETOUR_ARCH_X64
#elif defined(__arm__)
#define MINIDETOUR_ARCH_ARM
#elif defined(__aarch64__)
#define MINIDETOUR_ARCH_ARM64
#else
#error "Unhandled arch"
#endif
#elif defined(__APPLE__)
#define MINIDETOUR_OS_APPLE

#if defined(__i386__) || defined(__i386) || defined(i386)
#define MINIDETOUR_ARCH_X86
#elif defined(__x86_64__) || defined(__x86_64) || defined(__amd64) || defined(__amd64__)
#define MINIDETOUR_ARCH_X64
#elif defined(__arm__)
#define MINIDETOUR_ARCH_ARM
#elif defined(__aarch64__)
#define MINIDETOUR_ARCH_ARM64
#else
#error "Unhandled arch"
#endif
#endif

#if defined(MINIDETOUR_OS_WINDOWS)
#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <Windows.h>

#elif defined(MINIDETOUR_OS_LINUX)
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#elif defined(MINIDETOUR_OS_APPLE)
#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_prot.h>
#include <mach/vm_map.h>
#include <unistd.h>
#include <errno.h>

#endif

inline size_t page_addr_size(void* addr, size_t len, size_t page_size);
inline size_t region_size();
inline size_t jumps_in_region();

//------------------------------------------------------------------------------//
// Helper funcs
//------------------------------------------------------------------------------//
constexpr int addr_size = sizeof(void*);
constexpr int absolute_addr_size = addr_size;
constexpr int relative_addr_size = sizeof(int32_t);

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

// 32Bits abs jump
// PUSH XX XX XX XX
// RET

#ifdef MINIDETOUR_ARCH_X64
#include "mini_detour_x64.h"

#pragma pack(push, 1)
struct abs_jump_t
{
private:
    uint8_t  _code[14]; // FF 25                          | JMP
                        // 00 00 00 00 (rip + 0x00000000) | RIP OFFSET
                        // XX XX XX XX XX XX XX XX        | ABS_ADDR

public:
    abs_jump_t() :
        _code{}
    {
        _code[0] = 0xFF;
        _code[1] = 0x25;
    }

    inline void* GetAddr()
    {
        return *reinterpret_cast<void**>(&_code[6]);
    }

    inline void SetAddr(void* addr)
    {
        *reinterpret_cast<void**>(&_code[6]) = addr;
    }

    inline void WriteOpcodes(void* addr)
    {
        memcpy(addr, _code, GetOpcodeSize());
    }

    inline size_t GetOpcodeSize()
    {
        return 14;
    }

    static inline size_t GetOpcodeSize(void* addr)
    {
        return 14;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        return 14;
    }
};

struct rel_jump_t
{
private:
    uint8_t _code[5]; // E9          | JMP
                      // XX XX XX XX | REL ADDR

public:
    rel_jump_t() :
        _code{}
    {
        _code[0] = 0xE9;
    }

    inline int32_t GetAddr()
    {
        return *reinterpret_cast<int32_t*>(&_code[1]);
    }

    inline void SetAddr(int32_t addr)
    {
        *reinterpret_cast<int32_t*>(&_code[1]) = addr;
    }

    inline void WriteOpcodes(void* addr)
    {
        memcpy(addr, _code, GetOpcodeSize());
    }

    inline size_t GetOpcodeSize()
    {
        return 5;
    }

    static inline size_t GetOpcodeSize(void* addr)
    {
        return 5;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        return 5;
    }
};
#pragma pack(pop)

#elif defined(MINIDETOUR_ARCH_X86)
#include "mini_detour_x86.h"

#pragma pack(push, 1)
struct abs_jump_t
{
private:
    uint8_t _code[6]; // 0x68        | PUSH
                      // XX XX XX XX | ABS ADDR
                      // 0xC3        | RET

public:
    abs_jump_t() :
        _code{}
    {
        _code[0] = 0x68;
        _code[5] = 0xC3;
    }

    inline void* GetAddr()
    {
        return *reinterpret_cast<void**>(&_code[1]);
    }

    inline void SetAddr(void* addr)
    {
        *reinterpret_cast<void**>(&_code[1]) = addr;
    }

    inline void WriteOpcodes(void* addr)
    {
        memcpy(addr, _code, GetOpcodeSize());
    }

    inline size_t GetOpcodeSize()
    {
        return 6;
    }

    static inline size_t GetOpcodeSize(void* addr)
    {
        return 6;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        return 6;
    }
};

struct rel_jump_t
{
private:
    uint8_t _code[5]; // E9       | JMP
                      // XX XX XX | REL ADDR

public:

    rel_jump_t() :
        _code{}
    {
        _code[0] = 0xe9;
    }


    inline int32_t GetAddr()
    {
        return *reinterpret_cast<int32_t*>(&_code[1]);
    }

    inline void SetAddr(int32_t addr)
    {
        *reinterpret_cast<int32_t*>(&_code[1]) = addr;
    }

    inline void WriteOpcodes(void* addr)
    {
        assert(opcode_size != 0);

        memcpy(addr, _code, GetOpcodeSize());
    }

    inline size_t GetOpcodeSize()
    {
        return 5;
    }

    static inline size_t GetOpcodeSize(void* addr)
    {
        return 5;
    }

    static constexpr size_t GetMaxOpcodeSize()
    {
        return 5;
    }
};
#pragma pack(pop)

#elif defined(MINIDETOUR_ARCH_ARM)
#include "mini_detour_arm.h"

#pragma pack(push, 1)

struct abs_jump_t
{
private:


public:
    static constexpr uint8_t code[] = {
    };

    abs_jump_t()
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

struct rel_jump_t
{
private:
    int32_t b : 8; // 0xea B (branch)
    int32_t rel_addr : 24; // relative address * 4

public:
    static constexpr uint8_t code[] = { 0xE9,
                                        0x00, 0x00, 0x00, 0x00 };

    rel_jump_t() :
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

#elif defined(MINIDETOUR_ARCH_ARM64)
#include "mini_detour_arm64.h"

#define MEMORY_PADDING 4

#pragma pack(push, 1)

struct abs_jump_t
{
private:
    uint32_t movz;     // movz r8, 0
    uint32_t movk16;   // movk r8, 0, 16
    uint32_t movk32;   // movk r8, 0, 32
    uint32_t movk48;   // movk r8, 0, 48
    uint32_t br;       // br x8
    size_t opcode_size;

public:
    abs_jump_t() :
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
            sizeof(abs_jump_t::movz) +
            sizeof(abs_jump_t::movk16) +
            sizeof(abs_jump_t::movk32) +
            sizeof(abs_jump_t::movk48) +
            sizeof(abs_jump_t::br);
    }
};

struct rel_jump_t
{
private:
    uint32_t b; // 0x14 B (branch)
                // 26 bits relative address * 4 (rel addr 1 => offset 4)

public:
    rel_jump_t() :
        b{}
    {}

    inline int32_t GetAddr()
    {
        if ((b & 0xFC) != 0x14)
            return 0;
        
        if (b & 0x02000000)
        {// High 

        }

        return (b & 0x3FFFFFFF) * 4;
    }

    // Positiv: 0x000000 : 0xFFFFFFC
    inline void SetAddr(int32_t addr)
    {
        assert(addr % 4 == 0);
        addr /= 4;
        assert(addr & 0xC0000000 == 0);

        b = 0x14000000 | (addr & 0x3FFFFFFF);
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
        return sizeof(rel_jump_t::b);
    }
};
#pragma pack(pop)

#endif

namespace memory_manipulation {

#if defined(MINIDETOUR_OS_LINUX)
    int memory_protect_rights_to_native(memory_rights rights)
    {
        switch (rights)
        {
        case mem_r: return PROT_READ;
        case mem_w: return PROT_WRITE;
        case mem_x: return PROT_EXEC;
        case mem_rw: return PROT_WRITE | PROT_READ;
        case mem_rx: return PROT_READ | PROT_EXEC;
        case mem_wx: return PROT_WRITE | PROT_EXEC;
        case mem_rwx: return PROT_WRITE | PROT_READ | PROT_EXEC;

        default: return PROT_NONE;
        }
    }

    size_t page_size()
    {
        return sysconf(_SC_PAGESIZE);
    }

    region_infos_t get_region_infos(void* address)
    {
        region_infos_t res{};

        uint64_t target = (uint64_t)address;
        std::ifstream f("/proc/self/maps");
        std::string s;
        while (std::getline(f, s))
        {
            if (!s.empty() && s.find("vdso") == std::string::npos && s.find("vsyscall") == std::string::npos)
            {
                char* strend = &s[0];
                uint64_t start = strtoul(strend, &strend, 16);
                uint64_t end = strtoul(strend + 1, &strend, 16);
                if (start != 0 && end != 0 && start <= target && target < end) {
                    res.start = (void*)start;
                    res.end = (void*)end;

                    ++strend;
                    if (strend[0] == 'r')
                        (unsigned int&)res.rights |= mem_r;

                    if (strend[1] == 'w')
                        (unsigned int&)res.rights |= mem_w;

                    if (strend[2] == 'x')
                        (unsigned int&)res.rights |= mem_x;

                    break;
                }
            }
        }
        return res;
    }

    bool memory_protect(void* address, size_t size, memory_rights rights, memory_rights* old_rights)
    {
        region_infos_t infos = get_region_infos(address);
        bool res = mprotect(page_round(address, page_size()), page_addr_size(address, size, page_size()), memory_protect_rights_to_native(rights)) == 0;

        if (old_rights != nullptr)
            *old_rights = infos.rights;

        return res;
    }

    void memory_free(void* address, size_t size)
    {
        if (address != nullptr)
            munmap(address, size);
    }

    void* memory_alloc(void* address_hint, size_t size, memory_rights rights)
    {
        // TODO: Here find a way to allocate moemry near the address_hint.
        // Sometimes you get address too far for a relative jmp
        return mmap(address_hint, size, memory_protect_rights_to_native(rights), MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

    int flush_instruction_cache(void* address, size_t size)
    {
        return 1;
    }

#elif defined(MINIDETOUR_OS_WINDOWS)
    DWORD memory_protect_rights_to_native(memory_rights rights)
    {
        switch (rights)
        {
        case mem_r: return PAGE_READONLY;
        case mem_w: return PAGE_READWRITE;
        case mem_x: return PAGE_EXECUTE;
        case mem_rw: return PAGE_READWRITE;
        case mem_rx: return PAGE_EXECUTE_READ;
        case mem_wx: return PAGE_EXECUTE_READWRITE;
        case mem_rwx: return PAGE_EXECUTE_READWRITE;

        default: return PAGE_NOACCESS;
        }
    }

    memory_rights memory_native_to_protect_rights(DWORD rights)
    {
        switch (rights)
        {
        case PAGE_READONLY: return mem_r;
        case PAGE_READWRITE: return mem_rw;
        case PAGE_EXECUTE: return mem_x;
        case PAGE_EXECUTE_READ: return mem_rx;
        case PAGE_EXECUTE_READWRITE: return mem_rwx;
        default: return mem_none;
        }
    }

    size_t page_size()
    {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return sysInfo.dwPageSize;
    }

    region_infos_t get_region_infos(void* address)
    {
        MEMORY_BASIC_INFORMATION infos;
        region_infos_t res{};

        res.rights = mem_unset;
        if (VirtualQuery(address, &infos, sizeof(infos)) != 0)
        {
            res.start = infos.BaseAddress;
            res.end = (uint8_t*)res.start + infos.RegionSize;
            res.rights = memory_native_to_protect_rights(infos.Protect);
        }

        return res;
    }

    bool memory_protect(void* address, size_t size, memory_rights rights, memory_rights* old_rights)
    {
        DWORD oldProtect;
        bool res = VirtualProtect(address, size, memory_protect_rights_to_native(rights), &oldProtect) != FALSE;

        if (old_rights != nullptr)
            *old_rights = memory_native_to_protect_rights(oldProtect);

        return res;
    }

    void memory_free(void* address, size_t size)
    {
        if (address != nullptr)
            VirtualFree(address, 0, MEM_RELEASE);
    }

    void* memory_alloc(void* address_hint, size_t size, memory_rights rights)
    {
        MEMORY_BASIC_INFORMATION mbi;
        ZeroMemory(&mbi, sizeof(mbi));

        HANDLE hProcess = GetCurrentProcess();

        PBYTE pbBase = (PBYTE)address_hint;
        PBYTE pbLast = pbBase;
        for (;; pbLast = (PBYTE)mbi.BaseAddress + mbi.RegionSize)
        {

            ZeroMemory(&mbi, sizeof(mbi));
            if (VirtualQueryEx(hProcess, (PVOID)pbLast, &mbi, sizeof(mbi)) == 0)
                continue;

            // Usermode address space has such an unaligned region size always at the
            // end and only at the end.
            //
            if ((mbi.RegionSize & 0xfff) == 0xfff)
            {
                break;
            }

            // Skip anything other than a pure free region.
            //
            if (mbi.State != MEM_FREE)
                continue;

            // Use the max of mbi.BaseAddress and pbBase, in case mbi.BaseAddress < pbBase.
            PBYTE pbAddress = (PBYTE)mbi.BaseAddress > pbBase ? (PBYTE)mbi.BaseAddress : pbBase;

            // Round pbAddress up to the nearest MM allocation boundary.
            const DWORD_PTR mmGranularityMinusOne = (DWORD_PTR)(0x10000 - 1);
            pbAddress = (PBYTE)(((DWORD_PTR)pbAddress + mmGranularityMinusOne) & ~mmGranularityMinusOne);

            for (; pbAddress < (PBYTE)mbi.BaseAddress + mbi.RegionSize; pbAddress += 0x10000)
            {
                PBYTE pbAlloc = (PBYTE)VirtualAllocEx(hProcess, pbAddress, size,
                    MEM_RESERVE | MEM_COMMIT, memory_protect_rights_to_native(rights));

                if (pbAlloc == nullptr)
                    continue;

                return pbAlloc;
            }
        }

        return nullptr;
    }

    int flush_instruction_cache(void* pBase, size_t size)
    {
        return FlushInstructionCache(GetCurrentProcess(), pBase, size);
    }

#elif defined(MINIDETOUR_OS_APPLE)
    size_t memory_protect_rights_to_native(memory_rights rights)
    {
        switch (rights)
        {
        case mem_r: return VM_PROT_READ;
        case mem_w: return VM_PROT_WRITE;
        case mem_x: return VM_PROT_EXECUTE;
        case mem_rw: return VM_PROT_WRITE | VM_PROT_READ;
        case mem_rx: return VM_PROT_READ | VM_PROT_EXECUTE;
        case mem_wx: return VM_PROT_WRITE | VM_PROT_EXECUTE;
        case mem_rwx: return VM_PROT_WRITE | VM_PROT_READ | VM_PROT_EXECUTE;

        default: return VM_PROT_NONE;
        }
    }

    region_infos_t get_region_infos(void* address)
    {
        region_infos_t res{};

        mach_vm_address_t vm_address = (mach_vm_address_t)address;
        kern_return_t ret;
        mach_vm_size_t size;
        vm_region_basic_info_data_64_t infos;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name = MACH_PORT_NULL;

        ret = mach_vm_region(mach_task_self(), &vm_address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&infos, &count, &object_name);

        if (ret == KERN_SUCCESS)
        {
            res.start = (void*)vm_address;
            res.end = (void*)((uint64_t)vm_address + size);

            if (infos.protection & VM_PROT_READ)
                (unsigned int&)res.rights |= mem_r;

            if (infos.protection & VM_PROT_WRITE)
                (unsigned int&)res.rights |= mem_w;

            if (infos.protection & VM_PROT_EXECUTE)
                (unsigned int&)res.rights |= mem_x;
        }

        return res;
    }

    size_t page_size()
    {
        return sysconf(_SC_PAGESIZE);
    }

    bool memory_protect(void* address, size_t size, memory_rights rights, memory_rights* old_rights)
    {
        region_infos_t infos = get_region_infos(address);
        bool res = mach_vm_protect(mach_task_self(), (mach_vm_address_t)address, size, FALSE, memory_protect_rights_to_native(rights)) == KERN_SUCCESS;

        if (old_rights != nullptr)
            *old_rights = infos.rights;

        return res;
    }

    void memory_free(void* address, size_t size)
    {
        if (address != nullptr)
            mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)address, size);
    }

    void* memory_alloc(void* address_hint, size_t size, memory_rights rights)
    {
        mach_vm_address_t address = (mach_vm_address_t)0;
        size = (size_t)page_round_up((void*)size, page_size());

        mach_port_t task;
        task = mach_task_self();
        //task_for_pid(mach_task_self(), getpid(), &task);

        // VM_FLAGS_ANYWHERE allows for better compatibility as the Kernel will find a place for us.
        int flags = (address_hint == nullptr ? VM_FLAGS_ANYWHERE : VM_FLAGS_FIXED);

        kern_return_t res;

        if (flags == VM_FLAGS_ANYWHERE)
        {
            res = mach_vm_allocate(task, &address, (mach_vm_size_t)size, flags);
        }
        else
        {
#if defined(MINIDETOUR_ARCH_X64)
            void* max_user_address = (void*)0x7ffefffff000;
#elif defined(MINIDETOUR_ARCH_X86)
            void* max_user_address = (void*)0x70000000;
#endif

            if (address_hint > max_user_address)
                address_hint = max_user_address;

            region_infos_t infos = get_region_infos(address_hint);
            address = (mach_vm_address_t)infos.start;
            for (int i = 0; i < 100000; ++i, (uint8_t*&)address -= page_size())
            {
                res = mach_vm_allocate(task, &address, (mach_vm_size_t)size, flags);
                if (res == KERN_SUCCESS)
                    break;
            }
            if (res != KERN_SUCCESS)
            {
                address = (mach_vm_address_t)infos.end;
                for (int i = 0; i < 100000 && (void*)address < max_user_address; ++i, (uint8_t*&)address += page_size())
                {
                    res = mach_vm_allocate(task, &address, (mach_vm_size_t)size, flags);
                    if (res == KERN_SUCCESS)
                        break;
                }
            }
        }

        if (res == KERN_SUCCESS)
        {
            memory_protect((void*)address, size, rights);
        }
        else
        {
            address = 0;
        }

        return (void*)address;
    }

    int flush_instruction_cache(void* address, size_t size)
    {
        return 1;
    }

#endif

}

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)

////////////////////////////////////////////////////
/// Tiny disasm
bool is_opcode_terminating_function(void* pCode)
{
    switch (*(uint8_t*)pCode)
    {
        case 0xc2: // RETN imm16
        case 0xc3: // RETN
        case 0xc9: // LEAVE
        case 0xca: // RETF imm16
        case 0xcb: // RETF
        case 0xcc: // INT 3
        case 0xcd: // INT imm8
        case 0xce: // INTO eFlags
        case 0xcf: // IRET Flags
            return true;
    }
    return false;
}

int is_opcode_filler(uint8_t* pCode)
{
    if (pCode[0] == 0x90)
    {
        return 1;
    }
    if (pCode[0] == 0x66 && pCode[1] == 0x90)
    {
        return 2;
    }
    if (pCode[0] == 0x0F && pCode[1] == 0x1F && pCode[2] == 0x00)
    {
        return 3;
    }
    if (pCode[0] == 0x0F && pCode[1] == 0x1F && pCode[2] == 0x40 &&
        pCode[3] == 0x00)
    {
        return 4;
    }
    if (pCode[0] == 0x0F && pCode[1] == 0x1F && pCode[2] == 0x44 &&
        pCode[3] == 0x00 && pCode[4] == 0x00) {
        return 5;
    }
    if (pCode[0] == 0x66 && pCode[1] == 0x0F && pCode[2] == 0x1F &&
        pCode[3] == 0x44 && pCode[4] == 0x00 && pCode[5] == 0x00)
    {
        return 6;
    }
    if (pCode[0] == 0x0F && pCode[1] == 0x1F && pCode[2] == 0x80 &&
        pCode[3] == 0x00 && pCode[4] == 0x00 && pCode[5] == 0x00 &&
        pCode[6] == 0x00)
    {
        return 7;
    }
    if (pCode[0] == 0x0F && pCode[1] == 0x1F && pCode[2] == 0x84 &&
        pCode[3] == 0x00 && pCode[4] == 0x00 && pCode[5] == 0x00 &&
        pCode[6] == 0x00 && pCode[7] == 0x00)
    {
        return 8;
    }
    if (pCode[0] == 0x66 && pCode[1] == 0x0F && pCode[2] == 0x1F &&
        pCode[3] == 0x84 && pCode[4] == 0x00 && pCode[5] == 0x00 &&
        pCode[6] == 0x00 && pCode[7] == 0x00 && pCode[8] == 0x00)
    {
        return 9;
    }
    if (pCode[0] == 0x66 && pCode[1] == 0x66 && pCode[2] == 0x0F &&
        pCode[3] == 0x1F && pCode[4] == 0x84 && pCode[5] == 0x00 &&
        pCode[6] == 0x00 && pCode[7] == 0x00 && pCode[8] == 0x00 &&
        pCode[9] == 0x00)
    {
        return 10;
    }
    if (pCode[0] == 0x66 && pCode[1] == 0x66 && pCode[2] == 0x66 &&
        pCode[3] == 0x0F && pCode[4] == 0x1F && pCode[5] == 0x84 &&
        pCode[6] == 0x00 && pCode[7] == 0x00 && pCode[8] == 0x00 &&
        pCode[9] == 0x00 && pCode[10] == 0x00)
    {
        return 11;
    }
    // int 3.
    if (pCode[0] == 0xcc)
    {
        return 1;
    }

    return 0;
}

int read_mod_reg_rm_opcode(uint8_t* pCode, void** relocation)
{
    *relocation = nullptr;

    // MOD-REG-R/M Byte
    //  7 6    5 4 3    2 1 0 - bits
    //[ MOD ][  REG  ][  R/M  ]
    switch (pCode[1] & mod_mask) // Check MOD to know how many bytes we have after this opcode
    {
        case register_addressing_mode: return s_1byte_opcodes[*pCode].base_size; // register addressing mode [opcode] [R/M] [XX]
        case four_bytes_signed_displacement:
        {
            switch (pCode[1] & rm_mask)
            {
                case sib_with_no_displacement: return s_1byte_opcodes[*pCode].base_size + 5; // address mode byte + 4 bytes displacement
                default: return s_1byte_opcodes[*pCode].base_size + 4; // 4 bytes displacement
            }
        }
        break;

        case one_byte_signed_displacement:
        {
            switch (pCode[1] & rm_mask)
            {
                case sib_with_no_displacement: return s_1byte_opcodes[*pCode].base_size + 2; // address mode byte + 1 byte displacement
                default: return s_1byte_opcodes[*pCode].base_size + 1; // 1 byte displacement
            }
        }
        break;

        default:
            switch (pCode[1] & rm_mask)
            {
                case displacement_only_addressing:
                {
                    *relocation = pCode + s_1byte_opcodes[*pCode].base_size;
                    return s_1byte_opcodes[*pCode].base_size + 4; // 4 bytes Displacement only addressing mode
                }
                break;

                case sib_with_no_displacement: // SIB with no displacement
                {
                    if ((pCode[2] & 0x07) == 0x05)
                    {// Check this: No displacement, but there is if the low octal is 5 ?
                        return s_1byte_opcodes[*pCode].base_size + 5;
                    }
                    else
                    {
                        return s_1byte_opcodes[*pCode].base_size + 1;
                    }
                }
                break;

                case register_indirect_addressing_mode: // Register indirect addressing mode
                default: return s_1byte_opcodes[*pCode].base_size;
            }
    }


    // Never reached
    return 0;
}

int read_opcode(void* _pCode, void** relocation)
{
    uint8_t* pCode = (uint8_t*)_pCode;
    int code_len = 0;

    code_len = is_opcode_filler(pCode);
    if (code_len)
        return code_len;

    if (s_1byte_opcodes[*pCode].base_size == 0)
    {
        SPDLOG_DEBUG("Unknown opcode {:02x}", pCode[0]);
        SPDLOG_DEBUG("Next opcodes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}", pCode[1], pCode[2], pCode[3], pCode[4], pCode[5], pCode[6]);

        return 0;
    }

    if (s_1byte_opcodes[*pCode].has_r_m)
    {
        code_len = read_mod_reg_rm_opcode(pCode, relocation);
        SPDLOG_DEBUG("Opcode {}, base_size: {}, has_r_m: {}, opcode_size: {}",
            s_1byte_opcodes[*pCode].desc,
            (int)s_1byte_opcodes[*pCode].base_size,
            (int)s_1byte_opcodes[*pCode].has_r_m,
            code_len);
        return code_len;
    }
    else
    {
        SPDLOG_DEBUG("Opcode {}, size: {}", s_1byte_opcodes[*pCode].desc, (int)s_1byte_opcodes[*pCode].base_size);

        switch (*pCode)
        {
        case 0x0f: // 2 bytes opcode
            break;
#ifdef MINIDETOUR_ARCH_X64
        case 0x40: // REX
        case 0x41: // REX.B
        case 0x42: // REX.X
        case 0x43: // REX.XB
        case 0x44: // REX.R
        case 0x45: // REX.RB
        case 0x46: // REX.RX
        case 0x47: // REX.RXB
        case 0x48: // REX.W
        case 0x49: // REX.WB
        case 0x4a: // REX.WX
        case 0x4b: // REX.WXB
        case 0x4c: // REX.WR
        case 0x4d: // REX.WRB
        case 0x4e: // REX.WRX
        case 0x4f: // REX.WRXB
            return s_1byte_opcodes[*pCode].base_size + read_opcode(pCode + s_1byte_opcodes[*pCode].base_size, relocation); // REX works only with the next opcode, don't stop searching after a REX
#endif
        case 0x64: // FS:
        case 0x65: // GS:
            return s_1byte_opcodes[*pCode].base_size + read_opcode(pCode + s_1byte_opcodes[*pCode].base_size, relocation);

        case 0xe8: // CALL
            // we can relocate a CALL, need to be carefull tho
        case 0xe9: // JMP
            // we can relocate a JMP
            *relocation = pCode + 1;
            return s_1byte_opcodes[*pCode].base_size;

        case 0xf3: // REP
            // This is some weird opcode. Its size changes depending on the next opcode
            // TODO: need to look at this
            if (pCode[1] == 0x0f)
            {
                SPDLOG_DEBUG("REP: {:02x} {:02x} {:02x} {:02x}", pCode[0], pCode[1], pCode[2], pCode[3]);
                return 4;
            }
            return 0;

        case 0xff: // Extended
        {
            switch (pCode[1])
            {
                // Get the true function call
#ifdef MINIDETOUR_ARCH_X64
//    pCode = *reinterpret_cast<uint8_t**>(pCode + 6 + *(int32_t*)(pCode + 2)); // 2 opcodes + 4 relative address ptr
#else
//    pCode = **reinterpret_cast<uint8_t***>(pCode + 2); // 2 opcodes + 4 absolute address ptr
#endif
// Call
//case 0x15: return 6; //  This is an imported function
// JMP
            case 0x25: return 6; //  This is an imported function
            default: return 0; // Didn't manage the whole 2bytes opcode range.
            }
        }

        default:
            return s_1byte_opcodes[*pCode].base_size;
        }
    }

    // If we are here, then its a 2bytes opcode
    if (s_2bytes_opcodes[*(pCode + 1)].base_size == 0)
    {
        SPDLOG_DEBUG("Unknown 2bytes opcode {:02x} {:02x}", pCode[0], pCode[1]);
        SPDLOG_DEBUG("Next opcodes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}", pCode[2], pCode[3], pCode[4], pCode[5], pCode[6], pCode[7]);

        return 0;
    }

    ++pCode;
    if (s_2bytes_opcodes[*pCode].has_r_m)
    {
        code_len = read_mod_reg_rm_opcode(pCode, relocation);
        SPDLOG_DEBUG("Read {} bytes for 2bytes opcode {:02x} {:02x}", code_len, pCode[0], pCode[1]);
        return code_len;
    }
    else
    {
        return s_2bytes_opcodes[*pCode].base_size;
    }

    return 0;
}

///////////////////////////////////////////
// Tiny asm

inline uint8_t* relative_addr_to_absolute(int32_t rel_addr, uint8_t* source_addr)
{
    return source_addr + rel_addr + 5;
}

inline int32_t absolute_addr_to_relative(void* opcode_addr, void* destination_addr)
{
    return reinterpret_cast<uint8_t*>(destination_addr) - reinterpret_cast<uint8_t*>(opcode_addr) - 5;
}

void enter_recursive_thunk(uint8_t*& pCode)
{
    while (1)
    {
        // If its an imported function.      CALL                JUMP
        if (pCode[0] == 0xFF && (/*pCode[1] == 0x15 ||*/ pCode[1] == 0x25))
        {
            // Get the real imported function address
#ifdef MINIDETOUR_ARCH_X64
            pCode = *reinterpret_cast<uint8_t**>(pCode + 6 + *(int32_t*)(pCode + 2)); // 2 opcodes + 4 relative address ptr
#else
            pCode = **reinterpret_cast<uint8_t***>(pCode + 2); // 2 opcodes + 4 absolute address ptr
#endif
        }
        else if (pCode[0] == 0xe8 || pCode[0] == 0xe9)
        {
            pCode = relative_addr_to_absolute(*(int32_t*)(pCode + 1), pCode);
        }
        else
        {
            break;
        }
    }
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
            break;

        if (*tmp_relocation != nullptr)
        {
            // I can handle jmp and/or call
            if (*reinterpret_cast<uint8_t*>(pCode) == 0xe8)
            {
                //relocation_type = reloc_e::call;
                break; // Don't handle this kind of relocation for now
            }
            else if (*reinterpret_cast<uint8_t*>(pCode) == 0xe9)
            {
                //relocation_type = reloc_e::jmp;
                break; // Don't handle this kind of relocation for now
            }
            else
            {
                //relocation_type = reloc_e::other;
                break; // Don't handle this kind of relocation for now
            }
        }

        pCode = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(pCode) + opcode_size);
        relocatable_size += opcode_size;
    }

    return relocatable_size;
}

bool addresses_are_relative_jumpable(void* source, void* dest)
{
    uintptr_t min_addr = std::min((uintptr_t)source, (uintptr_t)dest);
    uintptr_t max_addr = std::max((uintptr_t)source, (uintptr_t)dest);

    return (max_addr - min_addr) <= 0x7FFFFFF0;
}

#elif defined(MINIDETOUR_ARCH_ARM) || defined(MINIDETOUR_ARCH_ARM64)

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
    // TODO
    return reinterpret_cast<uint8_t*>(destination_addr) - reinterpret_cast<uint8_t*>(opcode_addr) - 5;
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
    uintptr_t min_addr = std::min((uintptr_t)source, (uintptr_t)dest);
    uintptr_t max_addr = std::max((uintptr_t)source, (uintptr_t)dest);

#ifdef MINIDETOUR_ARCH_ARM64
    return (max_addr - min_addr) <= 0xFFFFFFC;
#elif
    return (max_addr - min_addr) <= 0x1FFFFFC;
#endif
}

#endif

struct memory_t
{
    uint8_t used;
#if MEMORY_PADDING != 0
    uint8_t padding[MEMORY_PADDING - sizeof(uint8_t)];
#endif
    uint8_t data[sizeof(void*) * 8 - 1];
};

class MemoryManager
{
    std::vector<void*> jumps_regions; // Jumps next to functions addresses   
    std::vector<memory_t*> trampolines_regions; // memory regions for trampolines

public:
    MemoryManager()
    {}

    ~MemoryManager()
    {
        for (auto& v : jumps_regions)
            memory_manipulation::memory_free(v, region_size());

        for (auto& v : trampolines_regions)
            memory_manipulation::memory_free(v, region_size());
    }

    void* AllocJumpsRegion(void* hint_addr)
    {
        void* jump = nullptr;

        jump = memory_manipulation::memory_alloc(hint_addr, region_size(), memory_manipulation::memory_rights::mem_rwx);

        if (jump != nullptr)
        {
            SPDLOG_INFO("{} | {}", hint_addr, jump);
            if (addresses_are_relative_jumpable(hint_addr, jump))
            {
                memset(jump, 0, region_size());

                // Protect trampoline region memory
                memory_manipulation::memory_protect(jump, region_size(), memory_manipulation::memory_rights::mem_rx);

                jumps_regions.emplace_back(jump);
            }
            else
            {
                memory_manipulation::memory_free(jump, region_size());
                jump = nullptr;
            }
        }

        return jump;
    }

    void* GetFreeJump(void* hint_addr)
    {
        constexpr uint8_t empty_region[abs_jump_t::GetMaxOpcodeSize()] = {};
        for (auto jumps_region : jumps_regions)
        {
            if (addresses_are_relative_jumpable(hint_addr, jumps_region))
            {
                for (int i = 0; i < jumps_in_region(); ++i)
                {
                    if (memcmp(jumps_region, empty_region, abs_jump_t::GetMaxOpcodeSize()) == 0)
                    {
                        return jumps_region;
                    }
                    jumps_region = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(jumps_region) + abs_jump_t::GetMaxOpcodeSize());
                }
            }
        }

        return AllocJumpsRegion(hint_addr);
    }

    void FreeJump(void* jump)
    {
        SPDLOG_DEBUG("Freeing jump {}", jump);

        if (!memory_manipulation::memory_protect(jump, abs_jump_t::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rwx))
            return;

        memset(jump, 0, abs_jump_t::GetMaxOpcodeSize());

        memory_manipulation::memory_protect(jump, abs_jump_t::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rx);
    }

    memory_t* AllocTrampolineRegion()
    {
        memory_t* mem = (memory_t*)memory_manipulation::memory_alloc(nullptr, region_size(), memory_manipulation::memory_rights::mem_rwx);
        if (mem == nullptr)
            return nullptr;

        trampolines_regions.emplace_back(mem);

        memset(mem, 0, region_size());

        return mem;
    }

    uint8_t* GetFreeTrampoline(size_t mem_size)
    {
        assert(mem_size <= sizeof(memory_t::data));
        uint8_t* res = nullptr;
        for (auto memory : trampolines_regions)
        {
            memory_t* end = memory + region_size() / sizeof(memory_t) + 1;
            for (; memory != end; ++memory)
            {
                if (!memory->used)
                {
                    SPDLOG_DEBUG("Using free memory at {}", (void*)memory);
                    if (!memory_manipulation::memory_protect(memory, sizeof(memory_t), memory_manipulation::memory_rights::mem_rwx))
                        return nullptr;

                    memory->used = 1;
                    memory_manipulation::memory_protect(memory, sizeof(memory_t), memory_manipulation::memory_rights::mem_rx);
                    return memory->data;
                }
            }
        }

        memory_t* mem_region = AllocTrampolineRegion();
        if (mem_region == nullptr)
            return nullptr;

        mem_region->used = 1;
        SPDLOG_DEBUG("Using new memory at {}", (void*)mem_region);

        return mem_region->data;
    }

    void FreeTrampoline(void* trampoline)
    {
        SPDLOG_DEBUG("Freeing trampoline {}", trampoline);
        memory_t* mem = reinterpret_cast<memory_t*>(reinterpret_cast<uint8_t*>(trampoline) - offsetof(memory_t, data));

        if (!memory_manipulation::memory_protect(mem, sizeof(memory_t), memory_manipulation::memory_rights::mem_rwx))
            return;
        mem->used = 0;

        memory_manipulation::memory_protect(mem, sizeof(memory_t), memory_manipulation::memory_rights::mem_rx);
    }
};

static MemoryManager mm;

inline size_t region_size()
{
    return memory_manipulation::page_size();
}

inline size_t jumps_in_region()
{
    return region_size() / abs_jump_t::GetMaxOpcodeSize();
}

inline void* library_address_by_handle(void* library)
{
    return (library == nullptr ? nullptr : *reinterpret_cast<void**>(library));
}

inline size_t page_addr_size(void* addr, size_t len, size_t page_size)
{
    uint8_t* start_addr = (uint8_t*)memory_manipulation::page_round(addr, page_size);
    uint8_t* end_addr = (uint8_t*)memory_manipulation::page_round_up((uint8_t*)addr + len, page_size);
    return end_addr - start_addr;
}

namespace mini_detour
{
    hook::hook() :
        _RestoreAddress(nullptr),
        _SavedCodeSize(0),
        _SavedCode(nullptr),
        _OriginalTrampolineAddress(nullptr),
        detour_func(nullptr),
        trampoline_address(nullptr),
        restore_on_destroy(true)
    {}

    hook::hook(hook&& other) noexcept
    {
        if (this != &other)
        {
            _RestoreAddress = std::move(other._RestoreAddress);
            _SavedCodeSize = std::move(other._SavedCodeSize);
            _SavedCode = std::move(other._SavedCode);
            _OriginalTrampolineAddress = std::move(other._OriginalTrampolineAddress);
            detour_func = std::move(other.detour_func);
            trampoline_address = std::move(other.trampoline_address);
            restore_on_destroy = std::move(other.restore_on_destroy);

            other.restore_on_destroy = false;
        }
    }

    hook& hook::operator=(hook&& other) noexcept
    {
        if (this != &other)
        {
            _RestoreAddress = std::move(other._RestoreAddress);
            _SavedCodeSize = std::move(other._SavedCodeSize);
            _SavedCode = std::move(other._SavedCode);
            _OriginalTrampolineAddress = std::move(other._OriginalTrampolineAddress);
            detour_func = std::move(other.detour_func);
            trampoline_address = std::move(other.trampoline_address);
            restore_on_destroy = std::move(other.restore_on_destroy);

            other.restore_on_destroy = false;
        }

        return *this;
    }

    hook::~hook()
    {
        if (restore_on_destroy)
        {
            restore_func();
        }
    }

    void hook::reset()
    {
        if (trampoline_address != nullptr)
        {// If we have a trampoline, clear it
            mm.FreeJump(trampoline_address);
            trampoline_address = nullptr;
        }

        mm.FreeTrampoline(_OriginalTrampolineAddress);
        free(_SavedCode);

        _RestoreAddress = nullptr;
        _SavedCodeSize = 0;
        _SavedCode = nullptr;
        _OriginalTrampolineAddress = nullptr;
        _OriginalFuncAddress = nullptr;
    }

    bool hook::can_hook(void* func)
    {
        if (_RestoreAddress != nullptr)
            return false;

        uint8_t* pCode = reinterpret_cast<uint8_t*>(func);
        void* relocation = nullptr;
        int relocatable_size = 0;

        enter_recursive_thunk(pCode);

        while (relocatable_size < std::min(abs_jump_t::GetOpcodeSize(func), rel_jump_t::GetOpcodeSize(func)))
        {
            int opcode_size = read_opcode(pCode, &relocation);
            //  Unknown opcode, break now
            if (opcode_size == 0 || is_opcode_terminating_function(pCode))
                break;

            if (relocation != nullptr)
            {
                // I can handle jmp and/or call
                if (*pCode == 0xe8)
                {
                    //relocation_type = reloc_e::call;
                    break; // Don't handle this kind of relocation for now
                }
                else if (*pCode == 0xe9)
                {
                    // Disable this for now
                    //relocatable_size += opcode_size;
                    //pCode += opcode_size;
                    break;
                }
                else
                {
                    //relocation_type = reloc_e::other;
                    break; // Don't handle this kind of relocation for now
                }
            }

            pCode += opcode_size;
            relocatable_size += opcode_size;
        }

        return relocatable_size >= std::min(abs_jump_t::GetOpcodeSize(pCode), rel_jump_t::GetOpcodeSize(pCode));
    }

    bool hook::replace_func(void* func, void* hook_func)
    {
        uint8_t* pCode = reinterpret_cast<uint8_t*>(func);
        size_t relocatable_size = 0;

        abs_jump_t abs_jump;

        enter_recursive_thunk(pCode);

        func = pCode;

        while (relocatable_size < std::min(abs_jump_t::GetOpcodeSize(hook_func), rel_jump_t::GetOpcodeSize(hook_func)))
        {
            void* tmp_relocation = nullptr;
            int opcode_size = read_opcode(pCode, &tmp_relocation);
            //  Unknown opcode, break now
            if (opcode_size == 0 || is_opcode_terminating_function(pCode))
                break;

            pCode += opcode_size;
            relocatable_size += opcode_size;
        }

        // can't even make a relative jump
        if (relocatable_size < std::min(abs_jump_t::GetOpcodeSize(pCode), rel_jump_t::GetOpcodeSize(pCode)))
            return false;

        if (!memory_manipulation::memory_protect(func, relocatable_size, memory_manipulation::memory_rights::mem_rwx))
            return false;

        if (relocatable_size >= abs_jump_t::GetOpcodeSize(pCode))
        {
            abs_jump_t hook_jump;
            hook_jump.SetAddr(hook_func);
            hook_jump.WriteOpcodes(func);

            memory_manipulation::memory_protect(func, hook_jump.GetOpcodeSize(), memory_manipulation::memory_rights::mem_rx);
            memory_manipulation::flush_instruction_cache(func, hook_jump.GetOpcodeSize());
        }
        else
        {
            // Setup the trampoline
            void* jump_mem = mm.GetFreeJump(func);
            if (jump_mem == nullptr)
                return false;

            if (!memory_manipulation::memory_protect(jump_mem, abs_jump_t::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rwx))
            {
                mm.FreeJump(jump_mem);
                return false;
            }

            abs_jump.SetAddr(hook_func);
            abs_jump.WriteOpcodes(jump_mem);

            memory_manipulation::memory_protect(jump_mem, abs_jump_t::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rx);
            memory_manipulation::flush_instruction_cache(jump_mem, abs_jump_t::GetMaxOpcodeSize());

            rel_jump_t hook_jump;
            hook_jump.SetAddr((intptr_t)func - (intptr_t)jump_mem);
            hook_jump.WriteOpcodes(func);
        }

        memory_manipulation::memory_protect(func, relocatable_size, memory_manipulation::memory_rights::mem_rx);
        memory_manipulation::flush_instruction_cache(func, relocatable_size);

        return true;

    }

    void* hook::hook_func(void* func, void* detour_func)
    {
        if (_OriginalTrampolineAddress != nullptr)
            return _OriginalTrampolineAddress;

        this->detour_func = detour_func;

        _OriginalFuncAddress = func;
        uint8_t* pCode = reinterpret_cast<uint8_t*>(func);
        size_t relocatable_size = 0;

        size_t total_original_trampoline_size = 0;
        abs_jump_t abs_jump;

        enter_recursive_thunk(pCode);

        void* tmp_relocation;
        relocatable_size = get_relocatable_size(pCode, &tmp_relocation, abs_jump_t::GetOpcodeSize(detour_func));

        SPDLOG_INFO("Needed relocatable size: found({}), rel({}), abs({})", relocatable_size, rel_jump_t::GetOpcodeSize(pCode), abs_jump_t::GetOpcodeSize(pCode));

        if (relocatable_size < std::min(abs_jump_t::GetOpcodeSize(detour_func), rel_jump_t::GetOpcodeSize(detour_func)))
        {
            SPDLOG_ERROR("Relocatable size was too small {} < {}", relocatable_size, std::min(abs_jump_t::GetOpcodeSize(pCode), rel_jump_t::GetOpcodeSize(pCode)));
            goto error;
        }

        _SavedCodeSize = relocatable_size;
        _SavedCode = (uint8_t*)malloc(sizeof(uint8_t) * relocatable_size);
        if (_SavedCode == nullptr)
            goto error;

        // Save the original code
        memcpy(_SavedCode, pCode, _SavedCodeSize);

        // The total number of bytes to copy from the original function + abs jump for trampoline
        abs_jump.SetAddr(pCode + _SavedCodeSize);
        total_original_trampoline_size = _SavedCodeSize + abs_jump.GetOpcodeSize();

        _OriginalTrampolineAddress = mm.GetFreeTrampoline(total_original_trampoline_size);
        if (_OriginalTrampolineAddress == nullptr)
            goto error;

        // RWX on our original trampoline func
        if (!memory_manipulation::memory_protect(_OriginalTrampolineAddress, total_original_trampoline_size, memory_manipulation::memory_rights::mem_rwx))
            goto error;

        // RWX on the orignal func
        if (!memory_manipulation::memory_protect(pCode, _SavedCodeSize, memory_manipulation::memory_rights::mem_rwx))
            goto error;

        // Copy the original code
        memcpy(_OriginalTrampolineAddress, pCode, _SavedCodeSize);

        // Write the absolute jump
        abs_jump.WriteOpcodes(reinterpret_cast<uint8_t*>(_OriginalTrampolineAddress) + _SavedCodeSize);

        if (relocatable_size >= abs_jump_t::GetOpcodeSize(pCode))
        {
            SPDLOG_INFO("Absolute hook {} >= {}", relocatable_size, abs_jump_t::GetOpcodeSize(pCode));

            abs_jump.SetAddr(detour_func);
            abs_jump.WriteOpcodes(pCode);
        }
        else
        {
            SPDLOG_INFO("Relative hook");

            // Setup the trampoline
            void* jump_mem = mm.GetFreeJump(func);
            if (jump_mem == nullptr)
                goto error;

            if (!memory_manipulation::memory_protect(jump_mem, abs_jump_t::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rwx))
            {
                mm.FreeJump(jump_mem);
                goto error;
            }

            abs_jump.SetAddr(detour_func);
            abs_jump.WriteOpcodes(jump_mem);

            memory_manipulation::memory_protect(jump_mem, abs_jump_t::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rx);
            memory_manipulation::flush_instruction_cache(jump_mem, abs_jump_t::GetMaxOpcodeSize());

            rel_jump_t hook_jump;
            hook_jump.SetAddr(absolute_addr_to_relative(pCode, jump_mem));
            hook_jump.WriteOpcodes(pCode);

            trampoline_address = jump_mem;
        }

        // Try to restore memory rights, if it fails, no problem, we are just a bit too permissive
        memory_manipulation::memory_protect(_OriginalTrampolineAddress, total_original_trampoline_size, memory_manipulation::memory_rights::mem_rx);
        memory_manipulation::flush_instruction_cache(_OriginalTrampolineAddress, total_original_trampoline_size);

        memory_manipulation::memory_protect(pCode, relocatable_size, memory_manipulation::memory_rights::mem_rx);
        memory_manipulation::flush_instruction_cache(pCode, relocatable_size);

        _RestoreAddress = pCode;

        return _OriginalTrampolineAddress;
    error:
        _RestoreAddress = nullptr;
        _SavedCodeSize = 0;
        if (_SavedCode != nullptr)
        {
            free(_SavedCode);
            _SavedCode = nullptr;
        }
        if (_OriginalTrampolineAddress != nullptr)
        {
            mm.FreeTrampoline(_OriginalTrampolineAddress);
            _OriginalTrampolineAddress = nullptr;
        }

        _OriginalFuncAddress = nullptr;

        return nullptr;
    }

    void* hook::restore_func()
    {
        void* res = nullptr;
        if (_RestoreAddress == nullptr)
            return res;

        if (!memory_manipulation::memory_protect(_RestoreAddress, _SavedCodeSize, memory_manipulation::memory_rights::mem_rwx))
            return res;

        SPDLOG_INFO("Restoring hook");

        memcpy(_RestoreAddress, _SavedCode, _SavedCodeSize);
        memory_manipulation::memory_protect(_RestoreAddress, _SavedCodeSize, memory_manipulation::memory_rights::mem_rx);
        memory_manipulation::flush_instruction_cache(_RestoreAddress, _SavedCodeSize);

        SPDLOG_INFO("Restored hook");

        res = _OriginalFuncAddress;
        reset();

        return res;
    }
}

//------------------------------------------------------------------------------//


/* ------ DOCUMENTATION ------
http://www.c-jump.com/CIS77/CPU/x86/lecture.html                <- some help to understand [MOD][REG][R/M] (see paragraph #6)
http://shell-storm.org/online/Online-Assembler-and-Disassembler <- online assembler
http://ref.x86asm.net/coder32.html                              <- opcodes reference

X86

push ebx     : 0x53
sub  esp ??  : 0x83 0xEC 0x??
call ????????: 0xE8 0x?? 0x?? 0x?? 0x??


// relative jmp: ???????? = dst_addr - curr_addr - 5
jmp ???????? : 0xe9 0x?? 0x?? 0x?? 0x??
destination = 0x8dba8
jmp location: 0x91995 - opcodes: e9 0e c2 ff ff
0e c2 ff ff = 0x8dba8 - 0x91995 - 5

// short jmp: ?? = dst_addr - curr_addr - 2
jmp short ??: 0xeb 0x??
destination = 0x91964
jmp location: 0x9198f - opcodes: 0xeb 0xd3
d3 = 0x91964 - 0x9198f - 2

X64
Reuse x86 relative jmp method to jmp to trampoline
From trampoline make an absolute jmp

Example:
Trampoline Addr 0x20000:
FuncToHook 0x10000:

FuncToHook Code:
0x90 NOP
0x90 NOP
0x90 NOP
0x90 NOP
0x90 NOP

Hook The Func:
FuncToHook Code:
0xE9 JMP
0xFB Relative Hook Addr
0xFF Relative Hook Addr
0x00 Relative Hook Addr
0x00 Relative Hook Addr

AArch64 // Need to align code on 4 bytes address (opcode are 4bytes fixed length)

Registers 	Description
X0 – X7     arguments and return value
X8 – X18    temporary registers
X19 – X28   callee-saved registers
X29         frame pointer
X30         link register
SP          stack pointer

ldr x8, #8 // 48 00 00 58 : Load value at PointerCode + 8 into x8
br  x8     // 00 01 1F D6 : Branch to value in x8
XX XX XX XX XX XX XX XX // Value at PointerCode + 8

movz // Load 16 bits imm into register with zero padding

movk // Load 16 bits imm into register with shift
movk R, #IMM16, Shift

movz:
Byte 1
11010010: d2

100XXXXX: X: 5 bits IMM16

XXXXXXXX: X: 8 bits IMM16

XXXYYYYY: X: 3bits IMM16 Y: 5 bits register select



Load 0xcdef89ab45670123 into x0:
11110010

movk x0, #0x0123, lsl 0
movk x0, #0x4567, lsl 16
movk x0, #0x89ab, lsl 32
movk x0, #0xcdef, lsl 48

*/
