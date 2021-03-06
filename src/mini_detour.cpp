#include <mini_detour/mini_detour.h>

#include <assert.h>
#include <string.h>

#include <algorithm>
#include <limits>
#include <utility>
#include <type_traits> // std::move
#include <fstream>
#include <string>

#ifdef USE_SPDLOG
	#include <spdlog/spdlog.h>
#else
	#define SPDLOG_DEBUG(...)
	#define SPDLOG_ERROR(...)
	#define SPDLOG_INFO(...)
#endif

#if defined(WIN64) || defined(_WIN64) || defined(__MINGW64__)
    #define MINIDETOUR_OS_WINDOWS
    #define MINIDETOUR_ARCH_X64
#elif defined(WIN32) || defined(_WIN32) || defined(__MINGW32__)
    #define MINIDETOUR_OS_WINDOWS
    #define MINIDETOUR_ARCH_X86
#elif defined(__linux__) || defined(linux)
    #if defined(__x86_64__)
        #define MINIDETOUR_OS_LINUX
        #define MINIDETOUR_ARCH_X64
    #else
        #define MINIDETOUR_OS_LINUX
        #define MINIDETOUR_ARCH_X86
    #endif
#elif defined(__APPLE__)
    #if defined(__x86_64__)
        #define MINIDETOUR_OS_APPLE
        #define MINIDETOUR_ARCH_X64
    #else
        #define MINIDETOUR_OS_APPLE
        #define MINIDETOUR_ARCH_X86
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
    static constexpr uint8_t code[] = { 0xFF, 0x25,
                                        0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t  jmp[2];   // FF 25
    uint32_t rip;      // 00 00 00 00 (rip + 0x00000000)
    void*    abs_addr; // XX XX XX XX XX XX XX XX

    abs_jump_t():
        jmp{0xFF, 0x25},
        rip(0x00000000),
        abs_addr(nullptr)
    {}
};

struct rel_jump_t
{
    static constexpr uint8_t code[] = { 0xE9,
                                        0x00, 0x00, 0x00, 0x00 };
    uint8_t jmp;       // E9
    uint32_t rel_addr; // XX XX XX XX

    rel_jump_t():
        jmp(0xe9),
        rel_addr(0x00000000)
    {}
};
#pragma pack(pop)

#elif defined(MINIDETOUR_ARCH_X86)
#include "mini_detour_x86.h"

#pragma pack(push, 1)
struct abs_jump_t
{
    static constexpr uint8_t code[] = { 0x68,
                                        0x00, 0x00, 0x00, 0x00,
                                        0xC3};
    uint8_t push;     // PUSH
    void*   abs_addr; // XX XX XX XX
    uint8_t ret;      // RET

    abs_jump_t():
        push(0x68),
        abs_addr(nullptr),
        ret(0xc3)
    {}
};

struct rel_jump_t
{
    static constexpr uint8_t code[] = { 0xE9,
                                        0x00, 0x00, 0x00, 0x00 };
    uint8_t jmp;       // E9
    uint32_t rel_addr; // XX XX XX XX

    rel_jump_t() :
        jmp(0xe9),
        rel_addr(0x00000000)
    {}
};
#pragma pack(pop)

#endif

constexpr decltype(abs_jump_t::code) abs_jump_t::code;
constexpr decltype(rel_jump_t::code) rel_jump_t::code;

namespace memory_manipulation {

#if defined(MINIDETOUR_OS_LINUX)
int memory_protect_rights_to_native(memory_rights rights)
{
    switch(rights)
    {
        case mem_r  : return PROT_READ;
        case mem_w  : return PROT_WRITE;
        case mem_x  : return PROT_EXEC;
        case mem_rw : return PROT_WRITE | PROT_READ;
        case mem_rx : return PROT_READ  | PROT_EXEC;
        case mem_wx : return PROT_WRITE | PROT_EXEC;
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
    switch(rights)
    {
        case mem_r  : return PAGE_READONLY;
        case mem_w  : return PAGE_READWRITE;
        case mem_x  : return PAGE_EXECUTE;
        case mem_rw : return PAGE_READWRITE;
        case mem_rx : return PAGE_EXECUTE_READ;
        case mem_wx : return PAGE_EXECUTE_READWRITE;
        case mem_rwx: return PAGE_EXECUTE_READWRITE;

        default: return PAGE_NOACCESS;
    }
}

memory_rights memory_native_to_protect_rights(DWORD rights)
{
    switch (rights)
    {
        case PAGE_READONLY         : return mem_r  ;
        case PAGE_READWRITE        : return mem_rw ; 
        case PAGE_EXECUTE          : return mem_x  ; 
        case PAGE_EXECUTE_READ     : return mem_rx ; 
        case PAGE_EXECUTE_READWRITE: return mem_rwx;
        default                    : return mem_none;
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
    switch(rights)
    {
        case mem_r  : return VM_PROT_READ;
        case mem_w  : return VM_PROT_WRITE;
        case mem_x  : return VM_PROT_EXECUTE;
        case mem_rw : return VM_PROT_WRITE | VM_PROT_READ;
        case mem_rx : return VM_PROT_READ | VM_PROT_EXECUTE;
        case mem_wx : return VM_PROT_WRITE | VM_PROT_EXECUTE;
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

    if(flags == VM_FLAGS_ANYWHERE)
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
        for(int i = 0; i < 100000; ++i, (uint8_t*&)address -= page_size() )
        {
            res = mach_vm_allocate(task, &address, (mach_vm_size_t)size, flags);
            if(res == KERN_SUCCESS)
                break;
        }
        if(res != KERN_SUCCESS)
        {
            address = (mach_vm_address_t)infos.end;
            for(int i = 0; i < 100000 && (void*)address < max_user_address; ++i, (uint8_t*&)address += page_size() )
            {
                res = mach_vm_allocate(task, &address, (mach_vm_size_t)size, flags);
                if(res == KERN_SUCCESS)
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

struct memory_t
{
    uint8_t used;
#ifdef MINIDETOUR_ARCH_X64
    uint8_t data[63];
#else
    uint8_t data[31];
#endif
};

struct memory_region_t
{
    memory_t* mem_addr;

    memory_region_t():
        mem_addr(nullptr)
    {}
};

class MemoryManager
{
    size_t jumps_regions_size;
    abs_jump_t** jumps_regions; // Jumps next to functions addresses
    size_t memory_regions_size;
    memory_region_t* memory_regions; // memory regions for trampolines

public:
    MemoryManager():
        jumps_regions_size(0),
        jumps_regions(nullptr),
        memory_regions_size(0),
        memory_regions(nullptr)
    {}

    abs_jump_t* AllocJumpsRegion(void* hint_addr)
    {
        abs_jump_t* jump = nullptr;

        jump = reinterpret_cast<abs_jump_t*>(memory_manipulation::memory_alloc(hint_addr, region_size(), memory_manipulation::memory_rights::mem_rwx));

        if (jump != nullptr)
        {
            uint64_t high = (uint64_t)std::max((void*)jump, hint_addr);
            uint64_t low  = (uint64_t)std::min((void*)jump, hint_addr);

            if((high - low) > std::numeric_limits<int32_t>::max())
            {
                memory_manipulation::memory_free(jump, region_size());
                jump = nullptr;
            }
        }

        if (jump)
        {
            size_t max_jumps = jumps_in_region();
            for (int i = 0; i < max_jumps; ++i)
            {// Setup the whole jumps region, user will only have to provide the absolute address
                memcpy(jump + i, abs_jump_t::code, sizeof(abs_jump_t));
            }
            // Protect trampoline region memory
            memory_manipulation::memory_protect(jump, region_size(), memory_manipulation::memory_rights::mem_rx);

            abs_jump_t** new_jumps = (abs_jump_t**)realloc(jumps_regions, sizeof(abs_jump_t*) * (jumps_regions_size + 1));
            if (new_jumps == nullptr)
            {
                memory_manipulation::memory_free(jump, region_size());
                return nullptr;
            }

            jumps_regions = new_jumps;
            jumps_regions[jumps_regions_size++] = jump;
        }

        return jump;
    }

    abs_jump_t* GetFreeJump(void* hint_addr)
    {
        for (int i = 0; i < jumps_regions_size; ++i)
        {
            auto jumps_region = jumps_regions[i];
            uint64_t high = (uint64_t)std::max((void*)jumps_region, hint_addr);
            uint64_t low = (uint64_t)std::min((void*)jumps_region, hint_addr);

            if ((high - low) <= std::numeric_limits<int32_t>::max())
            {
                for (int i = 0; i < jumps_in_region(); ++i)
                {
                    if (jumps_region->abs_addr == 0)
                    {
                        return jumps_region;
                    }
                    ++jumps_region;
                }
            }
        }

        return AllocJumpsRegion(hint_addr);
    }

    memory_region_t* AllocMemoryRegion()
    {
        memory_region_t* new_region = (memory_region_t*)realloc(memory_regions, sizeof(memory_region_t) * (memory_regions_size + 1));
        if (new_region == nullptr)
            return nullptr;

        memory_regions = new_region;
        memory_region_t& region = memory_regions[memory_regions_size++];
        region.mem_addr = (memory_t*)memory_manipulation::memory_alloc(nullptr, region_size(), memory_manipulation::memory_rights::mem_rwx);
        memset(region.mem_addr, 0, region_size());

        return &region;
    }

    uint8_t* GetFreeMemory(size_t mem_size)
    {
        assert(mem_size <= sizeof(memory_t::data));
        uint8_t* res = nullptr;
        for (int i = 0; i < memory_regions_size; ++i)
        {
            memory_t* mem = memory_regions[i].mem_addr;
            memory_t* end = mem + region_size() / sizeof(memory_t) + 1;
            for (; mem != end; ++mem)
            {
                if (!mem->used)
                {
                    SPDLOG_DEBUG("Using free memory at {}", (void*)mem);
                    if (!memory_manipulation::memory_protect(mem, sizeof(memory_t), memory_manipulation::memory_rights::mem_rwx))
                        return nullptr;

                    mem->used = 1;
                    memory_manipulation::memory_protect(mem, sizeof(memory_t), memory_manipulation::memory_rights::mem_rx);
                    return mem->data;
                }
            }
        }

        memory_region_t* mem_region = AllocMemoryRegion();
        if (mem_region == nullptr)
            return nullptr;

        mem_region->mem_addr->used = 1;
        SPDLOG_DEBUG("Using new memory at {}", (void*)mem_region->mem_addr);

        return mem_region->mem_addr->data;
    }

    void FreeMemory(void* memory)
    {
        SPDLOG_DEBUG("Freeing memory {}", memory);
        memory_t* mem = reinterpret_cast<memory_t*>(reinterpret_cast<uint8_t*>(memory)- 1);

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
    return region_size() / sizeof(abs_jump_t);
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

inline uint8_t* relative_addr_to_absolute(int32_t rel_addr, uint8_t* source_addr)
{
    return source_addr + rel_addr + 5;
}

inline int32_t absolute_addr_to_relative(uint8_t* opcode_addr, uint8_t* destination_addr)
{
    return destination_addr - opcode_addr - 5;
}

////////////////////////////////////////////////////
/// Tiny disasm

bool is_opcode_terminating_function(uint8_t opcode)
{
    switch (opcode)
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

int read_mod_reg_rm_opcode(uint8_t* pCode, uint8_t** relocation)
{
    *relocation = nullptr;

    // MOD-REG-R/M Byte
    //  7 6    5 4 3    2 1 0 - bits
    //[ MOD ][  REG  ][  R/M  ]
    switch (pCode[1] & mod_mask) // Check MOD to know how many bytes we have after this opcode
    {
        case register_addressing_mode      : return s_1byte_opcodes[*pCode].base_size; // register addressing mode [opcode] [R/M] [XX]
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

                case sib_with_no_displacement         : // SIB with no displacement
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

int read_opcode(uint8_t* pCode, uint8_t** relocation)
{
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
                    default  : return 0; // Didn't manage the whole 2bytes opcode range.
                }
            }

            default:
                return s_1byte_opcodes[*pCode].base_size;
        }
    }

    // If we are here, then its a 2bytes opcode
    if (s_2bytes_opcodes[*(pCode+1)].base_size == 0)
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

inline uint8_t* gen_absolute_jmp(uint8_t* opcode_addr, uint8_t* dest)
{
    return dest;
}

inline uint8_t* gen_relative_jmp(uint8_t* opcode_addr, uint8_t* dest)
{
    return dest - (uint64_t)(opcode_addr + relative_addr_size);
}

namespace mini_detour
{
    hook::hook():
        restore_address(nullptr),
        saved_code_size(0),
        saved_code(nullptr),
        original_trampoline_address(nullptr),
        detour_func(nullptr),
        trampoline_address(nullptr),
        restore_on_destroy(true)
    {}

    hook::hook(hook&& other) noexcept
    {
        if (this != &other)
        {
            restore_address             = std::move(other.restore_address);
            saved_code_size             = std::move(other.saved_code_size);
            saved_code                  = std::move(other.saved_code);
            original_trampoline_address = std::move(other.original_trampoline_address);
            detour_func                 = std::move(other.detour_func);
            trampoline_address          = std::move(other.trampoline_address);
            restore_on_destroy          = std::move(other.restore_on_destroy);

            other.restore_on_destroy = false;
        }
    }

    hook& hook::operator=(hook&& other) noexcept
    {
        if (this != &other)
        {
            restore_address             = std::move(other.restore_address);
            saved_code_size             = std::move(other.saved_code_size);
            saved_code                  = std::move(other.saved_code);
            original_trampoline_address = std::move(other.original_trampoline_address);
            detour_func                 = std::move(other.detour_func);
            trampoline_address          = std::move(other.trampoline_address);
            restore_on_destroy          = std::move(other.restore_on_destroy);

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
            if (memory_manipulation::memory_protect(trampoline_address, sizeof(*trampoline_address), memory_manipulation::memory_rights::mem_rwx))
            {// If it fails, we can't do much, memory leak of sizeof(abs_jmp_t)
                trampoline_address->abs_addr = nullptr;
                memory_manipulation::flush_instruction_cache(trampoline_address, sizeof(*trampoline_address));
                memory_manipulation::memory_protect(trampoline_address, sizeof(*trampoline_address), memory_manipulation::memory_rights::mem_rx);
            }
            trampoline_address = nullptr;
        }

        mm.FreeMemory(original_trampoline_address);
        mm.FreeMemory(saved_code);

        restore_address = nullptr;
        saved_code_size = 0;
        saved_code = 0;
        original_trampoline_address = nullptr;
        orignal_func_address = nullptr;
    }

    bool hook::can_hook(void* func)
    {
        if (restore_address != nullptr)
            return false;

        uint8_t* pCode = reinterpret_cast<uint8_t*>(func);
        uint8_t* relocation = nullptr;
        int relocatable_size = 0;

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

        while (relocatable_size < sizeof(abs_jump_t))
        {
            int opcode_size = read_opcode(pCode, &relocation);
            //  Unknown opcode, break now
            if (opcode_size == 0 || is_opcode_terminating_function(*pCode))
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

        // Check both cases, maybe someday the relative jump will be bigger than absolute jump
        return (relocatable_size >= sizeof(abs_jump_t) && relocatable_size >= sizeof(rel_jump_t));
    }

    bool hook::replace_func(void* func, void* hook_func)
    {
        uint8_t* pCode = reinterpret_cast<uint8_t*>(func);
        size_t relocatable_size = 0;

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

        func = pCode;

        while (relocatable_size < sizeof(abs_jump_t))
        {
            uint8_t* tmp_relocation = nullptr;
            int opcode_size = read_opcode(pCode, &tmp_relocation);
            //  Unknown opcode, break now
            if (opcode_size == 0 || is_opcode_terminating_function(*pCode))
                break;

            pCode += opcode_size;
            relocatable_size += opcode_size;
        }

        // can't even make a relative jump
        if (relocatable_size < sizeof(rel_jump_t))
            return false;

        if(!memory_manipulation::memory_protect(func, relocatable_size, memory_manipulation::memory_rights::mem_rwx))
            return false;

        if (relocatable_size >= sizeof(abs_jump_t))
        {
            abs_jump_t hook_jump;
            hook_jump.abs_addr = hook_func;
            // Write the jump
            memcpy(func, &hook_jump, sizeof(hook_jump));
            memory_manipulation::memory_protect(func, sizeof(hook_jump), memory_manipulation::memory_rights::mem_rx);
            memory_manipulation::flush_instruction_cache(func, sizeof(abs_jump_t));
        }
        else
        {
            // Setup the trampoline
            abs_jump_t* abs_jump = mm.GetFreeJump(func);
            if (abs_jump == nullptr)
                return false;

            if (!memory_manipulation::memory_protect(abs_jump, sizeof(*abs_jump), memory_manipulation::memory_rights::mem_rwx))
            {
                mm.FreeMemory(abs_jump);
                return false;
            }

            abs_jump->abs_addr = hook_func;
            memory_manipulation::memory_protect(abs_jump, sizeof(*abs_jump), memory_manipulation::memory_rights::mem_rx);
            memory_manipulation::flush_instruction_cache(abs_jump, sizeof(*abs_jump));

            rel_jump_t hook_jump;
            hook_jump.rel_addr = absolute_addr_to_relative((uint8_t*)func, (uint8_t*)abs_jump);

            // Write the jump
            memcpy(func, &hook_jump, sizeof(hook_jump));
        }

        memory_manipulation::memory_protect(func, relocatable_size, memory_manipulation::memory_rights::mem_rx);
        memory_manipulation::flush_instruction_cache(func, relocatable_size);

        return true;

    }

    void* hook::hook_func(void* func, void* detour_func)
    {
        if (original_trampoline_address != nullptr)
            return original_trampoline_address;

        this->detour_func = detour_func;

        orignal_func_address = func;
        uint8_t* pCode = reinterpret_cast<uint8_t*>(func);
        size_t relocatable_size = 0;

        size_t original_trampoline_size = 0;
        size_t total_original_trampoline_size = 0;
        abs_jump_t* jump = nullptr;

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

        restore_address = pCode;

        uint8_t* tmp_relocation = nullptr;
        while (relocatable_size < sizeof(abs_jump_t))
        {
            int opcode_size = read_opcode(pCode, &tmp_relocation);
            //  Unknown opcode, break now
            if (opcode_size == 0 || is_opcode_terminating_function(*pCode))
                break;

            if (tmp_relocation != nullptr)
            {
                // I can handle jmp and/or call
                if (*pCode == 0xe8)
                {
                    //relocation_type = reloc_e::call;
                    break; // Don't handle this kind of relocation for now
                }
                else if (*pCode == 0xe9)
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

            pCode += opcode_size;
            relocatable_size += opcode_size;
        }

        if (relocatable_size < sizeof(rel_jump_t))
        {
            SPDLOG_ERROR("Relocatable size was too small {} < {}", relocatable_size, sizeof(rel_jump_t));
            goto error;
        }

        saved_code_size = relocatable_size;
        saved_code = mm.GetFreeMemory(saved_code_size);
        if (saved_code == nullptr)
            goto error;

        if(!memory_manipulation::memory_protect(saved_code, saved_code_size, memory_manipulation::memory_rights::mem_rwx))
            goto error;

        // Save the original code
        memcpy(saved_code, restore_address, saved_code_size);
        memory_manipulation::memory_protect(saved_code, saved_code_size, memory_manipulation::memory_rights::mem_rx);

        // The number of bytes to copy from the original function for trampoline
        original_trampoline_size = relocatable_size;
        // The total number of bytes to copy from the original function + abs jump for trampoline
        total_original_trampoline_size = original_trampoline_size + sizeof(abs_jump_t);

        original_trampoline_address = mm.GetFreeMemory(total_original_trampoline_size);
        if (original_trampoline_address == nullptr)
            goto error;

        // RWX on our original trampoline funx
        if (!memory_manipulation::memory_protect(original_trampoline_address, total_original_trampoline_size, memory_manipulation::memory_rights::mem_rwx))
            goto error;

        // RWX on the orignal func
        if (!memory_manipulation::memory_protect(restore_address, relocatable_size, memory_manipulation::memory_rights::mem_rwx))
            goto error;

        // Copy the original code
        memcpy(original_trampoline_address, restore_address, original_trampoline_size);

        // Get the absolute jump
        jump = reinterpret_cast<abs_jump_t*>((reinterpret_cast<uint8_t*>(original_trampoline_address) + original_trampoline_size));
        memcpy(jump, abs_jump_t::code, sizeof(abs_jump_t::code));

        // Set the jump address to the original code
        jump->abs_addr = reinterpret_cast<uint8_t*>(restore_address) + saved_code_size;

        if (relocatable_size >= sizeof(abs_jump_t))
        {
            SPDLOG_INFO("Absolute hook {} >= {}", relocatable_size, sizeof(abs_jump_t));

            abs_jump_t hook_jump;
            hook_jump.abs_addr = detour_func;
            // Write the jump
            memcpy(restore_address, &hook_jump, sizeof(hook_jump));
        }
        else
        {
            SPDLOG_INFO("Relative hook");

            // Setup the trampoline
            abs_jump_t* abs_jump = mm.GetFreeJump(restore_address);
            if (abs_jump == nullptr)
                goto error;

            if (!memory_manipulation::memory_protect(abs_jump, sizeof(*abs_jump), memory_manipulation::memory_rights::mem_rwx))
                goto error;

            abs_jump->abs_addr = detour_func;
            memory_manipulation::memory_protect(abs_jump, sizeof(*abs_jump), memory_manipulation::memory_rights::mem_rx);
            memory_manipulation::flush_instruction_cache(abs_jump, sizeof(*abs_jump));

            rel_jump_t hook_jump;
            hook_jump.rel_addr = absolute_addr_to_relative((uint8_t*)restore_address, (uint8_t*)abs_jump);

            // Write the jump
            memcpy(restore_address, &hook_jump, sizeof(hook_jump));

            trampoline_address = abs_jump;
        }

        // Try to restore memory rights, if it fails, no problem, we are just a bit too permissive
        memory_manipulation::memory_protect(original_trampoline_address, total_original_trampoline_size, memory_manipulation::memory_rights::mem_rx);
        memory_manipulation::flush_instruction_cache(original_trampoline_address, total_original_trampoline_size);

        memory_manipulation::memory_protect(restore_address, relocatable_size, memory_manipulation::memory_rights::mem_rx);
        memory_manipulation::flush_instruction_cache(restore_address, relocatable_size);

        return original_trampoline_address;
    error:
        restore_address = nullptr;
        saved_code_size = 0;
        if (saved_code != nullptr)
        {
            mm.FreeMemory(saved_code);
            saved_code = nullptr;
        }
        if (original_trampoline_address != nullptr)
        {
            mm.FreeMemory(original_trampoline_address);
            original_trampoline_address = nullptr;
        }

        orignal_func_address = nullptr;

        return nullptr;
    }

    void* hook::restore_func()
    {
        void* res = nullptr;
        if (restore_address == nullptr)
            return res;

        if (!memory_manipulation::memory_protect(restore_address, saved_code_size, memory_manipulation::memory_rights::mem_rwx))
            return res;

        SPDLOG_INFO("Restoring hook");

        memcpy(restore_address, saved_code, saved_code_size);
        memory_manipulation::memory_protect(restore_address, saved_code_size, memory_manipulation::memory_rights::mem_rx);
        memory_manipulation::flush_instruction_cache(restore_address, saved_code_size);

        SPDLOG_INFO("Restored hook");

        res = orignal_func_address;
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


*/
