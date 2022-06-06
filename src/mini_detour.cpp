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

#include <iomanip>
#include <sstream>

template <>
struct fmt::formatter<memory_manipulation::memory_rights> {
    // Parses format specifications of the form ['f' | 'e'].
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin(), end = ctx.end();

        // Check if reached the end of the range:
        if (it != end && *it != '}')
            throw format_error("invalid format");

        // Return an iterator past the end of the parsed range:
        return it;
    }

    // Formats the point p using the parsed format specification (presentation)
    // stored in this formatter.
    template <typename FormatContext>
    auto format(memory_manipulation::memory_rights rights, FormatContext& ctx) {
        // auto format(const point &p, FormatContext &ctx) -> decltype(ctx.out()) // c++11
          // ctx.out() is an output iterator to write to.
        return format_to(ctx.out(), "{}{}{}",
            rights & memory_manipulation::memory_rights::mem_r ? 'r' : '-',
            rights & memory_manipulation::memory_rights::mem_w ? 'w' : '-',
            rights & memory_manipulation::memory_rights::mem_x ? 'x' : '-');
    }
};

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

inline size_t region_size();
inline size_t jumps_in_region();
inline size_t page_addr_size(void* addr, size_t len, size_t page_size);

#if defined(MINIDETOUR_OS_WINDOWS)
#include "mini_detour_windows.h"

#elif defined(MINIDETOUR_OS_LINUX)
#include "mini_detour_linux.h"

#elif defined(MINIDETOUR_OS_APPLE)
#include "mini_detour_macos.h"

#endif

inline size_t region_size()
{
    return memory_manipulation::page_size();
}

inline size_t jumps_in_region()
{
    return region_size() / AbsJump::GetMaxOpcodeSize();
}

inline size_t page_addr_size(void* addr, size_t len, size_t page_size)
{
    uintptr_t start_addr = reinterpret_cast<uintptr_t>(memory_manipulation::page_round(addr, page_size));
    uintptr_t end_addr = reinterpret_cast<uintptr_t>(memory_manipulation::page_round_up(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(addr) + len), page_size));
    return end_addr - start_addr;
}

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
            if (addresses_are_relative_jumpable(hint_addr, jump))
            {
                SPDLOG_INFO("Relative jump from {} to {} is possible", hint_addr, jump);

                memset(jump, 0, region_size());

                // Protect trampoline region memory
                memory_manipulation::memory_protect(jump, region_size(), memory_manipulation::memory_rights::mem_rx);

                jumps_regions.emplace_back(jump);
            }
            else
            {
                SPDLOG_INFO("Relative jump from {} to {} is impossible", hint_addr, jump);

                memory_manipulation::memory_free(jump, region_size());
                jump = nullptr;
            }
        }

        return jump;
    }

    void* GetFreeJump(void* address_hint)
    {
        constexpr uint8_t empty_region[AbsJump::GetMaxOpcodeSize()] = {};
        for (auto jumps_region : jumps_regions)
        {
            void* region_base = jumps_region;
            if (addresses_are_relative_jumpable(address_hint, jumps_region))
            {
                for (int i = 0; i < jumps_in_region(); ++i)
                {
                    if (memcmp(jumps_region, empty_region, AbsJump::GetMaxOpcodeSize()) == 0)
                    {
                        SPDLOG_INFO("Using free jump {} in region {} for {}", region_base, jumps_region, address_hint);
                        return jumps_region;
                    }
                    jumps_region = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(jumps_region) + AbsJump::GetMaxOpcodeSize());
                }
            }
        }

        void* res = AllocJumpsRegion(address_hint);
        if (res == nullptr)
        {
            SPDLOG_INFO("Couldn't find a suitable free jump and couldn't allocate one near {}, hooking will fail.", address_hint);
        }
        else
        {
            SPDLOG_INFO("Couldn't find a suitable free jump but allocated a new region near {} at {}.", address_hint, res);
        }
        return res;
    }

    void FreeJump(void* jump)
    {
        SPDLOG_DEBUG("Freeing jump {}", jump);

        if (!memory_manipulation::memory_protect(jump, AbsJump::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rwx))
            return;

        memset(jump, 0, AbsJump::GetMaxOpcodeSize());

        memory_manipulation::memory_protect(jump, AbsJump::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rx);
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

namespace mini_detour
{
    hook::hook() :
        _SavedCodeSize(0),
        _SavedCode(nullptr),
        _OriginalTrampolineAddress(nullptr),
        _DetourFunc(nullptr),
        trampoline_address(nullptr),
        restore_on_destroy(true)
    {}

    hook::hook(hook&& other) noexcept
    {
        if (this != &other)
        {
            _SavedCodeSize = std::move(other._SavedCodeSize);
            _SavedCode = std::move(other._SavedCode);
            _OriginalTrampolineAddress = std::move(other._OriginalTrampolineAddress);
            _DetourFunc = std::move(other._DetourFunc);
            trampoline_address = std::move(other.trampoline_address);
            restore_on_destroy = std::move(other.restore_on_destroy);

            other.restore_on_destroy = false;
        }
    }

    hook& hook::operator=(hook&& other) noexcept
    {
        if (this != &other)
        {
            _SavedCodeSize = std::move(other._SavedCodeSize);
            _SavedCode = std::move(other._SavedCode);
            _OriginalTrampolineAddress = std::move(other._OriginalTrampolineAddress);
            _DetourFunc = std::move(other._DetourFunc);
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

        _SavedCodeSize = 0;
        _SavedCode = nullptr;
        _OriginalTrampolineAddress = nullptr;
        _OriginalFuncAddress = nullptr;
    }

    bool hook::can_hook(void* func)
    {
        if (_OriginalFuncAddress != nullptr)
            return false;

        void* relocation = nullptr;

        enter_recursive_thunk(func);

        return get_relocatable_size(func, &relocation, false, AbsJump::GetOpcodeSize(func)) >= std::min(AbsJump::GetOpcodeSize(func), RelJump::GetOpcodeSize(func));
    }

    bool hook::replace_func(void* func, void* hook_func)
    {
        size_t relocatable_size = 0;

        void* tmp_relocation = nullptr;
        AbsJump abs_jump;

        enter_recursive_thunk(func);

        relocatable_size = get_relocatable_size(func, &tmp_relocation, true, AbsJump::GetOpcodeSize(hook_func));

        // can't even make a relative jump
        if (relocatable_size < std::min(AbsJump::GetOpcodeSize(hook_func), RelJump::GetOpcodeSize(hook_func)))
            return false;

        if (!memory_manipulation::memory_protect(func, relocatable_size, memory_manipulation::memory_rights::mem_rwx))
            return false;

        if (relocatable_size >= AbsJump::GetOpcodeSize(hook_func))
        {
            AbsJump hook_jump;
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

            if (!memory_manipulation::memory_protect(jump_mem, AbsJump::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rwx))
            {
                mm.FreeJump(jump_mem);
                return false;
            }

            abs_jump.SetAddr(hook_func);
            abs_jump.WriteOpcodes(jump_mem);

            memory_manipulation::memory_protect(jump_mem, AbsJump::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rx);
            memory_manipulation::flush_instruction_cache(jump_mem, AbsJump::GetMaxOpcodeSize());

            RelJump hook_jump;
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

        size_t relocatable_size = 0;

        size_t total_original_trampoline_size = 0;
        AbsJump abs_jump;

        enter_recursive_thunk(func);

        void* tmp_relocation;
        relocatable_size = get_relocatable_size(func, &tmp_relocation, false, AbsJump::GetOpcodeSize(detour_func));

        SPDLOG_INFO("Needed relocatable size: found({}), rel({}), abs({})", relocatable_size, RelJump::GetOpcodeSize(func), AbsJump::GetOpcodeSize(func));

        if (relocatable_size < std::min(AbsJump::GetOpcodeSize(detour_func), RelJump::GetOpcodeSize(detour_func)))
        {
            SPDLOG_ERROR("Relocatable size was too small {} < {}", relocatable_size, std::min(AbsJump::GetOpcodeSize(func), RelJump::GetOpcodeSize(func)));
            goto error;
        }

        _SavedCodeSize = relocatable_size;
        _SavedCode = (uint8_t*)malloc(sizeof(uint8_t) * relocatable_size);
        if (_SavedCode == nullptr)
        {
            SPDLOG_ERROR("Failed to malloc {} for code save.", relocatable_size);
            goto error;
        }

        // Save the original code
        memcpy(_SavedCode, func, _SavedCodeSize);

        // The total number of bytes to copy from the original function + abs jump for trampoline
        abs_jump.SetAddr(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(func) + _SavedCodeSize));
        total_original_trampoline_size = _SavedCodeSize + abs_jump.GetOpcodeSize();

        _OriginalTrampolineAddress = mm.GetFreeTrampoline(total_original_trampoline_size);
        if (_OriginalTrampolineAddress == nullptr)
        {
            SPDLOG_ERROR("Failed to get memory for trampoline.");
            goto error;
        }

        // RWX on our original trampoline func
        if (!memory_manipulation::memory_protect(_OriginalTrampolineAddress, total_original_trampoline_size, memory_manipulation::memory_rights::mem_rwx))
        {
            SPDLOG_ERROR("Failed to protect trampoline memory ({} : {}), current rights: {}.", _OriginalTrampolineAddress, total_original_trampoline_size, memory_manipulation::get_region_infos(_OriginalTrampolineAddress).rights);
            goto error;
        }

        // RWX on the orignal func
        if (!memory_manipulation::memory_protect(func, _SavedCodeSize, memory_manipulation::memory_rights::mem_rwx))
        {
            SPDLOG_ERROR("Failed to protect function memory ({} : {}), current rights: {}.", func, _SavedCodeSize, memory_manipulation::get_region_infos(func).rights);
            goto error;
        }

        // Copy the original code
        memcpy(_OriginalTrampolineAddress, func, _SavedCodeSize);

        // Write the absolute jump
        abs_jump.WriteOpcodes(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(_OriginalTrampolineAddress) + _SavedCodeSize));

        if (relocatable_size >= AbsJump::GetOpcodeSize(func))
        {
            SPDLOG_INFO("Absolute hook {} >= {}", relocatable_size, AbsJump::GetOpcodeSize(func));

            abs_jump.SetAddr(detour_func);

#ifdef USE_SPDLOG
            {
                size_t dbg_opcode_size = _SavedCodeSize;
                std::stringstream sstr;
                for (int i = 0; i < dbg_opcode_size; ++i)
                {
                    sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t*>(func)[i];
                }
                SPDLOG_INFO("Before write {}", sstr.str());
            }
#endif

            abs_jump.WriteOpcodes(func);

#ifdef USE_SPDLOG
            {
                size_t dbg_opcode_size = abs_jump.GetOpcodeSize();
                std::stringstream sstr;
                for (int i = 0; i < dbg_opcode_size; ++i)
                {
                    sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t*>(func)[i];
                }
                SPDLOG_INFO("After write {}", sstr.str());
            }
#endif
        }
        else
        {
            SPDLOG_INFO("Relative hook");

            // Setup the trampoline
            void* jump_mem = mm.GetFreeJump(func);
            if (jump_mem == nullptr)
            {
                SPDLOG_ERROR("Failed to get memory for jump.");
                goto error;
            }

            if (!memory_manipulation::memory_protect(jump_mem, AbsJump::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rwx))
            {
                mm.FreeJump(jump_mem);
                SPDLOG_ERROR("Failed to protect jump memory.");
                goto error;
            }

            abs_jump.SetAddr(detour_func);
            abs_jump.WriteOpcodes(jump_mem);

            memory_manipulation::memory_protect(jump_mem, AbsJump::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rx);
            memory_manipulation::flush_instruction_cache(jump_mem, AbsJump::GetMaxOpcodeSize());

            RelJump hook_jump;
            hook_jump.SetAddr(absolute_addr_to_relative(func, jump_mem));

#ifdef USE_SPDLOG
            {
                size_t dbg_opcode_size = _SavedCodeSize;
                std::stringstream sstr;
                for (int i = 0; i < dbg_opcode_size; ++i)
                {
                    sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t*>(func)[i];
                }
                SPDLOG_INFO("Before write {}", sstr.str());
            }
#endif

            hook_jump.WriteOpcodes(func);

            trampoline_address = jump_mem;

#ifdef USE_SPDLOG
            {
                size_t dbg_opcode_size = hook_jump.GetOpcodeSize();
                std::stringstream sstr;
                for (int i = 0; i < dbg_opcode_size; ++i)
                {
                    sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t*>(func)[i];
                }
                SPDLOG_INFO("After write {}", sstr.str());
            }
#endif
        }

        // Try to restore memory rights, if it fails, no problem, we are just a bit too permissive
        memory_manipulation::memory_protect(_OriginalTrampolineAddress, total_original_trampoline_size, memory_manipulation::memory_rights::mem_rx);
        memory_manipulation::flush_instruction_cache(_OriginalTrampolineAddress, total_original_trampoline_size);

        memory_manipulation::memory_protect(func, relocatable_size, memory_manipulation::memory_rights::mem_rx);
        memory_manipulation::flush_instruction_cache(func, relocatable_size);

        _OriginalFuncAddress = func;
        _DetourFunc = detour_func;

        return _OriginalTrampolineAddress;
    error:
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
        if (_OriginalFuncAddress == nullptr)
            return res;

        if (!memory_manipulation::memory_protect(_OriginalFuncAddress, _SavedCodeSize, memory_manipulation::memory_rights::mem_rwx))
            return res;

        SPDLOG_INFO("Restoring hook");

        memcpy(_OriginalFuncAddress, _SavedCode, _SavedCodeSize);
        memory_manipulation::memory_protect(_OriginalFuncAddress, _SavedCodeSize, memory_manipulation::memory_rights::mem_rx);
        memory_manipulation::flush_instruction_cache(_OriginalFuncAddress, _SavedCodeSize);

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
