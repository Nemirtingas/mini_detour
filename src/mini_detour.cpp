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

//#include <keystone/keystone.h>
#include <capstone/capstone.h>

//class CodeAsm {
//    ks_engine* _Engine;
//    std::string _AssemblySource;
//    unsigned char *_BinaryCode;
//    size_t _BinaryCodeSize;
//
//    bool _IsHandleValid()
//    {
//        return _Engine != nullptr;
//    }
//
//    void _FreeBinaryCode()
//    {
//        if (_BinaryCode != nullptr)
//        {
//            ks_free(_BinaryCode);
//            _BinaryCode = nullptr;
//            _BinaryCodeSize = 0;
//        }
//    }
//
//    void _FreeEngine()
//    {
//        if (!_IsHandleValid())
//            return;
//        
//        ks_close(_Engine);
//        _Engine = nullptr;
//    }
//
//public:
//    CodeAsm():
//        _Engine{ nullptr },
//        _BinaryCode{ nullptr },
//        _BinaryCodeSize{ 0 }
//    {}
//
//    ~CodeAsm()
//    {
//        _FreeBinaryCode();
//        _FreeEngine();
//    }
//
//    ks_err Init(ks_arch arch, ks_mode mode)
//    {
//        _FreeEngine();
//
//        return ks_open(arch, mode, &_Engine);
//    }
//
//    void AddSource(std::string const& str)
//    {
//        _AssemblySource.append(str.data(), str.length());
//    }
//
//    void AddSourceLine(std::string const& str)
//    {
//        AddSource(str);
//        if(str[str.length()-1] != '\n')
//            _AssemblySource += '\n';
//    }
//
//    ks_err Build(uint64_t base_address)
//    {
//        if (!_IsHandleValid())
//            return ks_err::KS_ERR_HANDLE;
//
//        size_t ignored;
//
//        _FreeBinaryCode();
//
//        if (ks_asm(_Engine, _AssemblySource.c_str(), base_address, &_BinaryCode, &_BinaryCodeSize, &ignored) != 0)
//            return ks_errno(_Engine);
//
//        return ks_err::KS_ERR_OK;
//    }
//
//    std::vector<uint8_t> GetBinary() const
//    {
//        return std::vector<uint8_t>{(const uint8_t*)_BinaryCode, (const uint8_t*)_BinaryCode + _BinaryCodeSize};
//    }
//
//    static int RuntimeEndianness()
//    {
//        uint32_t x{ 0x12345678 };
//        uint8_t e = *(uint8_t*)&x;
//        return static_cast<int>(e == 0x12 ? ks_mode::KS_MODE_BIG_ENDIAN : ks_mode::KS_MODE_LITTLE_ENDIAN);
//    }
//};

class CodeDisasm
{
    csh _DisasmHandle;
    cs_insn _CurrentInstruction;
    cs_detail _InstructionDetails;

    inline bool _IsHandleValid()
    {
        return _DisasmHandle != 0;
    }

    inline void _CloseHandle()
    {
        if (_IsHandleValid())
        {
            cs_close(&_DisasmHandle);
            _DisasmHandle = 0;
        }
    }

public:
    CodeDisasm() :
        _DisasmHandle{},
        _CurrentInstruction{},
        _InstructionDetails{}
    {
        _CurrentInstruction.detail = &_InstructionDetails;
    }

    ~CodeDisasm()
    {
        _CloseHandle();
    }

    cs_err Init(cs_arch arch, cs_mode mode)
    {
        _CloseHandle();

        cs_err err;
        if ((err = cs_open(arch, mode, &_DisasmHandle)) != cs_err::CS_ERR_OK)
            return err;

        if ((err = cs_option(_DisasmHandle, cs_opt_type::CS_OPT_DETAIL, cs_opt_value::CS_OPT_ON)) != cs_err::CS_ERR_OK)
            return err;

        return cs_err::CS_ERR_OK;
    }

    bool Disasm(const uint8_t** ppCode, size_t* pszCode, uint64_t* pAddr)
    {
        if (!_IsHandleValid())
            return false;

        return cs_disasm_iter(_DisasmHandle, ppCode, pszCode, pAddr, &_CurrentInstruction);
    }

    const cs_insn& GetInstruction() const
    {
        return _CurrentInstruction;
    }

    bool IsInstructionTerminating() const
    {
        for (int i = 0; i < _CurrentInstruction.detail->groups_count; ++i)
        {
            switch (_CurrentInstruction.detail->groups[i])
            {
                case cs_group_type::CS_GRP_INT:
                case cs_group_type::CS_GRP_RET:
                case cs_group_type::CS_GRP_IRET:
                case cs_group_type::CS_GRP_BRANCH_RELATIVE:
                case cs_group_type::CS_GRP_CALL:
                case cs_group_type::CS_GRP_JUMP:
                    return true;
            }
        }

        return false;
    }

    int GetJumpType() const
    {
        int type = 0;
        for (int i = 0; i < _CurrentInstruction.detail->groups_count; ++i)
        {
            switch (_CurrentInstruction.detail->groups[i])
            {
                case cs_group_type::CS_GRP_BRANCH_RELATIVE: type |= 1; break;
                case cs_group_type::CS_GRP_JUMP: type |= 2; break;
                case cs_group_type::CS_GRP_CALL: type |= 4; break;
            }
        }

        return type;
    }

    static int RuntimeEndianness()
    {
        uint32_t x{ 0x12345678 };
        uint8_t e = *(uint8_t*)&x;
        return static_cast<int>(e == 0x12 ? cs_mode::CS_MODE_BIG_ENDIAN : cs_mode::CS_MODE_LITTLE_ENDIAN);
    }
};

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
                for (size_t i = 0; i < jumps_in_region(); ++i)
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
    class HookImpl
    {
        // Where the original bytes were modified for hook
        void* _OriginalFuncAddress;
        // Saved code to restore
        size_t _SavedCodeSize;
        uint8_t* _SavedCode;
        // Where the original relocation is, to call the original function
        // The content is the saved code + abs jump to original code
        void* _OriginalTrampolineAddress;
        // The hook address
        void* _DetourFunc;
        // Optional, if we have space for only a relative jump, we need a trampoline
        void* trampoline_address;
        bool restore_on_destroy;

    public:
        void* _DetourCallFunc;
        // This can be different than _OriginalTrampolineAddress on ARM Thumb for example
        void* _OriginalTrampolineCallAddress;

        HookImpl() :
            _OriginalFuncAddress{},
            _SavedCodeSize(0),
            _SavedCode(nullptr),
            _OriginalTrampolineAddress(nullptr),
            _DetourFunc(nullptr),
            trampoline_address(nullptr),
            restore_on_destroy(true),
            _DetourCallFunc(nullptr),
            _OriginalTrampolineCallAddress(nullptr)
        {}

        HookImpl(HookImpl&& other) noexcept
        {
            if (this != &other)
            {
                _OriginalFuncAddress = std::move(other._OriginalFuncAddress);
                _SavedCodeSize = std::move(other._SavedCodeSize);
                _SavedCode = std::move(other._SavedCode);
                _OriginalTrampolineAddress = std::move(other._OriginalTrampolineAddress);
                _DetourFunc = std::move(other._DetourFunc);
                trampoline_address = std::move(other.trampoline_address);
                restore_on_destroy = std::move(other.restore_on_destroy);
                _DetourCallFunc = std::move(other._DetourCallFunc);
                _OriginalTrampolineCallAddress = std::move(other._OriginalTrampolineCallAddress);

                other.restore_on_destroy = false;
            }
        }

        HookImpl& operator=(HookImpl&& other) noexcept
        {
            if (this != &other)
            {
                _OriginalFuncAddress = std::move(other._OriginalFuncAddress);
                _SavedCodeSize = std::move(other._SavedCodeSize);
                _SavedCode = std::move(other._SavedCode);
                _OriginalTrampolineAddress = std::move(other._OriginalTrampolineAddress);
                _DetourFunc = std::move(other._DetourFunc);
                trampoline_address = std::move(other.trampoline_address);
                restore_on_destroy = std::move(other.restore_on_destroy);
                _DetourCallFunc = std::move(other._DetourCallFunc);
                _OriginalTrampolineCallAddress = std::move(other._OriginalTrampolineCallAddress);

                other.restore_on_destroy = false;
            }

            return *this;
        }

        ~HookImpl()
        {
            if (restore_on_destroy)
            {
                RestoreFunc();
            }
        }

        void Reset()
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

        bool CanHook(void* func)
        {
            if (_OriginalFuncAddress != nullptr)
                return false;

            void* jump_destination;
            size_t jump_destination_size;
            int code_mode = 0;
            cs_err disasm_err;
            CodeDisasm disasm;
#if defined(MINIDETOUR_ARCH_X86)
            disasm_err = disasm.Init(cs_arch::CS_ARCH_X86, (cs_mode)(cs_mode::CS_MODE_32 | CodeDisasm::RuntimeEndianness()));
#elif defined(MINIDETOUR_ARCH_X64)
            disasm_err = disasm.Init(cs_arch::CS_ARCH_X86, (cs_mode)(cs_mode::CS_MODE_64 | CodeDisasm::RuntimeEndianness()));
#elif defined(MINIDETOUR_ARCH_ARM)
            code_mode = reinterpret_cast<uintptr_t>(func) & 1;
            disasm_err = disasm.Init(cs_arch::CS_ARCH_ARM, (cs_mode)((code_mode ? cs_mode::CS_MODE_THUMB : cs_mode::CS_MODE_ARM) | CodeDisasm::RuntimeEndianness()));

            // Sanitize address for ARM/THUMB valid opcodes.
            func = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(func) & ~1);

#elif defined(MINIDETOUR_ARCH_ARM64)
            disasm_err = disasm.Init(cs_arch::CS_ARCH_ARM64, (cs_mode)(cs_mode::CS_MODE_ARM | CodeDisasm::RuntimeEndianness()));
#endif

            if (disasm_err != cs_err::CS_ERR_OK)
                return false;

            size_t relative_jump_size = RelJump::GetOpcodeSize(func, reinterpret_cast<void*>(0xfffffff0), code_mode, code_mode);
            size_t absolute_jump_size = AbsJump::GetOpcodeSize(func, code_mode, code_mode);
            size_t smallest_jump_size = std::min(relative_jump_size, absolute_jump_size);

            _EnterRecursiveThunk(func);
            return _GetRelocatableSize(func, jump_destination, jump_destination_size, false, disasm, absolute_jump_size) >= smallest_jump_size;
        }

        static bool ReplaceFunc(void* func, void* hook_func)
        {
            void* jump_destination;
            size_t jump_destination_size;

            int func_mode = 0;
            int hook_mode = 0;
            cs_err disasm_err;
            CodeDisasm disasm;
#if defined(MINIDETOUR_ARCH_X86)
            disasm_err = disasm.Init(cs_arch::CS_ARCH_X86, (cs_mode)(cs_mode::CS_MODE_32 | CodeDisasm::RuntimeEndianness()));
#elif defined(MINIDETOUR_ARCH_X64)
            disasm_err = disasm.Init(cs_arch::CS_ARCH_X86, (cs_mode)(cs_mode::CS_MODE_64 | CodeDisasm::RuntimeEndianness()));
#elif defined(MINIDETOUR_ARCH_ARM)
            func_mode = reinterpret_cast<uintptr_t>(func) & 1;
            hook_mode = reinterpret_cast<uintptr_t>(hook_func) & 1;
            disasm_err = disasm.Init(cs_arch::CS_ARCH_ARM, (cs_mode)((func_mode ? cs_mode::CS_MODE_THUMB : cs_mode::CS_MODE_ARM) | CodeDisasm::RuntimeEndianness()));

            // Sanitize address for ARM/THUMB valid opcodes.
            func = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(func) & ~1);
            hook_func = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hook_func) & ~1);

#elif defined(MINIDETOUR_ARCH_ARM64)
            disasm_err = disasm.Init(cs_arch::CS_ARCH_ARM64, (cs_mode)(cs_mode::CS_MODE_ARM | CodeDisasm::RuntimeEndianness()));
#endif

            if (disasm_err != cs_err::CS_ERR_OK)
                return false;

            size_t relative_jump_size = RelJump::GetOpcodeSize(func, hook_func, func_mode, hook_mode);
            size_t absolute_jump_size = AbsJump::GetOpcodeSize(hook_func, func_mode, hook_mode);
            size_t smallest_jump_size = std::min(relative_jump_size, absolute_jump_size);

            size_t relocatable_size = 0;
            
            _EnterRecursiveThunk(func);
            
            relocatable_size = _GetRelocatableSize(func, jump_destination, jump_destination_size, true, disasm, absolute_jump_size);
            
            // can't even make a relative jump
            if (relocatable_size < smallest_jump_size)
                return false;
            
            if (!memory_manipulation::memory_protect(func, relocatable_size, memory_manipulation::memory_rights::mem_rwx))
                return false;
            
            if (relocatable_size >= absolute_jump_size)
            {
                AbsJump::WriteOpcodes(func, hook_func, func_mode, hook_mode);
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
            
                AbsJump::WriteOpcodes(jump_mem, hook_func, func_mode, hook_mode);
            
                memory_manipulation::memory_protect(jump_mem, AbsJump::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rx);
                memory_manipulation::flush_instruction_cache(jump_mem, AbsJump::GetMaxOpcodeSize());
            
                RelJump::WriteOpcodes(func, jump_mem, func_mode, hook_mode);
            }
            
            memory_manipulation::memory_protect(func, relocatable_size, memory_manipulation::memory_rights::mem_rx);
            memory_manipulation::flush_instruction_cache(func, relocatable_size);

            return true;
        }

        void* HookFunc(void* func, void* hook_func)
        {
            if (_OriginalTrampolineAddress != nullptr)
                return _OriginalTrampolineAddress;

            int func_mode = 0;
            int hook_mode = 0;
            cs_err disasm_err;
            CodeDisasm disasm;
            void* jump_destination;
            size_t jump_destination_size;

#if defined(MINIDETOUR_ARCH_X86)
            disasm_err = disasm.Init(cs_arch::CS_ARCH_X86, (cs_mode)(cs_mode::CS_MODE_32 | CodeDisasm::RuntimeEndianness()));
#elif defined(MINIDETOUR_ARCH_X64)
            disasm_err = disasm.Init(cs_arch::CS_ARCH_X86, (cs_mode)(cs_mode::CS_MODE_64 | CodeDisasm::RuntimeEndianness()));
#elif defined(MINIDETOUR_ARCH_ARM)
            func_mode = reinterpret_cast<uintptr_t>(func) & 1;
            hook_mode = reinterpret_cast<uintptr_t>(hook_func) & 1;
            disasm_err = disasm.Init(cs_arch::CS_ARCH_ARM, (cs_mode)((func_mode ? cs_mode::CS_MODE_THUMB : cs_mode::CS_MODE_ARM) | CodeDisasm::RuntimeEndianness()));

            // Sanitize address for ARM/THUMB valid opcodes.
            func = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(func) & ~1);
            hook_func = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hook_func) & ~1);

#elif defined(MINIDETOUR_ARCH_ARM64)
            disasm_err = disasm.Init(cs_arch::CS_ARCH_ARM64, (cs_mode)(cs_mode::CS_MODE_ARM | CodeDisasm::RuntimeEndianness()));
#endif

            if (disasm_err != cs_err::CS_ERR_OK)
                return nullptr;

            size_t relative_jump_size = RelJump::GetOpcodeSize(func, hook_func, func_mode, hook_mode);
            size_t absolute_jump_size = AbsJump::GetOpcodeSize(hook_func, func_mode, hook_mode);
            size_t smallest_jump_size = std::min(relative_jump_size, absolute_jump_size);

            size_t relocatable_size = 0;
            size_t total_original_trampoline_size = 0;

            _EnterRecursiveThunk(func);

            relocatable_size = _GetRelocatableSize(func, jump_destination, jump_destination_size, false, disasm, absolute_jump_size);

            SPDLOG_INFO("Needed relocatable size: found({}), rel({}), abs({})", relocatable_size, relative_jump_size, absolute_jump_size);

            if (relocatable_size < smallest_jump_size)
            {
                SPDLOG_ERROR("Relocatable size was too small {} < {}", relocatable_size, smallest_jump_size);
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
            total_original_trampoline_size = _SavedCodeSize + AbsJump::GetOpcodeSize(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(func) + _SavedCodeSize), func_mode, hook_mode);
            
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
            memcpy(_OriginalTrampolineAddress, func, _SavedCodeSize - jump_destination_size);

            // Write the absolute jump
            if (jump_destination == nullptr)
            {
                AbsJump::WriteOpcodes(
                    reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(_OriginalTrampolineAddress) + _SavedCodeSize),
                    reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(func) + _SavedCodeSize),
                    func_mode,  // Write the trampoline in the same
                    func_mode); // mode as the original function mode
            }
            else
            {
                AbsJump::WriteOpcodes(
                    reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(_OriginalTrampolineAddress) + _SavedCodeSize - jump_destination_size),
                    reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(jump_destination)),
                    func_mode,  // Write the trampoline in the same
                    func_mode); // mode as the original function mode
            }

            if (relocatable_size >= absolute_jump_size)
            {
                SPDLOG_INFO("Absolute hook {} >= {}", relocatable_size, absolute_jump_size);

#ifdef USE_SPDLOG
                {
                    size_t dbg_opcode_size = _SavedCodeSize;
                    std::stringstream sstr;
                    for (size_t i = 0; i < dbg_opcode_size; ++i)
                    {
                        sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t*>(func)[i];
                    }
                    SPDLOG_INFO("Before write {}", sstr.str());
                }
#endif

                AbsJump::WriteOpcodes(func, hook_func, func_mode, hook_mode);

#ifdef USE_SPDLOG
                {
                    size_t dbg_opcode_size = absolute_jump_size;
                    std::stringstream sstr;
                    for (size_t i = 0; i < dbg_opcode_size; ++i)
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

                SPDLOG_INFO("Trampoline located at: {}", jump_mem);
                AbsJump::WriteOpcodes(jump_mem, hook_func, func_mode, hook_mode);

                memory_manipulation::memory_protect(jump_mem, AbsJump::GetMaxOpcodeSize(), memory_manipulation::memory_rights::mem_rx);
                memory_manipulation::flush_instruction_cache(jump_mem, AbsJump::GetMaxOpcodeSize());

#ifdef USE_SPDLOG
                {
                    size_t dbg_opcode_size = _SavedCodeSize;
                    std::stringstream sstr;
                    for (size_t i = 0; i < dbg_opcode_size; ++i)
                    {
                        sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t*>(func)[i];
                    }
                    SPDLOG_INFO("Before write {}", sstr.str());
                }
#endif

#ifndef USE_SPDLOG
                // Relative jump shoud have the same mode as the hooked function
                RelJump::WriteOpcodes(func, jump_mem, func_mode, func_mode);
#else
                {
                    size_t dbg_opcode_size = RelJump::WriteOpcodes(func, jump_mem, func_mode, func_mode);
                    std::stringstream sstr;
                    for (size_t i = 0; i < dbg_opcode_size; ++i)
                    {
                        sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t*>(func)[i];
                    }
                    SPDLOG_INFO("After write {}", sstr.str());
                }
#endif
                trampoline_address = jump_mem;
            }

            // Try to restore memory rights, if it fails, no problem, we are just a bit too permissive
            memory_manipulation::memory_protect(_OriginalTrampolineAddress, total_original_trampoline_size, memory_manipulation::memory_rights::mem_rx);
            memory_manipulation::flush_instruction_cache(_OriginalTrampolineAddress, total_original_trampoline_size);

            memory_manipulation::memory_protect(func, relocatable_size, memory_manipulation::memory_rights::mem_rx);
            memory_manipulation::flush_instruction_cache(func, relocatable_size);

            _OriginalFuncAddress = func;
            _DetourFunc = hook_func;

#if defined(MINIDETOUR_ARCH_ARM)
            _OriginalTrampolineCallAddress = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(_OriginalTrampolineAddress) | (func_mode ? 1 : 0));
            _DetourCallFunc = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(_DetourFunc) | (hook_mode ? 1 : 0));
#else
            _OriginalTrampolineCallAddress = _OriginalTrampolineAddress;
            _DetourCallFunc = _DetourFunc;
#endif

            return _OriginalTrampolineCallAddress;
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

        void* RestoreFunc()
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
            Reset();

            return res;
        }
    };

    hook::hook() :
        _Impl(new HookImpl)
    {}

    hook::hook(hook&& other) noexcept
    {
        auto t = other._Impl;
        other._Impl = nullptr;
        _Impl = t;
    }

    hook& hook::operator=(hook&& other) noexcept
    {
        auto t = other._Impl;
        other._Impl = _Impl;
        _Impl = t;

        return *this;
    }

    hook::~hook()
    {
        delete _Impl;
    }

    void hook::reset()
    {
        _Impl->Reset();
    }

    bool hook::can_hook(void* func)
    {
        return _Impl->CanHook(func);
    }

    bool hook::replace_func(void* func, void* hook_func)
    {
        return HookImpl::ReplaceFunc(func, hook_func);
    }

    void* hook::hook_func(void* func, void* detour_func)
    {
        return _Impl->HookFunc(func, detour_func);
    }

    void* hook::restore_func()
    {
        return _Impl->RestoreFunc();
    }

    void* hook::get_hook_func()
    {
        return _Impl->_DetourCallFunc;
    }

    void* hook::get_original_func()
    {
        return _Impl->_OriginalTrampolineCallAddress;
    }
}