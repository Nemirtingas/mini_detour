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
struct fmt::formatter<MiniDetour::MemoryManipulation::MemoryRights> {
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
    auto format(MiniDetour::MemoryManipulation::MemoryRights rights, FormatContext& ctx) {
        // auto format(const point &p, FormatContext &ctx) -> decltype(ctx.out()) // c++11
          // ctx.out() is an output iterator to write to.
        return format_to(ctx.out(), "{}{}{}",
            rights & MiniDetour::MemoryManipulation::MemoryRights::mem_r ? 'r' : '-',
            rights & MiniDetour::MemoryManipulation::MemoryRights::mem_w ? 'w' : '-',
            rights & MiniDetour::MemoryManipulation::MemoryRights::mem_x ? 'x' : '-');
    }
};

#else
#define SPDLOG_DEBUG(...)
#define SPDLOG_ERROR(...)
#define SPDLOG_WARN(...)
#define SPDLOG_INFO(...)
#define SPDLOG_DEBUG(...)
#endif

//#include <keystone/keystone.h>
#include <capstone/capstone.h>

namespace detail
{
    template<typename It1, typename It2>
    static bool equal(It1 first1, It1 last1, It2 first2, It2 last2)
    {
        while (first1 != last1 && first2 != last2)
        {
            if (*first1++ != *first2++)
                return false;
        }
        return first1 == last1 && first2 == last2;
    }
}

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
    cs_detail _InstructionImplementation;

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
        _InstructionImplementation{}
    {
        _CurrentInstruction.detail = &_InstructionImplementation;
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

enum class JumpType_e
{
    Jump,
    Call,
};

#if defined(MINIDETOUR_ARCH_X64)
#include "mini_detour_x64.h"

#elif defined(MINIDETOUR_ARCH_X86)
#include "mini_detour_x86.h"

#elif defined(MINIDETOUR_ARCH_ARM64)
#include "mini_detour_arm64.h"

#elif defined(MINIDETOUR_ARCH_ARM)
#include "mini_detour_arm.h"

#endif

inline size_t _RegionSize();
inline size_t _JumpsInRegion();
inline size_t _PageAddrSize(void* addr, size_t len, size_t page_size);

inline size_t _RegionSize()
{
    return MiniDetour::MemoryManipulation::PageSize();
}

inline size_t _JumpsInRegion()
{
    return _RegionSize() / AbsJump::GetMaxOpcodeSize();
}

inline size_t _PageAddrSize(void* addr, size_t len, size_t page_size)
{
    uintptr_t start_addr = reinterpret_cast<uintptr_t>(MiniDetour::MemoryManipulation::PageRound(addr, page_size));
    uintptr_t end_addr = reinterpret_cast<uintptr_t>(MiniDetour::MemoryManipulation::PageRoundUp(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(addr) + len), page_size));
    return end_addr - start_addr;
}

class MemoryManager
{
    struct JumpRegion_t
    {
        std::vector<bool> bitmap;
        struct jump_t
        {
            uint8_t code[AbsJump::GetMaxOpcodeSize()];
        };
        jump_t* jump_table;
    };

    std::vector<JumpRegion_t> jumps_regions; // Jumps next to functions addresses
    std::vector<memory_t*> trampolines_regions; // memory regions for trampolines

public:
    MemoryManager()
    {}

    ~MemoryManager()
    {
        //for (auto& v : jumps_regions)
        //    MemoryManipulation::MemoryFree(v, _RegionSize());
        //
        //for (auto& v : trampolines_regions)
        //    MemoryManipulation::MemoryFree(v, _RegionSize());
    }

    void* AllocJumpsRegion(void* hint_addr)
    {
        void* jump_table = nullptr;

        jump_table = MiniDetour::MemoryManipulation::MemoryAlloc(hint_addr, _RegionSize(), MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);
        SPDLOG_INFO("Jumps region allocated can hold {} jumps", _JumpsInRegion());

        if (jump_table != nullptr)
        {
            if (_AddressesAreRelativeJumpable(hint_addr, jump_table))
            {
                SPDLOG_INFO("Relative jump from {} to {} is possible", hint_addr, jump_table);

                memset(jump_table, 0xCC, _RegionSize());

                // Protect trampoline region memory
                MiniDetour::MemoryManipulation::MemoryProtect(jump_table, _RegionSize(), MiniDetour::MemoryManipulation::MemoryRights::mem_rx);

                jumps_regions.emplace_back();
                auto& region = *jumps_regions.rbegin();
                region.bitmap.resize(_JumpsInRegion(), false);
                region.bitmap[0] = true;
                region.jump_table = (JumpRegion_t::jump_t*)jump_table;
            }
            else
            {
                SPDLOG_INFO("Relative jump from {} to {} is impossible", hint_addr, jump_table);

                MiniDetour::MemoryManipulation::MemoryFree(jump_table, _RegionSize());
                jump_table = nullptr;
            }
        }

        return jump_table;
    }

    void* GetFreeJump(void* address_hint)
    {
        for (auto& region : jumps_regions)
        {
            for (int i = 0; i < region.bitmap.size(); ++i)
            {
                if (!region.bitmap[i] && _AddressesAreRelativeJumpable(address_hint, region.jump_table + i))
                {
                    SPDLOG_INFO("Using free jump {} in region {} for {}", (void*)(region.jump_table + i), (void*)region.jump_table, address_hint);
                    region.bitmap[i] = true;
                    return region.jump_table + i;
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

        JumpRegion_t::jump_t* jump_addr = reinterpret_cast<JumpRegion_t::jump_t*>(jump);

        for (auto& region : jumps_regions)
        {
            if (region.jump_table <= jump_addr && jump_addr < (region.jump_table + region.bitmap.size()))
            {
                region.bitmap[jump_addr - region.jump_table] = false;
                break;
            }
        }
    }

    memory_t* AllocTrampolineRegion()
    {
        memory_t* mem = (memory_t*)MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, _RegionSize(), MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);
        if (mem == nullptr)
            return nullptr;

        trampolines_regions.emplace_back(mem);

        memset(mem, 0, _RegionSize());

        return mem;
    }

    uint8_t* GetFreeTrampoline(size_t mem_size)
    {
        assert(mem_size <= sizeof(memory_t::data));
        uint8_t* res = nullptr;
        for (auto memory : trampolines_regions)
        {
            memory_t* end = memory + _RegionSize() / sizeof(memory_t) + 1;
            for (; memory != end; ++memory)
            {
                if (!memory->used)
                {
                    SPDLOG_DEBUG("Using free memory at {}", (void*)memory);
                    if (!MiniDetour::MemoryManipulation::MemoryProtect(memory, sizeof(memory_t), MiniDetour::MemoryManipulation::MemoryRights::mem_rwx))
                        return nullptr;

                    memory->used = 1;
                    MiniDetour::MemoryManipulation::MemoryProtect(memory, sizeof(memory_t), MiniDetour::MemoryManipulation::MemoryRights::mem_rx);
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

        if (!MiniDetour::MemoryManipulation::MemoryProtect(mem, sizeof(memory_t), MiniDetour::MemoryManipulation::MemoryRights::mem_rwx))
            return;
        mem->used = 0;

        MiniDetour::MemoryManipulation::MemoryProtect(mem, sizeof(memory_t), MiniDetour::MemoryManipulation::MemoryRights::mem_rx);
    }
};

static MemoryManager mm;

#if defined(MINIDETOUR_OS_WINDOWS)
#include "mini_detour_windows.h"

#elif defined(MINIDETOUR_OS_LINUX)
#include "mini_detour_linux.h"

#elif defined(MINIDETOUR_OS_APPLE)
#include "mini_detour_macos.h"

#endif

namespace MiniDetour {
namespace MemoryManipulation {
namespace Implementation {

    size_t WriteAbsoluteJump(void* address, void* destination)
    {
#if defined(MINIDETOUR_ARCH_ARM)
        int source_mode = reinterpret_cast<uintptr_t>(address) & 1;
        int destination_mode = reinterpret_cast<uintptr_t>(destination) & 1;
#else
        int source_mode = 0;
        int destination_mode = 0;
#endif

        if (address == nullptr)
            return AbsJump::GetOpcodeSize(destination, source_mode, destination_mode);

        return AbsJump::WriteOpcodes(address, destination, source_mode, destination_mode);
    }
}//namespace Implementation
}//namespace MemoryManipulation
}//namespace MiniDetour

namespace MiniDetour {
namespace Implementation {

class Hook_t
{
    // Where the original bytes were modified for hook
    void* _OriginalFuncAddress;
    // Saved code to restore
    std::vector<uint8_t> _SavedCode;
    // Hook code to check
    std::vector<uint8_t> _HookCode;
    // Where the original relocation is, to call the original function
    // The content is the saved code + abs jump to original code
    void* _OriginalTrampolineAddress;
    // The hook address
    void* _DetourFunc;
    // Optional, if we have space for only a relative jump, we need a trampoline
    void* _TrampolineAddress;

public:
    bool _RestoreOnDestroy;
    void* _DetourCallFunc;
    // This can be different than _OriginalTrampolineAddress on ARM Thumb for example
    void* _OriginalTrampolineCallAddress;

    Hook_t() :
        _OriginalFuncAddress{},
        _OriginalTrampolineAddress(nullptr),
        _DetourFunc(nullptr),
        _TrampolineAddress(nullptr),
        _RestoreOnDestroy(true),
        _DetourCallFunc(nullptr),
        _OriginalTrampolineCallAddress(nullptr)
    {}

    Hook_t(Hook_t&& other) noexcept:
        _OriginalFuncAddress(std::move(other._OriginalFuncAddress)),
        _SavedCode(std::move(other._SavedCode)),
        _HookCode(std::move(other._HookCode)),
        _OriginalTrampolineAddress(std::move(other._OriginalTrampolineAddress)),
        _DetourFunc(std::move(other._DetourFunc)),
        _TrampolineAddress(std::move(other._TrampolineAddress)),
        _RestoreOnDestroy(std::move(other._RestoreOnDestroy)),
        _DetourCallFunc(std::move(other._DetourCallFunc)),
        _OriginalTrampolineCallAddress(std::move(other._OriginalTrampolineCallAddress))
    {
            other._RestoreOnDestroy = false;
    }

    Hook_t& operator=(Hook_t&& other) noexcept
    {
        if (this != &other)
        {
            _OriginalFuncAddress = std::move(other._OriginalFuncAddress);
            _SavedCode = std::move(other._SavedCode);
            _HookCode = std::move(other._HookCode);
            _OriginalTrampolineAddress = std::move(other._OriginalTrampolineAddress);
            _DetourFunc = std::move(other._DetourFunc);
            _TrampolineAddress = std::move(other._TrampolineAddress);
            _RestoreOnDestroy = std::move(other._RestoreOnDestroy);
            _DetourCallFunc = std::move(other._DetourCallFunc);
            _OriginalTrampolineCallAddress = std::move(other._OriginalTrampolineCallAddress);

            other._RestoreOnDestroy = false;
        }

        return *this;
    }

    ~Hook_t()
    {
        if (_RestoreOnDestroy)
        {
            RestoreFunc();
        }
    }

    void Reset(bool free_trampoline)
    {
        if (free_trampoline)
        {
            if (_TrampolineAddress != nullptr)
            {// If we have a relative jump, clear it
                mm.FreeJump(_TrampolineAddress);
                _TrampolineAddress = nullptr;
            }

            mm.FreeTrampoline(_OriginalTrampolineAddress);
        }

        _SavedCode.clear();
        _HookCode.clear();
        _OriginalTrampolineAddress = nullptr;
        _OriginalFuncAddress = nullptr;
    }

    bool CanHook(void* func)
    {
        if (_OriginalFuncAddress != nullptr)
            return false;

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

        size_t relativeJumpSize = RelJump::GetOpcodeSize(func, reinterpret_cast<void*>(static_cast<uintptr_t>(0xfffffff0)), code_mode, code_mode);
        size_t absoluteJumpSize = AbsJump::GetOpcodeSize(func, code_mode, code_mode);
        size_t smallest_jump_size = std::min(relativeJumpSize, absoluteJumpSize);
        size_t relocatedOriginalCodeSize = 0;

        _EnterRecursiveThunk(func);
        return _GetRelocatableSize(func, relocatedOriginalCodeSize, false, disasm, absoluteJumpSize) >= smallest_jump_size;
    }

    static bool _InitializeHookState(
        void*& functionToHook,
        void*& newFunction,
        bool ignoreRelocations,
        CodeDisasm& disasm,
        size_t& relativeJumpSize,
        size_t& absoluteJumpSize,
        size_t& smallestJumpSize,
        size_t& relocatableSize,
        size_t& relocatedOriginalCodeSize,
        int& func_mode,
        int& hook_mode)
    {
        func_mode = 0;
        hook_mode = 0;
        cs_err disasm_err;
#if defined(MINIDETOUR_ARCH_X86)
        disasm_err = disasm.Init(cs_arch::CS_ARCH_X86, (cs_mode)(cs_mode::CS_MODE_32 | CodeDisasm::RuntimeEndianness()));
#elif defined(MINIDETOUR_ARCH_X64)
        disasm_err = disasm.Init(cs_arch::CS_ARCH_X86, (cs_mode)(cs_mode::CS_MODE_64 | CodeDisasm::RuntimeEndianness()));
#elif defined(MINIDETOUR_ARCH_ARM)
        func_mode = reinterpret_cast<uintptr_t>(functionToHook) & 1;
        hook_mode = reinterpret_cast<uintptr_t>(newFunction) & 1;
        disasm_err = disasm.Init(cs_arch::CS_ARCH_ARM, (cs_mode)((func_mode ? cs_mode::CS_MODE_THUMB : cs_mode::CS_MODE_ARM) | CodeDisasm::RuntimeEndianness()));

        // Sanitize address for ARM/THUMB valid opcodes.
        functionToHook = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(functionToHook) & ~1);
        newFunction = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(newFunction) & ~1);

#elif defined(MINIDETOUR_ARCH_ARM64)
        disasm_err = disasm.Init(cs_arch::CS_ARCH_ARM64, (cs_mode)(cs_mode::CS_MODE_ARM | CodeDisasm::RuntimeEndianness()));
#endif

        if (disasm_err != cs_err::CS_ERR_OK)
            return false;

        _EnterRecursiveThunk(functionToHook);

        relativeJumpSize = RelJump::GetOpcodeSize(functionToHook, newFunction, func_mode, hook_mode);
        absoluteJumpSize = AbsJump::GetOpcodeSize(newFunction, func_mode, hook_mode);
        smallestJumpSize = std::min(relativeJumpSize, absoluteJumpSize);
        relocatableSize = _GetRelocatableSize(functionToHook, relocatedOriginalCodeSize, ignoreRelocations, disasm, absoluteJumpSize);

        return true;
    }

    static bool ReplaceFunction(void* functionToReplace, void* newFunction)
    {
        void* jumpDestination;
        size_t jumpDestinationSize;
        JumpType_e jumpType;

        int func_mode;
        int hook_mode;
        CodeDisasm disasm;

        size_t relativeJumpSize = 0;
        size_t absoluteJumpSize = 0;
        size_t smallestJumpSize = 0;
        size_t relocatableSize = 0;
        size_t relocatedOriginalCodeSize = 0;

        if (!_InitializeHookState(functionToReplace, newFunction, true, disasm, relativeJumpSize, absoluteJumpSize, smallestJumpSize, relocatableSize, relocatedOriginalCodeSize, func_mode, hook_mode))
            return false;
            
        // can't even make a relative jump
        if (relocatableSize < smallestJumpSize)
            return false;
            
        if (!MemoryManipulation::MemoryProtect(functionToReplace, relocatableSize, MemoryManipulation::MemoryRights::mem_rwx))
            return false;
            
        if (relocatableSize >= absoluteJumpSize)
        {
            AbsJump::WriteOpcodes(functionToReplace, newFunction, func_mode, hook_mode);
        }
        else
        {
            // Setup the trampoline
            void* jump_mem = mm.GetFreeJump(functionToReplace);
            if (jump_mem == nullptr)
                return false;
            
            if (!MemoryManipulation::MemoryProtect(jump_mem, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::MemoryRights::mem_rwx))
            {
                mm.FreeJump(jump_mem);
                return false;
            }
            
            AbsJump::WriteOpcodes(jump_mem, newFunction, func_mode, hook_mode);
            
            MemoryManipulation::MemoryProtect(jump_mem, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::MemoryRights::mem_rx);
            MemoryManipulation::FlushInstructionCache(jump_mem, AbsJump::GetMaxOpcodeSize());
            
            RelJump::WriteOpcodes(functionToReplace, functionToReplace, jump_mem, func_mode, hook_mode);
        }
            
        MemoryManipulation::MemoryProtect(functionToReplace, relocatableSize, MemoryManipulation::MemoryRights::mem_rx);
        MemoryManipulation::FlushInstructionCache(functionToReplace, relocatableSize);

        return true;
    }

    void* HookFunc(void* functionToHook, void* newFunction)
    {
        int func_mode;
        int hook_mode;
        CodeDisasm disasm;

        size_t relativeJumpSize = 0;
        size_t absoluteJumpSize = 0;
        size_t smallestJumpSize = 0;
        size_t relocatableSize = 0;
        size_t relocatedOriginalCodeSize = 0;

        if (!_InitializeHookState(functionToHook, newFunction, false, disasm, relativeJumpSize, absoluteJumpSize, smallestJumpSize, relocatableSize, relocatedOriginalCodeSize, func_mode, hook_mode))
            return nullptr;

        size_t totalOriginalTrampolineSize = 0;
        SPDLOG_INFO("Needed relocatable size: found({}), rel({})", relocatableSize, relativeJumpSize);

        if (relocatableSize < relativeJumpSize)
        {
            SPDLOG_ERROR("Relocatable size was too small {} < {}", relocatableSize, relativeJumpSize);
            goto error;
        }

        _SavedCode.resize(relocatableSize);

        // Save the original code
        memcpy(&_SavedCode[0], functionToHook, _SavedCode.size());

        // The total number of bytes to copy from the original function + abs jump for trampoline
        totalOriginalTrampolineSize = relocatedOriginalCodeSize + AbsJump::GetOpcodeSize(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(functionToHook) + relocatedOriginalCodeSize), func_mode, hook_mode);
            
        _OriginalTrampolineAddress = mm.GetFreeTrampoline(totalOriginalTrampolineSize);
        if (_OriginalTrampolineAddress == nullptr)
        {
            SPDLOG_ERROR("Failed to get memory for trampoline.");
            goto error;
        }

        // RWX on our original trampoline func
        if (!MemoryManipulation::MemoryProtect(_OriginalTrampolineAddress, totalOriginalTrampolineSize, MemoryManipulation::MemoryRights::mem_rwx))
        {
            MiniDetour::MemoryManipulation::RegionInfos_t regionInfos;
            MemoryManipulation::GetRegionInfos(_OriginalTrampolineAddress, &regionInfos);
            SPDLOG_ERROR("Failed to protect trampoline memory ({} : {}), current rights: {}.", _OriginalTrampolineAddress, totalOriginalTrampolineSize, regionInfos.Rights);
            goto error;
        }

        // RWX on the orignal func
        if (!MemoryManipulation::MemoryProtect(functionToHook, _SavedCode.size(), MemoryManipulation::MemoryRights::mem_rwx))
        {
            MiniDetour::MemoryManipulation::RegionInfos_t regionInfos;
            MemoryManipulation::GetRegionInfos(functionToHook, &regionInfos);
            SPDLOG_ERROR("Failed to protect function memory ({} : {}), current rights: {}.", functionToHook, _SavedCode.size(), regionInfos.Rights);
            goto error;
        }

        _RelocateCode(functionToHook, _OriginalTrampolineAddress, disasm, relativeJumpSize);

        if (relocatableSize >= relativeJumpSize)
//            {
//                SPDLOG_INFO("Absolute hook {} >= {}", relocatableSize, absoluteJumpSize);
//
//#ifdef USE_SPDLOG
//                {
//                    size_t dbg_opcode_size = _SavedCode.size();
//                    std::stringstream sstr;
//                    for (size_t i = 0; i < dbg_opcode_size; ++i)
//                    {
//                        sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t*>(func)[i];
//                    }
//                    SPDLOG_INFO("Before write {}", sstr.str());
//                }
//#endif
//
//                _HookCode.resize(absoluteJumpSize);
//                AbsJump::WriteOpcodes(_HookCode.data(), func, hook_func, func_mode, hook_mode);
//                memcpy(func, _HookCode.data(), _HookCode.size());
//
//#ifdef USE_SPDLOG
//                {
//                    size_t dbg_opcode_size = absoluteJumpSize;
//                    std::stringstream sstr;
//                    for (size_t i = 0; i < dbg_opcode_size; ++i)
//                    {
//                        sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t*>(func)[i];
//                    }
//                    SPDLOG_INFO("After write {}", sstr.str());
//                }
//#endif
//            }
//            else
        {
            SPDLOG_INFO("Relative hook");

            // Setup the trampoline
            void* jump_mem = mm.GetFreeJump(functionToHook);
            if (jump_mem == nullptr)
            {
                SPDLOG_ERROR("Failed to get memory for jump.");
                goto error;
            }

            if (!MemoryManipulation::MemoryProtect(jump_mem, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::MemoryRights::mem_rwx))
            {
                mm.FreeJump(jump_mem);
                SPDLOG_ERROR("Failed to protect jump memory.");
                goto error;
            }

            SPDLOG_INFO("Trampoline located at: {}", jump_mem);
            AbsJump::WriteOpcodes(jump_mem, newFunction, func_mode, hook_mode);

            MemoryManipulation::MemoryProtect(jump_mem, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::MemoryRights::mem_rx);
            MemoryManipulation::FlushInstructionCache(jump_mem, AbsJump::GetMaxOpcodeSize());

#ifdef USE_SPDLOG
            {
                size_t dbg_opcode_size = _SavedCode.size();
                std::stringstream sstr;
                for (size_t i = 0; i < dbg_opcode_size; ++i)
                {
                    sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t*>(functionToHook)[i];
                }
                SPDLOG_INFO("Before write {}", sstr.str());
            }
#endif

            // Relative jump shoud have the same mode as the hooked function
            _HookCode.resize(relativeJumpSize);
            RelJump::WriteOpcodes(_HookCode.data(), functionToHook, jump_mem, func_mode, func_mode);
            memcpy(functionToHook, _HookCode.data(), _HookCode.size());

#ifdef USE_SPDLOG
            {
                size_t dbg_opcode_size = relativeJumpSize;
                std::stringstream sstr;
                for (size_t i = 0; i < dbg_opcode_size; ++i)
                {
                    sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t*>(functionToHook)[i];
                }
                SPDLOG_INFO("After write {}", sstr.str());
            }
#endif
            _TrampolineAddress = jump_mem;
        }

        // Try to restore memory rights, if it fails, no problem, we are just a bit too permissive
        MemoryManipulation::MemoryProtect(_OriginalTrampolineAddress, totalOriginalTrampolineSize, MemoryManipulation::MemoryRights::mem_rx);
        MemoryManipulation::FlushInstructionCache(_OriginalTrampolineAddress, totalOriginalTrampolineSize);

        MemoryManipulation::MemoryProtect(functionToHook, relocatableSize, MemoryManipulation::MemoryRights::mem_rx);
        MemoryManipulation::FlushInstructionCache(functionToHook, relocatableSize);

        _OriginalFuncAddress = functionToHook;
        _DetourFunc = newFunction;

#if defined(MINIDETOUR_ARCH_ARM)
        _OriginalTrampolineCallAddress = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(_OriginalTrampolineAddress) | (func_mode ? 1 : 0));
        _DetourCallFunc = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(_DetourFunc) | (hook_mode ? 1 : 0));
#else
        _OriginalTrampolineCallAddress = _OriginalTrampolineAddress;
        _DetourCallFunc = _DetourFunc;
#endif

        return _OriginalTrampolineCallAddress;
    error:
        _SavedCode.clear();
        _HookCode.clear();

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
        std::vector<uint8_t> buffer;
        void* res = nullptr;
        if (_OriginalFuncAddress == nullptr)
            return res;

        SPDLOG_INFO("Restoring hook");

        buffer.resize(_HookCode.size());

        MiniDetour::MemoryManipulation::RegionInfos_t originalMemoryInfos;
        MemoryManipulation::GetRegionInfos(_OriginalFuncAddress, &originalMemoryInfos);
        // Memory has been freed, don't try to restore it.
        if (originalMemoryInfos.Rights == MemoryManipulation::MemoryRights::mem_unset || originalMemoryInfos.Rights == MemoryManipulation::MemoryRights::mem_none)
            return nullptr;

        memcpy(buffer.data(), _OriginalFuncAddress, buffer.size());

        res = _OriginalFuncAddress;

        if (detail::equal(buffer.begin(), buffer.end(), _HookCode.begin(), _HookCode.end()))
        {// Our hook code is still there, we can restore the old instructions.
            if (!MemoryManipulation::MemoryProtect(_OriginalFuncAddress, _SavedCode.size(), MemoryManipulation::MemoryRights::mem_rwx))
                return res;

            memcpy(_OriginalFuncAddress, _SavedCode.data(), _SavedCode.size());

            MemoryManipulation::MemoryProtect(_OriginalFuncAddress, _SavedCode.size(), MemoryManipulation::MemoryRights::mem_rx);
            MemoryManipulation::FlushInstructionCache(_OriginalFuncAddress, _SavedCode.size());

            Reset(true);
            SPDLOG_INFO("Restored hook");
        }
        else
        {// Our Hook code has been modified, we have to nullify the hook.
            if (!MemoryManipulation::MemoryProtect(_TrampolineAddress, _SavedCode.size(), MemoryManipulation::MemoryRights::mem_rwx))
                return res;

            int func_mode = 0;
            int hook_mode = 0;

            #if defined(MINIDETOUR_ARCH_ARM)
                func_mode = reinterpret_cast<uintptr_t>(_TrampolineAddress) & 1;
                hook_mode = reinterpret_cast<uintptr_t>(_DetourCallFunc) & 1;
            #endif

            AbsJump::WriteOpcodes(_TrampolineAddress, _DetourCallFunc, func_mode, hook_mode);

            MemoryManipulation::MemoryProtect(_TrampolineAddress, _SavedCode.size(), MemoryManipulation::MemoryRights::mem_rx);
            MemoryManipulation::FlushInstructionCache(_TrampolineAddress, _SavedCode.size());

            Reset(false);
            SPDLOG_INFO("Bypassed hook");
        }

        return res;
    }
};

}//namespace Implementation
}//namespace MiniDetour

// MiniDetour Utils C functions

MINIDETOUR_EXPORT(void*) MiniDetourUtilsPageRoundUp(void* _addr, size_t page_size)
{
    uintptr_t addr = (uintptr_t)_addr;
    return (void*)((addr + (page_size - 1)) & (((uintptr_t)-1) ^ (page_size - 1)));
}

MINIDETOUR_EXPORT(void*) MiniDetourUtilsPageRound(void* _addr, size_t page_size)
{
    uintptr_t addr = (uintptr_t)_addr;
    return (void*)(addr & (((uintptr_t)-1) ^ (page_size - 1)));
}

MINIDETOUR_EXPORT(size_t) MiniDetourUtilsPageSize()
{
    return MiniDetour::MemoryManipulation::Implementation::PageSize();
}

// MiniDetour MemoryManipulation C functions
MINIDETOUR_EXPORT(void) MiniDetourMemoryManipulationGetRegionInfos(void* address, MiniDetourMemoryManipulationRegionInfos_t* regionInfos)
{
    MiniDetour::MemoryManipulation::Implementation::GetRegionInfos(address, regionInfos);
}

MINIDETOUR_EXPORT(size_t) MiniDetourMemoryManipulationGetAllRegions(MiniDetourMemoryManipulationRegionInfos_t* regions, size_t regionCount)
{
    return MiniDetour::MemoryManipulation::Implementation::GetAllRegions(regions, regionCount);
}

MINIDETOUR_EXPORT(size_t) MiniDetourMemoryManipulationGetFreeRegions(MiniDetourMemoryManipulationRegionInfos_t* regions, size_t regionCount)
{
    return MiniDetour::MemoryManipulation::Implementation::GetFreeRegions(regions, regionCount);
}

MINIDETOUR_EXPORT(bool) MiniDetourMemoryManipulationMemoryProtect(void* address, size_t size, MiniDetourMemoryManipulationMemoryRights rights, MiniDetourMemoryManipulationMemoryRights* old_rights)
{
    return MiniDetour::MemoryManipulation::Implementation::MemoryProtect(address, size, rights, old_rights);
}

MINIDETOUR_EXPORT(void) MiniDetourMemoryManipulationMemoryFree(void* address, size_t size)
{
    return MiniDetour::MemoryManipulation::Implementation::MemoryFree(address, size);
}

MINIDETOUR_EXPORT(void*) MiniDetourMemoryManipulationMemoryAlloc(void* address_hint, size_t size, MiniDetourMemoryManipulationMemoryRights rights)
{
    return MiniDetour::MemoryManipulation::Implementation::MemoryAlloc(address_hint, size, rights);
}

MINIDETOUR_EXPORT(bool) MiniDetourMemoryManipulationSafeMemoryRead(void* address, uint8_t* buffer, size_t size)
{
    return MiniDetour::MemoryManipulation::Implementation::SafeMemoryRead(address, buffer, size);
}

MINIDETOUR_EXPORT(bool) MiniDetourMemoryManipulationSafeMemoryWrite(void* address, const uint8_t* buffer, size_t size)
{
    return MiniDetour::MemoryManipulation::Implementation::SafeMemoryWrite(address, buffer, size);
}

MINIDETOUR_EXPORT(size_t) MiniDetourMemoryManipulationWriteAbsoluteJump(void* address, void* destination)
{
    return MiniDetour::MemoryManipulation::Implementation::WriteAbsoluteJump(address, destination);
}

MINIDETOUR_EXPORT(int) MiniDetourMemoryManipulationFlushInstructionCache(void* address, size_t size)
{
    return MiniDetour::MemoryManipulation::Implementation::FlushInstructionCache(address, size);
}

// MiniDetour ModuleManipulation C functions

MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationGetAllExportedSymbols(void* moduleHandle, MiniDetourModuleManipulationExportDetails_t* exportDetails, size_t exportDetailsCount)
{
    return MiniDetour::ModuleManipulation::Implementation::GetAllExportedSymbols(moduleHandle, exportDetails, exportDetailsCount);
}

MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationGetAllIATSymbols(void* moduleHandle, MiniDetourModuleManipulationIATDetails_t* iatDetails, size_t iatDetailsCount)
{
    return MiniDetour::ModuleManipulation::Implementation::GetAllIATSymbols(moduleHandle, iatDetails, iatDetailsCount);
}

MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationReplaceModuleExports(void* moduleHandle, MiniDetourModuleManipulationExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount)
{
    return MiniDetour::ModuleManipulation::Implementation::ReplaceModuleExports(moduleHandle, exportReplaceDetails, exportReplaceDetailsCount);
}

MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationRestoreModuleExports(void* moduleHandle, MiniDetourModuleManipulationExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount)
{
    return MiniDetour::ModuleManipulation::Implementation::RestoreModuleExports(moduleHandle, exportReplaceDetails, exportReplaceDetailsCount);
}

MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationReplaceModuleIATs(void* moduleHandle, MiniDetourModuleManipulationIATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount)
{
    return MiniDetour::ModuleManipulation::Implementation::ReplaceModuleIATs(moduleHandle, iatReplaceDetails, iatReplaceDetailsCount);
}

MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationRestoreModuleIATs(void* moduleHandle, MiniDetourModuleManipulationIATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount)
{
    return MiniDetour::ModuleManipulation::Implementation::RestoreModuleIATs(moduleHandle, iatReplaceDetails, iatReplaceDetailsCount);
}

// MiniDetour Hook_t C functions

MINIDETOUR_EXPORT(minidetour_hook_handle_t) MiniDetourHookTAlloc()
{
    return reinterpret_cast<minidetour_hook_handle_t>(new MiniDetour::Implementation::Hook_t());
}

MINIDETOUR_EXPORT(void) MiniDetourHookTFree(minidetour_hook_handle_t handle)
{
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t*>(handle);
    delete hook;
}

MINIDETOUR_EXPORT(void) MiniDetourHookTRestoreOnDestroy(minidetour_hook_handle_t handle, bool restore)
{
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t*>(handle);
    hook->_RestoreOnDestroy = restore;
}

MINIDETOUR_EXPORT(bool) MiniDetourHookTCanHook(minidetour_hook_handle_t handle, void* function)
{
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t*>(handle);
    return hook->CanHook(function);
}

MINIDETOUR_EXPORT(void*) MiniDetourHookTHookFunction(minidetour_hook_handle_t handle, void* function_to_hook, void* new_function)
{
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t*>(handle);
    return hook->HookFunc(function_to_hook, new_function);
}

MINIDETOUR_EXPORT(void*) MiniDetourHookTRestoreFunction(minidetour_hook_handle_t handle)
{
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t*>(handle);
    return hook->RestoreFunc();
}

MINIDETOUR_EXPORT(void*) MiniDetourHookTGetHookFunction(minidetour_hook_handle_t handle)
{
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t*>(handle);
    return hook->_DetourCallFunc;
}

MINIDETOUR_EXPORT(void*) MiniDetourHookTGetOriginalFunction(minidetour_hook_handle_t handle)
{
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t*>(handle);
    return hook->_OriginalTrampolineCallAddress;
}

MINIDETOUR_EXPORT(bool) MiniDetourHookTReplaceFunction(void* function_to_replace, void* new_function)
{
    return MiniDetour::Implementation::Hook_t::ReplaceFunction(function_to_replace, new_function);
}
