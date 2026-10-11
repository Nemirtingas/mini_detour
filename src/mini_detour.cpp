#include <mini_detour/mini_detour.h>

#include <string.h>

#include <algorithm>
#include <limits>
#include <mutex>
#include <new>
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
struct fmt::formatter<MiniDetour::MemoryManipulation::MemoryRights>
{
    // Parses format specifications of the form ['f' | 'e'].
    constexpr auto parse(format_parse_context &ctx)
    {
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
    constexpr auto format(MiniDetour::MemoryManipulation::MemoryRights rights, FormatContext &ctx) const
    {
        // auto format(const point &p, FormatContext &ctx) -> decltype(ctx.out()) // c++11
        // ctx.out() is an output iterator to write to.
        return format_to(
            ctx.out(),
            "{}{}{}",
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

// #include <keystone/keystone.h>
#include <capstone/capstone.h>

namespace detail
{
template <typename It1, typename It2>
static bool equal(It1 first1, It1 last1, It2 first2, It2 last2)
{
    while (first1 != last1 && first2 != last2)
    {
        if (*first1++ != *first2++)
            return false;
    }
    return first1 == last1 && first2 == last2;
}
} // namespace detail

// class CodeAsm {
//     ks_engine* _Engine;
//     std::string _AssemblySource;
//     unsigned char *_BinaryCode;
//     size_t _BinaryCodeSize;
//
//     bool _IsHandleValid()
//     {
//         return _Engine != nullptr;
//     }
//
//     void _FreeBinaryCode()
//     {
//         if (_BinaryCode != nullptr)
//         {
//             ks_free(_BinaryCode);
//             _BinaryCode = nullptr;
//             _BinaryCodeSize = 0;
//         }
//     }
//
//     void _FreeEngine()
//     {
//         if (!_IsHandleValid())
//             return;
//
//         ks_close(_Engine);
//         _Engine = nullptr;
//     }
//
// public:
//     CodeAsm():
//         _Engine{ nullptr },
//         _BinaryCode{ nullptr },
//         _BinaryCodeSize{ 0 }
//     {}
//
//     ~CodeAsm()
//     {
//         _FreeBinaryCode();
//         _FreeEngine();
//     }
//
//     ks_err Init(ks_arch arch, ks_mode mode)
//     {
//         _FreeEngine();
//
//         return ks_open(arch, mode, &_Engine);
//     }
//
//     void AddSource(std::string const& str)
//     {
//         _AssemblySource.append(str.data(), str.length());
//     }
//
//     void AddSourceLine(std::string const& str)
//     {
//         AddSource(str);
//         if(str[str.length()-1] != '\n')
//             _AssemblySource += '\n';
//     }
//
//     ks_err Build(uint64_t base_address)
//     {
//         if (!_IsHandleValid())
//             return ks_err::KS_ERR_HANDLE;
//
//         size_t ignored;
//
//         _FreeBinaryCode();
//
//         if (ks_asm(_Engine, _AssemblySource.c_str(), base_address, &_BinaryCode, &_BinaryCodeSize, &ignored) != 0)
//             return ks_errno(_Engine);
//
//         return ks_err::KS_ERR_OK;
//     }
//
//     std::vector<uint8_t> GetBinary() const
//     {
//         return std::vector<uint8_t>{(const uint8_t*)_BinaryCode, (const uint8_t*)_BinaryCode + _BinaryCodeSize};
//     }
//
//     static int RuntimeEndianness()
//     {
//         uint32_t x{ 0x12345678 };
//         uint8_t e = *(uint8_t*)&x;
//         return static_cast<int>(e == 0x12 ? ks_mode::KS_MODE_BIG_ENDIAN : ks_mode::KS_MODE_LITTLE_ENDIAN);
//     }
// };

class CodeDisasm
{
    csh _DisasmHandle;
    cs_insn _CurrentInstruction;
    cs_detail _InstructionImplementation;

    inline bool _IsHandleValid() { return _DisasmHandle != 0; }

    inline void _CloseHandle()
    {
        if (_IsHandleValid())
        {
            cs_close(&_DisasmHandle);
            _DisasmHandle = 0;
        }
    }

  public:
    CodeDisasm()
        : _DisasmHandle{}
        , _CurrentInstruction{}
        , _InstructionImplementation{}
    {
        _CurrentInstruction.detail = &_InstructionImplementation;
    }

    ~CodeDisasm() { _CloseHandle(); }

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

    bool Disasm(const uint8_t **ppCode, size_t *pszCode, uint64_t *pAddr)
    {
        if (!_IsHandleValid())
            return false;

        return cs_disasm_iter(_DisasmHandle, ppCode, pszCode, pAddr, &_CurrentInstruction);
    }

    const cs_insn &GetInstruction() const { return _CurrentInstruction; }

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
                case cs_group_type::CS_GRP_JUMP: return true;
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
        uint32_t x{0x12345678};
        uint8_t e = *(uint8_t *)&x;
        return static_cast<int>(e == 0x12 ? cs_mode::CS_MODE_BIG_ENDIAN : cs_mode::CS_MODE_LITTLE_ENDIAN);
    }
};

// Copies up to size bytes of code starting at pCode. The page holding pCode is readable, but the next one may not be
// (small function at the end of a mapping), so it is read safely and the result is shortened if it isn't readable.
static size_t _ReadCode(const void *pCode, uint8_t *buffer, size_t size)
{
    const size_t pageSize   = MiniDetour::MemoryManipulation::PageSize();
    const size_t inPageSize = pageSize - (reinterpret_cast<uintptr_t>(pCode) % pageSize);
    if (size <= inPageSize)
    {
        memcpy(buffer, pCode, size);
        return size;
    }

    memcpy(buffer, pCode, inPageSize);
    return inPageSize +
           MiniDetour::MemoryManipulation::SafeMemoryRead(const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(pCode)) + inPageSize, buffer + inPageSize, size - inPageSize);
}

// Copies size bytes from address page by page, and returns how many were copied. The platforms copy a range all or
// nothing, but the rights are set per page: stopping at the first page that fails gives the exact count.
// copy(pageAddress, offset, chunkSize) copies one chunk, which never crosses a page.
template <typename Copy>
static size_t _CopyPageByPage(void *address, size_t size, Copy copy)
{
    const size_t pageSize = MiniDetour::MemoryManipulation::PageSize();
    const uintptr_t start = reinterpret_cast<uintptr_t>(address);
    size_t copied         = 0;
    while (copied < size)
    {
        const uintptr_t current = start + copied;
        const size_t chunkSize  = (std::min)(size - copied, pageSize - current % pageSize);
        if (!copy(reinterpret_cast<void *>(current), copied, chunkSize))
            break;

        copied += chunkSize;
    }

    return copied;
}

// Distance between an address and a free region (0 if the region contains it), to try the closest regions first.
static uintptr_t _DistanceToRegion(uintptr_t address, MiniDetour::MemoryManipulation::RegionInfos_t const &region)
{
    if (address < region.Start)
        return region.Start - address;

    if (address >= region.End)
        return address - region.End;

    return 0;
}

// Tries to allocate size bytes in a free region, at a multiple of step (the allocation granularity), starting from the
// address closest to addressHint: upward from there, then downward. tryAlloc(address) returns the allocation or nullptr.
template <typename TryAlloc>
static void *_AllocInFreeRegion(MiniDetour::MemoryManipulation::RegionInfos_t const &region, uintptr_t addressHint, size_t size, size_t step, TryAlloc tryAlloc)
{
    // Computed from the region size so a huge size can't wrap around.
    if (size > region.End - region.Start)
        return nullptr;

    const uintptr_t lowest = (region.Start + step - 1) / step * step;
    uintptr_t highest      = region.End - size;
    highest -= highest % step;
    if (highest < lowest)
        return nullptr;

    const uintptr_t first = std::min(std::max(addressHint - addressHint % step, lowest), highest);
    for (uintptr_t allocAddress = first;; allocAddress += step)
    {
        void *address = tryAlloc(allocAddress);
        if (address != nullptr)
            return address;

        if (highest - allocAddress < step)
            break;
    }

    for (uintptr_t allocAddress = first; allocAddress - lowest >= step;)
    {
        allocAddress -= step;
        void *address = tryAlloc(allocAddress);
        if (address != nullptr)
            return address;
    }

    return nullptr;
}

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
inline size_t _PageAddrSize(void *addr, size_t len, size_t page_size);

inline size_t _RegionSize()
{
    return MiniDetour::MemoryManipulation::PageSize();
}

inline size_t _JumpsInRegion()
{
    return _RegionSize() / AbsJump::GetMaxOpcodeSize();
}

inline size_t _PageAddrSize(void *addr, size_t len, size_t page_size)
{
    uintptr_t start_addr = reinterpret_cast<uintptr_t>(MiniDetour::MemoryManipulation::PageRound(addr, page_size));
    uintptr_t end_addr   = reinterpret_cast<uintptr_t>(MiniDetour::MemoryManipulation::PageRoundUp(reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(addr) + len), page_size));
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
        jump_t *jump_table;
    };

    std::vector<JumpRegion_t> jumps_regions;     // Jumps next to functions addresses
    std::vector<memory_t *> trampolines_regions; // memory regions for trampolines

    // Guards the regions, and the pages they share between hooks: hooks can be set from several threads.
    std::recursive_mutex _Mutex;

  public:
    MemoryManager() {}

    std::recursive_mutex &Mutex() { return _Mutex; }

    ~MemoryManager()
    {
        // for (auto& v : jumps_regions)
        //     MemoryManipulation::MemoryFree(v, _RegionSize());
        //
        // for (auto& v : trampolines_regions)
        //     MemoryManipulation::MemoryFree(v, _RegionSize());
    }

    // Allocates near hint_addr. When the closest free memory isn't usable from reference (for example below a module
    // that needs a positive RVA), the other free regions are tried, closest first.
    void *_AllocUsableJumpsRegion(void *hint_addr, void *reference, bool (*isUsable)(void *, void *))
    {
        const size_t regionSize = _RegionSize();
        void *jump_table        = MiniDetour::MemoryManipulation::MemoryAlloc(hint_addr, regionSize, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);
        if (jump_table == nullptr || isUsable(reference, jump_table))
            return jump_table;

        MiniDetour::MemoryManipulation::MemoryFree(jump_table, regionSize);

        auto freeRegionCount = MiniDetour::MemoryManipulation::GetFreeRegions(nullptr, 0);
        std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> freeRegions((size_t)(freeRegionCount * 1.5));
        freeRegionCount = MiniDetour::MemoryManipulation::GetFreeRegions(freeRegions.data(), freeRegions.size());
        if (freeRegionCount < freeRegions.size())
            freeRegions.resize(freeRegionCount);

        const uintptr_t hint = reinterpret_cast<uintptr_t>(hint_addr);
        std::sort(
            freeRegions.begin(),
            freeRegions.end(),
            [hint](MiniDetour::MemoryManipulation::RegionInfos_t const &l, MiniDetour::MemoryManipulation::RegionInfos_t const &r)
            { return _DistanceToRegion(hint, l) < _DistanceToRegion(hint, r); });

        for (auto const &region : freeRegions)
        {
            if (region.End - region.Start < regionSize)
                continue;

            // Both ends of the region: the closest one to the reference depends on which side of it the region is.
            const uintptr_t candidates[] = {region.Start, region.End - regionSize};
            for (auto candidate : candidates)
            {
                if (!isUsable(reference, reinterpret_cast<void *>(candidate)))
                    continue;

                jump_table = MiniDetour::MemoryManipulation::MemoryAlloc(reinterpret_cast<void *>(candidate), regionSize, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);
                if (jump_table != nullptr && isUsable(reference, jump_table))
                    return jump_table;

                if (jump_table != nullptr)
                    MiniDetour::MemoryManipulation::MemoryFree(jump_table, regionSize);
            }
        }

        return nullptr;
    }

    // isUsable(reference, jump) tells if a jump slot can be used from reference.
    void *AllocJumpsRegion(void *hint_addr, void *reference, bool (*isUsable)(void *, void *))
    {
        void *jump_table = _AllocUsableJumpsRegion(hint_addr, reference, isUsable);
        SPDLOG_INFO("Jumps region allocated can hold {} jumps", _JumpsInRegion());

        if (jump_table != nullptr)
        {
            if (isUsable(reference, jump_table))
            {
                SPDLOG_INFO("Jump region {} is usable from {}", jump_table, reference);

                memset(jump_table, 0xCC, _RegionSize());

                // Protect trampoline region memory
                MiniDetour::MemoryManipulation::MemoryProtect(jump_table, _RegionSize(), MiniDetour::MemoryManipulation::MemoryRights::mem_rx);

                jumps_regions.emplace_back();
                auto &region = *jumps_regions.rbegin();
                region.bitmap.resize(_JumpsInRegion(), false);
                region.bitmap[0]  = true;
                region.jump_table = (JumpRegion_t::jump_t *)jump_table;
            }
            else
            {
                SPDLOG_INFO("Jump region {} is not usable from {}", jump_table, reference);

                MiniDetour::MemoryManipulation::MemoryFree(jump_table, _RegionSize());
                jump_table = nullptr;
            }
        }

        return jump_table;
    }

    void *GetFreeJump(void *address_hint) { return GetFreeJump(address_hint, address_hint, _AddressesAreRelativeJumpable); }

    // Free jump slot for which isUsable(reference, slot) is true. A new region is allocated near address_hint if needed.
    void *GetFreeJump(void *address_hint, void *reference, bool (*isUsable)(void *, void *))
    {
        std::lock_guard<std::recursive_mutex> lock(_Mutex);

        for (auto &region : jumps_regions)
        {
            for (int i = 0; i < region.bitmap.size(); ++i)
            {
                if (!region.bitmap[i] && isUsable(reference, region.jump_table + i))
                {
                    SPDLOG_INFO("Using free jump {} in region {} for {}", (void *)(region.jump_table + i), (void *)region.jump_table, address_hint);
                    region.bitmap[i] = true;
                    return region.jump_table + i;
                }
            }
        }

        void *res = AllocJumpsRegion(address_hint, reference, isUsable);
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

    void FreeJump(void *jump)
    {
        std::lock_guard<std::recursive_mutex> lock(_Mutex);

        SPDLOG_DEBUG("Freeing jump {}", jump);

        JumpRegion_t::jump_t *jump_addr = reinterpret_cast<JumpRegion_t::jump_t *>(jump);

        for (auto &region : jumps_regions)
        {
            if (region.jump_table <= jump_addr && jump_addr < (region.jump_table + region.bitmap.size()))
            {
                region.bitmap[jump_addr - region.jump_table] = false;
                break;
            }
        }
    }

    memory_t *AllocTrampolineRegion()
    {
        memory_t *mem = (memory_t *)MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, _RegionSize(), MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);
        if (mem == nullptr)
            return nullptr;

        trampolines_regions.emplace_back(mem);

        memset(mem, 0, _RegionSize());

        return mem;
    }

    uint8_t *GetFreeTrampoline(size_t mem_size)
    {
        std::lock_guard<std::recursive_mutex> lock(_Mutex);

        // A larger trampoline would be written over the next slot.
        if (mem_size > sizeof(memory_t::data))
        {
            SPDLOG_ERROR("Trampoline of {} bytes doesn't fit in a {} bytes slot.", mem_size, sizeof(memory_t::data));
            return nullptr;
        }

        for (auto memory : trampolines_regions)
        {
            memory_t *end = memory + _RegionSize() / sizeof(memory_t);
            for (; memory != end; ++memory)
            {
                if (!memory->used)
                {
                    SPDLOG_DEBUG("Using free memory at {}", (void *)memory);
                    if (!MiniDetour::MemoryManipulation::MemoryProtect(memory, sizeof(memory_t), MiniDetour::MemoryManipulation::MemoryRights::mem_rwx))
                        return nullptr;

                    memory->used = 1;
                    MiniDetour::MemoryManipulation::MemoryProtect(memory, sizeof(memory_t), MiniDetour::MemoryManipulation::MemoryRights::mem_rx);
                    return memory->data;
                }
            }
        }

        memory_t *mem_region = AllocTrampolineRegion();
        if (mem_region == nullptr)
            return nullptr;

        mem_region->used = 1;
        SPDLOG_DEBUG("Using new memory at {}", (void *)mem_region);

        return mem_region->data;
    }

    void FreeTrampoline(void *trampoline)
    {
        std::lock_guard<std::recursive_mutex> lock(_Mutex);

        SPDLOG_DEBUG("Freeing trampoline {}", trampoline);
        memory_t *mem = reinterpret_cast<memory_t *>(reinterpret_cast<uint8_t *>(trampoline) - offsetof(memory_t, data));

        if (!MiniDetour::MemoryManipulation::MemoryProtect(mem, sizeof(memory_t), MiniDetour::MemoryManipulation::MemoryRights::mem_rwx))
            return;
        mem->used = 0;

        MiniDetour::MemoryManipulation::MemoryProtect(mem, sizeof(memory_t), MiniDetour::MemoryManipulation::MemoryRights::mem_rx);
    }
};

// Never destroyed: Hook_t objects with static storage restore their hook (and use the manager) during static
// destruction, possibly after the manager would have been destroyed.
static MemoryManager &GetMemoryManager()
{
    static MemoryManager *memoryManager = new MemoryManager();
    return *memoryManager;
}

// Gives back to hooked code the rights it had before being made writable: forcing mem_rx would remove the write
// access of code that needs it (JIT buffers). If they couldn't be read, the code is at least made executable again.
static void _RestoreCodeRights(void *address, size_t size, MiniDetour::MemoryManipulation::MemoryRights oldRights)
{
    if (oldRights == MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
        oldRights = MiniDetour::MemoryManipulation::MemoryRights::mem_rx;

    MiniDetour::MemoryManipulation::MemoryProtect(address, size, oldRights);
}

// Makes an import table slot (IAT/GOT entry) writable. The other rights of its page are kept: the slot is data,
// so execution is never added, but it may share a page with code that must stay executable.
static bool _MakeImportSlotWritable(void *address, size_t size, MiniDetour::MemoryManipulation::MemoryRights *oldRights)
{
    MiniDetour::MemoryManipulation::RegionInfos_t infos;
    MiniDetour::MemoryManipulation::GetRegionInfos(address, &infos);
    if (infos.Rights == MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
        return false;

    *oldRights  = infos.Rights;
    auto rights = static_cast<MiniDetour::MemoryManipulation::MemoryRights>(infos.Rights | MiniDetour::MemoryManipulation::MemoryRights::mem_w);
    return MiniDetour::MemoryManipulation::MemoryProtect(address, size, rights, nullptr);
}

#if defined(MINIDETOUR_OS_WINDOWS)
#include "mini_detour_windows.h"

#elif defined(MINIDETOUR_OS_LINUX)
#include "mini_detour_linux.h"

#elif defined(MINIDETOUR_OS_APPLE)
#include "mini_detour_macos.h"

#endif

namespace MiniDetour
{
namespace MemoryManipulation
{
namespace Implementation
{

// Allocates as close as possible to the hint, so hooks can reach the memory with relative jumps.
// The platform gives _MemoryAllocAt, _MemoryAllocAnywhere, _AllocationGranularity and the user address space
// bounds, _MinUserAddress and _MaxUserAddress (end of the user address space).
void *MemoryAlloc(void *_addressHint, size_t size, MemoryRights rights)
{
    const uintptr_t minAddress = _MinUserAddress();
    const uintptr_t maxAddress = _MaxUserAddress();
    if (reinterpret_cast<uintptr_t>(_addressHint) >= maxAddress)
        _addressHint = reinterpret_cast<void *>(maxAddress - 1);

    auto pageSize    = PageSize();
    auto addressHint = reinterpret_cast<uintptr_t>(PageRound(_addressHint, pageSize));
    size             = _PageAddrSize((void *)addressHint, size, pageSize);

    if (_addressHint == nullptr)
        return _MemoryAllocAnywhere(size, rights);

    auto freeRegionCount = GetFreeRegions(nullptr, 0);
    std::vector<RegionInfos_t> freeRegions((size_t)(freeRegionCount * 1.5));
    freeRegionCount = GetFreeRegions(freeRegions.data(), freeRegions.size());
    if (freeRegionCount < freeRegions.size())
        freeRegions.resize(freeRegionCount);

    // Only keep the part of the free regions the process can allocate.
    for (auto &region : freeRegions)
    {
        region.Start = std::max<uintptr_t>(region.Start, minAddress);
        region.End   = std::min<uintptr_t>(region.End, maxAddress);
    }
    freeRegions.erase(std::remove_if(freeRegions.begin(), freeRegions.end(), [](RegionInfos_t const &region) { return region.Start >= region.End; }), freeRegions.end());

    std::sort(
        freeRegions.begin(),
        freeRegions.end(),
        [addressHint](RegionInfos_t const &l, RegionInfos_t const &r) { return _DistanceToRegion(addressHint, l) < _DistanceToRegion(addressHint, r); });

    const size_t granularity = _AllocationGranularity();
    for (auto const &region : freeRegions)
    {
        void *address = _AllocInFreeRegion(region, addressHint, size, granularity, [&](uintptr_t allocAddress) { return _MemoryAllocAt((void *)allocAddress, size, rights); });

        if (address != nullptr)
            return address;
    }

    // Fallback to anywhere alloc
    return _MemoryAllocAnywhere(size, rights);
}

size_t WriteAbsoluteJump(void *address, void *destination)
{
    int source_mode      = _GetCodeMode(address);
    int destination_mode = _GetCodeMode(destination);

    if (address == nullptr)
        return AbsJump::GetOpcodeSize(destination, source_mode, destination_mode);

    return AbsJump::WriteOpcodes(address, destination, source_mode, destination_mode);
}
} // namespace Implementation
} // namespace MemoryManipulation
} // namespace MiniDetour

namespace MiniDetour
{
namespace Implementation
{

class Hook_t
{
    // Where the original bytes were modified for hook
    void *_OriginalFuncAddress;
    // Saved code to restore
    std::vector<uint8_t> _SavedCode;
    // Hook code to check
    std::vector<uint8_t> _HookCode;
    // Where the original relocation is, to call the original function
    // The content is the saved code + abs jump to original code
    void *_OriginalTrampolineAddress;
    // The hook address
    void *_DetourFunc;
    // Optional, if we have space for only a relative jump, we need a trampoline
    void *_TrampolineAddress;

  public:
    bool _RestoreOnDestroy;
    void *_DetourCallFunc;
    // This can be different than _OriginalTrampolineAddress on ARM Thumb for example
    void *_OriginalTrampolineCallAddress;

    Hook_t()
        : _OriginalFuncAddress{}
        , _OriginalTrampolineAddress(nullptr)
        , _DetourFunc(nullptr)
        , _TrampolineAddress(nullptr)
        , _RestoreOnDestroy(true)
        , _DetourCallFunc(nullptr)
        , _OriginalTrampolineCallAddress(nullptr)
    {
    }

    Hook_t(Hook_t &&other) noexcept
        : _OriginalFuncAddress(std::move(other._OriginalFuncAddress))
        , _SavedCode(std::move(other._SavedCode))
        , _HookCode(std::move(other._HookCode))
        , _OriginalTrampolineAddress(std::move(other._OriginalTrampolineAddress))
        , _DetourFunc(std::move(other._DetourFunc))
        , _TrampolineAddress(std::move(other._TrampolineAddress))
        , _RestoreOnDestroy(std::move(other._RestoreOnDestroy))
        , _DetourCallFunc(std::move(other._DetourCallFunc))
        , _OriginalTrampolineCallAddress(std::move(other._OriginalTrampolineCallAddress))
    {
        other._RestoreOnDestroy = false;
    }

    Hook_t &operator=(Hook_t &&other) noexcept
    {
        if (this != &other)
        {
            _OriginalFuncAddress           = std::move(other._OriginalFuncAddress);
            _SavedCode                     = std::move(other._SavedCode);
            _HookCode                      = std::move(other._HookCode);
            _OriginalTrampolineAddress     = std::move(other._OriginalTrampolineAddress);
            _DetourFunc                    = std::move(other._DetourFunc);
            _TrampolineAddress             = std::move(other._TrampolineAddress);
            _RestoreOnDestroy              = std::move(other._RestoreOnDestroy);
            _DetourCallFunc                = std::move(other._DetourCallFunc);
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
            { // If we have a relative jump, clear it
                GetMemoryManager().FreeJump(_TrampolineAddress);
                _TrampolineAddress = nullptr;
            }

            GetMemoryManager().FreeTrampoline(_OriginalTrampolineAddress);
        }

        _SavedCode.clear();
        _HookCode.clear();
        _OriginalTrampolineAddress = nullptr;
        _OriginalFuncAddress       = nullptr;
        // Don't expose the old trampoline: once freed, it can be given to another hook.
        _OriginalTrampolineCallAddress = nullptr;
        _DetourFunc                    = nullptr;
        _DetourCallFunc                = nullptr;
    }

    bool CanHook(void *func)
    {
        if (_OriginalFuncAddress != nullptr)
            return false;

        CodeDisasm disasm;

        // Before reading the mode: on ARM, a PLT entry and the function it leads to can use different modes.
        _EnterRecursiveThunk(func);
        const int code_mode = _GetCodeMode(func);
        func                = _GetCodeAddress(func);

        if (_InitDisasm(disasm, code_mode) != cs_err::CS_ERR_OK)
            return false;

        size_t relativeJumpSize          = RelJump::GetOpcodeSize(func, reinterpret_cast<void *>(static_cast<uintptr_t>(0xfffffff0)), code_mode, code_mode);
        size_t absoluteJumpSize          = AbsJump::GetOpcodeSize(func, code_mode, code_mode);
        size_t smallest_jump_size        = std::min(relativeJumpSize, absoluteJumpSize);
        size_t relocatedOriginalCodeSize = 0;

        return _GetRelocatableSize(func, relocatedOriginalCodeSize, false, disasm, absoluteJumpSize) >= smallest_jump_size;
    }

    static bool _InitializeHookState(
        void *&functionToHook,
        void *&newFunction,
        bool ignoreRelocations,
        CodeDisasm &disasm,
        size_t &relativeJumpSize,
        size_t &absoluteJumpSize,
        size_t &relocatableSize,
        size_t &relocatedOriginalCodeSize,
        int &func_mode,
        int &hook_mode)
    {
        // Before reading the mode: on ARM, a PLT entry and the function it leads to can use different modes.
        _EnterRecursiveThunk(functionToHook);
        func_mode      = _GetCodeMode(functionToHook);
        hook_mode      = _GetCodeMode(newFunction);
        functionToHook = _GetCodeAddress(functionToHook);
        newFunction    = _GetCodeAddress(newFunction);

        if (_InitDisasm(disasm, func_mode) != cs_err::CS_ERR_OK)
            return false;

        // The relative jump goes to a jump slot that isn't allocated yet, not to newFunction: its size can't be known here
        // (Thumb has 2 and 4 bytes encodings), so the bytes of the longest encoding are relocated.
        relativeJumpSize = RelJump::GetMaxOpcodeSize();
        absoluteJumpSize = AbsJump::GetOpcodeSize(newFunction, func_mode, hook_mode);
        relocatableSize  = _GetRelocatableSize(functionToHook, relocatedOriginalCodeSize, ignoreRelocations, disasm, absoluteJumpSize);

        return true;
    }

    static bool ReplaceFunction(void *functionToReplace, void *newFunction)
    {
        int func_mode;
        int hook_mode;
        CodeDisasm disasm;

        size_t relativeJumpSize          = 0;
        size_t absoluteJumpSize          = 0;
        size_t relocatableSize           = 0;
        size_t relocatedOriginalCodeSize = 0;

        if (!_InitializeHookState(
                functionToReplace,
                newFunction,
                true,
                disasm,
                relativeJumpSize,
                absoluteJumpSize,
                relocatableSize,
                relocatedOriginalCodeSize,
                func_mode,
                hook_mode))
            return false;

        // can't even make a relative jump
        auto smallestJumpSize = std::min(relativeJumpSize, absoluteJumpSize);
        if (relocatableSize < smallestJumpSize)
            return false;

        // Restored if the replace fails after this point.
        MemoryManipulation::MemoryRights functionOldRights;
        if (!MemoryManipulation::MemoryProtect(functionToReplace, relocatableSize, MemoryManipulation::MemoryRights::mem_rwx, &functionOldRights))
            return false;

        _OtherThreadsFreezer_t freezer;
        if (relocatableSize >= absoluteJumpSize)
        {
            if (!freezer.Freeze(functionToReplace, relocatableSize))
            {
                _RestoreCodeRights(functionToReplace, relocatableSize, functionOldRights);
                return false;
            }

            AbsJump::WriteOpcodes(functionToReplace, newFunction, func_mode, hook_mode);
        }
        else
        {
            // Setup the trampoline
            void *jump_mem = GetMemoryManager().GetFreeJump(functionToReplace);
            if (jump_mem == nullptr)
            {
                _RestoreCodeRights(functionToReplace, relocatableSize, functionOldRights);
                return false;
            }

            if (!MemoryManipulation::MemoryProtect(jump_mem, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::MemoryRights::mem_rwx))
            {
                GetMemoryManager().FreeJump(jump_mem);
                _RestoreCodeRights(functionToReplace, relocatableSize, functionOldRights);
                return false;
            }

            AbsJump::WriteOpcodes(jump_mem, newFunction, func_mode, hook_mode);

            MemoryManipulation::MemoryProtect(jump_mem, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::MemoryRights::mem_rx);
            MemoryManipulation::FlushInstructionCache(jump_mem, AbsJump::GetMaxOpcodeSize());

            if (!freezer.Freeze(functionToReplace, relocatableSize))
            {
                GetMemoryManager().FreeJump(jump_mem);
                _RestoreCodeRights(functionToReplace, relocatableSize, functionOldRights);
                return false;
            }

            RelJump::WriteOpcodes(functionToReplace, functionToReplace, jump_mem, func_mode, hook_mode);
        }

        MemoryManipulation::FlushInstructionCache(functionToReplace, relocatableSize);
        freezer.Unfreeze();

        _RestoreCodeRights(functionToReplace, relocatableSize, functionOldRights);

        return true;
    }

    void *HookFunc(void *functionToHook, void *newFunction)
    {
        // Already hooking a function: hooking another one would lose the state needed to restore the first one.
        if (_OriginalFuncAddress != nullptr)
        {
            SPDLOG_ERROR("This hook is already in use, restore it first.");
            return nullptr;
        }

        int func_mode;
        int hook_mode;
        CodeDisasm disasm;

        size_t relativeJumpSize          = 0;
        size_t absoluteJumpSize          = 0;
        size_t relocatableSize           = 0;
        size_t relocatedOriginalCodeSize = 0;

        if (!_InitializeHookState(functionToHook, newFunction, false, disasm, relativeJumpSize, absoluteJumpSize, relocatableSize, relocatedOriginalCodeSize, func_mode, hook_mode))
            return nullptr;

        size_t totalOriginalTrampolineSize = 0;
        // Restored in the error path once the function was made writable.
        bool functionRightsChanged                         = false;
        MemoryManipulation::MemoryRights functionOldRights = MemoryManipulation::MemoryRights::mem_unset;
        SPDLOG_INFO("Needed relocatable size: found({}), rel({})", relocatableSize, relativeJumpSize);

        if (relocatableSize < relativeJumpSize)
        {
            SPDLOG_ERROR("Relocatable size was too small {} < {}", relocatableSize, relativeJumpSize);
            goto error;
        }

        // Only the bytes overwritten by the jump are saved and restored: the next ones may be changed by someone else
        // while the hook is set.
        _SavedCode.assign(reinterpret_cast<uint8_t *>(functionToHook), reinterpret_cast<uint8_t *>(functionToHook) + relativeJumpSize);

        // Upper bound of the trampoline code: the relocated code + the jump back to the function (its size can depend
        // on its destination). Used to check the slot size, and to protect and flush the whole trampoline.
        totalOriginalTrampolineSize = relocatedOriginalCodeSize + AbsJump::GetMaxOpcodeSize();

        _OriginalTrampolineAddress = GetMemoryManager().GetFreeTrampoline(totalOriginalTrampolineSize);
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
        if (!MemoryManipulation::MemoryProtect(functionToHook, _SavedCode.size(), MemoryManipulation::MemoryRights::mem_rwx, &functionOldRights))
        {
            MiniDetour::MemoryManipulation::RegionInfos_t regionInfos;
            MemoryManipulation::GetRegionInfos(functionToHook, &regionInfos);
            SPDLOG_ERROR("Failed to protect function memory ({} : {}), current rights: {}.", functionToHook, _SavedCode.size(), regionInfos.Rights);
            goto error;
        }
        functionRightsChanged = true;

        // A failed relocation leaves the trampoline without its jump back to the original function.
        if (_RelocateCode(functionToHook, _OriginalTrampolineAddress, disasm, relativeJumpSize, func_mode) < relativeJumpSize)
        {
            SPDLOG_ERROR("Failed to relocate code.");
            goto error;
        }

        if (relocatableSize >= relativeJumpSize)
        {
            SPDLOG_INFO("Relative hook");

            // Setup the trampoline
            void *jump_mem = GetMemoryManager().GetFreeJump(functionToHook);
            if (jump_mem == nullptr)
            {
                SPDLOG_ERROR("Failed to get memory for jump.");
                goto error;
            }

            if (!MemoryManipulation::MemoryProtect(jump_mem, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::MemoryRights::mem_rwx))
            {
                GetMemoryManager().FreeJump(jump_mem);
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
                    sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t *>(functionToHook)[i];
                }
                SPDLOG_INFO("Before write {}", sstr.str());
            }
#endif

            // Relative jump shoud have the same mode as the hooked function.
            // A shorter encoding than relativeJumpSize keeps the original bytes after it.
            _HookCode = _SavedCode;
            RelJump::WriteOpcodes(_HookCode.data(), functionToHook, jump_mem, func_mode, func_mode);
            {
                // Nothing can be logged while the other threads are suspended: it would allocate.
                _OtherThreadsFreezer_t freezer;
                if (!freezer.Freeze(functionToHook, _HookCode.size()))
                {
                    GetMemoryManager().FreeJump(jump_mem);
                    SPDLOG_ERROR("A thread is running the code to hook.");
                    goto error;
                }

                memcpy(functionToHook, _HookCode.data(), _HookCode.size());
                MemoryManipulation::FlushInstructionCache(functionToHook, _HookCode.size());
            }

#ifdef USE_SPDLOG
            {
                size_t dbg_opcode_size = relativeJumpSize;
                std::stringstream sstr;
                for (size_t i = 0; i < dbg_opcode_size; ++i)
                {
                    sstr << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)reinterpret_cast<uint8_t *>(functionToHook)[i];
                }
                SPDLOG_INFO("After write {}", sstr.str());
            }
#endif
            _TrampolineAddress = jump_mem;
        }

        // Try to restore memory rights, if it fails, no problem, we are just a bit too permissive
        MemoryManipulation::MemoryProtect(_OriginalTrampolineAddress, totalOriginalTrampolineSize, MemoryManipulation::MemoryRights::mem_rx);
        MemoryManipulation::FlushInstructionCache(_OriginalTrampolineAddress, totalOriginalTrampolineSize);

        _RestoreCodeRights(functionToHook, _SavedCode.size(), functionOldRights);
        MemoryManipulation::FlushInstructionCache(functionToHook, _SavedCode.size());

        _OriginalFuncAddress = functionToHook;
        _DetourFunc          = newFunction;

        _OriginalTrampolineCallAddress = _GetCallAddress(_OriginalTrampolineAddress, func_mode);
        _DetourCallFunc                = _GetCallAddress(_DetourFunc, hook_mode);

        return _OriginalTrampolineCallAddress;
    error:
        // The function code wasn't modified yet: only its rights.
        if (functionRightsChanged)
            _RestoreCodeRights(functionToHook, _SavedCode.size(), functionOldRights);

        _SavedCode.clear();
        _HookCode.clear();

        if (_OriginalTrampolineAddress != nullptr)
        {
            GetMemoryManager().FreeTrampoline(_OriginalTrampolineAddress);
            _OriginalTrampolineAddress = nullptr;
        }

        _OriginalFuncAddress = nullptr;

        return nullptr;
    }

    void *RestoreFunc()
    {
        std::vector<uint8_t> buffer;
        void *res = nullptr;
        if (_OriginalFuncAddress == nullptr)
            return res;

        SPDLOG_INFO("Restoring hook");

        buffer.resize(_HookCode.size());

        MiniDetour::MemoryManipulation::RegionInfos_t originalMemoryInfos;
        MemoryManipulation::GetRegionInfos(_OriginalFuncAddress, &originalMemoryInfos);
        // Memory has been freed, don't try to restore it, but release our jump and trampoline so the hook can be reused.
        if (originalMemoryInfos.Rights == MemoryManipulation::MemoryRights::mem_unset || originalMemoryInfos.Rights == MemoryManipulation::MemoryRights::mem_none)
        {
            Reset(true);
            SPDLOG_INFO("Hooked memory was freed, hook released");
            return nullptr;
        }

        memcpy(buffer.data(), _OriginalFuncAddress, buffer.size());

        res = _OriginalFuncAddress;

        if (detail::equal(buffer.begin(), buffer.end(), _HookCode.begin(), _HookCode.end()))
        { // Our hook code is still there, we can restore the old instructions.
            MemoryManipulation::MemoryRights functionOldRights;
            if (!MemoryManipulation::MemoryProtect(_OriginalFuncAddress, _SavedCode.size(), MemoryManipulation::MemoryRights::mem_rwx, &functionOldRights))
                return res;

            {
                _OtherThreadsFreezer_t freezer;
                if (!freezer.Freeze(_OriginalFuncAddress, _SavedCode.size()))
                {
                    // The hook stays in place: restoring it can be tried again.
                    _RestoreCodeRights(_OriginalFuncAddress, _SavedCode.size(), functionOldRights);
                    SPDLOG_ERROR("A thread is running the hooked code, it can't be restored.");
                    return nullptr;
                }

                memcpy(_OriginalFuncAddress, _SavedCode.data(), _SavedCode.size());
                MemoryManipulation::FlushInstructionCache(_OriginalFuncAddress, _SavedCode.size());
            }

            _RestoreCodeRights(_OriginalFuncAddress, _SavedCode.size(), functionOldRights);

            Reset(true);
            SPDLOG_INFO("Restored hook");
        }
        else
        {
            // Our Hook code has been modified, we have to nullify the hook:
            // the jump to the detour now goes to the original function trampoline, which stays allocated.
            const size_t jumpSize = AbsJump::GetMaxOpcodeSize();
            if (!MemoryManipulation::MemoryProtect(_TrampolineAddress, jumpSize, MemoryManipulation::MemoryRights::mem_rwx))
                return res;

            // The jump is reached from the hooked function and goes to its relocated code: both use the function mode.
            const int func_mode = _GetCodeMode(_OriginalTrampolineCallAddress);

            AbsJump::WriteOpcodes(_TrampolineAddress, _OriginalTrampolineAddress, func_mode, func_mode);

            MemoryManipulation::MemoryProtect(_TrampolineAddress, jumpSize, MemoryManipulation::MemoryRights::mem_rx);
            MemoryManipulation::FlushInstructionCache(_TrampolineAddress, jumpSize);

            Reset(false);
            SPDLOG_INFO("Bypassed hook");
        }

        return res;
    }
};

} // namespace Implementation
} // namespace MiniDetour

// MiniDetour Utils C functions

MINIDETOUR_EXPORT(void *) MiniDetourUtilsPageRoundUp(void *_addr, size_t page_size)
{
    uintptr_t addr = (uintptr_t)_addr;
    return (void *)((addr + (page_size - 1)) & (((uintptr_t)-1) ^ (page_size - 1)));
}

MINIDETOUR_EXPORT(void *) MiniDetourUtilsPageRound(void *_addr, size_t page_size)
{
    uintptr_t addr = (uintptr_t)_addr;
    return (void *)(addr & (((uintptr_t)-1) ^ (page_size - 1)));
}

MINIDETOUR_EXPORT(size_t) MiniDetourUtilsPageSize()
{
    return MiniDetour::MemoryManipulation::Implementation::PageSize();
}

// MiniDetour MemoryManipulation C functions
MINIDETOUR_EXPORT(void) MiniDetourMemoryManipulationGetRegionInfos(void *address, MiniDetourMemoryManipulationRegionInfos_t *regionInfos)
{
    if (regionInfos == nullptr)
        return;

    // The ModuleName size is computed from StructSize: a smaller value (not initialized by a C caller) would make it
    // wrap around. The other fields are always there.
    if (regionInfos->StructSize < sizeof(*regionInfos))
    {
        regionInfos->Rights = MiniDetour::MemoryManipulation::MemoryRights::mem_unset;
        regionInfos->Start  = 0;
        regionInfos->End    = 0;
        return;
    }

    MiniDetour::MemoryManipulation::Implementation::GetRegionInfos(address, regionInfos);
}

MINIDETOUR_EXPORT(size_t) MiniDetourMemoryManipulationGetAllRegions(MiniDetourMemoryManipulationRegionInfos_t *regions, size_t regionCount)
{
    return MiniDetour::MemoryManipulation::Implementation::GetAllRegions(regions, regionCount);
}

MINIDETOUR_EXPORT(size_t) MiniDetourMemoryManipulationGetFreeRegions(MiniDetourMemoryManipulationRegionInfos_t *regions, size_t regionCount)
{
    return MiniDetour::MemoryManipulation::Implementation::GetFreeRegions(regions, regionCount);
}

MINIDETOUR_EXPORT(int)
MiniDetourMemoryManipulationMemoryProtect(void *address, size_t size, MiniDetourMemoryManipulationMemoryRights rights, MiniDetourMemoryManipulationMemoryRights *old_rights)
{
    // mem_unset is what GetRegionInfos reports for an unknown region: restoring it would make the pages inaccessible.
    if (rights == MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
        return 0;

    return MiniDetour::MemoryManipulation::Implementation::MemoryProtect(address, size, rights, old_rights) ? 1 : 0;
}

MINIDETOUR_EXPORT(void) MiniDetourMemoryManipulationMemoryFree(void *address, size_t size)
{
    return MiniDetour::MemoryManipulation::Implementation::MemoryFree(address, size);
}

MINIDETOUR_EXPORT(void *) MiniDetourMemoryManipulationMemoryAlloc(void *address_hint, size_t size, MiniDetourMemoryManipulationMemoryRights rights)
{
    return MiniDetour::MemoryManipulation::Implementation::MemoryAlloc(address_hint, size, rights);
}

MINIDETOUR_EXPORT(size_t) MiniDetourMemoryManipulationSafeMemoryRead(void *address, uint8_t *buffer, size_t size)
{
    if (buffer == nullptr)
        return 0;

    return _CopyPageByPage(
        address,
        size,
        [buffer](void *chunk, size_t offset, size_t chunkSize) { return MiniDetour::MemoryManipulation::Implementation::SafeMemoryRead(chunk, buffer + offset, chunkSize); });
}

MINIDETOUR_EXPORT(size_t) MiniDetourMemoryManipulationSafeMemoryWrite(void *address, const uint8_t *buffer, size_t size)
{
    if (buffer == nullptr)
        return 0;

    return _CopyPageByPage(
        address,
        size,
        [buffer](void *chunk, size_t offset, size_t chunkSize) { return MiniDetour::MemoryManipulation::Implementation::SafeMemoryWrite(chunk, buffer + offset, chunkSize); });
}

MINIDETOUR_EXPORT(size_t) MiniDetourMemoryManipulationWriteAbsoluteJump(void *address, void *destination)
{
    return MiniDetour::MemoryManipulation::Implementation::WriteAbsoluteJump(address, destination);
}

MINIDETOUR_EXPORT(int) MiniDetourMemoryManipulationFlushInstructionCache(void *address, size_t size)
{
    return MiniDetour::MemoryManipulation::Implementation::FlushInstructionCache(address, size);
}

// MiniDetour ModuleManipulation C functions

MINIDETOUR_EXPORT(size_t)
MiniDetourModuleManipulationGetAllExportedSymbols(void *moduleHandle, MiniDetourModuleManipulationExportDetails_t *exportDetails, size_t exportDetailsCount)
{
    return MiniDetour::ModuleManipulation::Implementation::GetAllExportedSymbols(moduleHandle, exportDetails, exportDetailsCount);
}

MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationGetAllIATSymbols(void *moduleHandle, MiniDetourModuleManipulationIATDetails_t *iatDetails, size_t iatDetailsCount)
{
    return MiniDetour::ModuleManipulation::Implementation::GetAllIATSymbols(moduleHandle, iatDetails, iatDetailsCount);
}

MINIDETOUR_EXPORT(size_t)
MiniDetourModuleManipulationReplaceModuleExports(void *moduleHandle, MiniDetourModuleManipulationExportReplaceParameter_t *exportReplaceDetails, size_t exportReplaceDetailsCount)
{
    if (exportReplaceDetails == nullptr && exportReplaceDetailsCount != 0)
        return 0;

    std::lock_guard<std::recursive_mutex> lock(GetMemoryManager().Mutex());
    return MiniDetour::ModuleManipulation::Implementation::ReplaceModuleExports(moduleHandle, exportReplaceDetails, exportReplaceDetailsCount);
}

MINIDETOUR_EXPORT(size_t)
MiniDetourModuleManipulationRestoreModuleExports(void *moduleHandle, MiniDetourModuleManipulationExportReplaceParameter_t *exportReplaceDetails, size_t exportReplaceDetailsCount)
{
    if (exportReplaceDetails == nullptr && exportReplaceDetailsCount != 0)
        return 0;

    std::lock_guard<std::recursive_mutex> lock(GetMemoryManager().Mutex());
    return MiniDetour::ModuleManipulation::Implementation::RestoreModuleExports(moduleHandle, exportReplaceDetails, exportReplaceDetailsCount);
}

MINIDETOUR_EXPORT(size_t)
MiniDetourModuleManipulationReplaceModuleIATs(void *moduleHandle, MiniDetourModuleManipulationIATReplaceParameter_t *iatReplaceDetails, size_t iatReplaceDetailsCount)
{
    if (iatReplaceDetails == nullptr && iatReplaceDetailsCount != 0)
        return 0;

    std::lock_guard<std::recursive_mutex> lock(GetMemoryManager().Mutex());
    return MiniDetour::ModuleManipulation::Implementation::ReplaceModuleIATs(moduleHandle, iatReplaceDetails, iatReplaceDetailsCount);
}

MINIDETOUR_EXPORT(size_t)
MiniDetourModuleManipulationRestoreModuleIATs(void *moduleHandle, MiniDetourModuleManipulationIATReplaceParameter_t *iatReplaceDetails, size_t iatReplaceDetailsCount)
{
    if (iatReplaceDetails == nullptr && iatReplaceDetailsCount != 0)
        return 0;

    std::lock_guard<std::recursive_mutex> lock(GetMemoryManager().Mutex());
    return MiniDetour::ModuleManipulation::Implementation::RestoreModuleIATs(moduleHandle, iatReplaceDetails, iatReplaceDetailsCount);
}

// MiniDetour Hook_t C functions

MINIDETOUR_EXPORT(minidetour_hook_handle_t) MiniDetourHookTAlloc()
{
    // An exception must not go through the C API.
    return reinterpret_cast<minidetour_hook_handle_t>(new (std::nothrow) MiniDetour::Implementation::Hook_t());
}

MINIDETOUR_EXPORT(void) MiniDetourHookTFree(minidetour_hook_handle_t handle)
{
    std::lock_guard<std::recursive_mutex> lock(GetMemoryManager().Mutex());
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t *>(handle);
    delete hook;
}

MINIDETOUR_EXPORT(void) MiniDetourHookTRestoreOnDestroy(minidetour_hook_handle_t handle, int restore)
{
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t *>(handle);
    if (hook != nullptr)
        hook->_RestoreOnDestroy = restore != 0;
}

MINIDETOUR_EXPORT(int) MiniDetourHookTCanHook(minidetour_hook_handle_t handle, void *function)
{
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t *>(handle);
    return (hook != nullptr && function != nullptr && hook->CanHook(function)) ? 1 : 0;
}

MINIDETOUR_EXPORT(void *) MiniDetourHookTHookFunction(minidetour_hook_handle_t handle, void *function_to_hook, void *new_function)
{
    std::lock_guard<std::recursive_mutex> lock(GetMemoryManager().Mutex());
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t *>(handle);
    if (hook == nullptr || function_to_hook == nullptr || new_function == nullptr)
        return nullptr;

    return hook->HookFunc(function_to_hook, new_function);
}

MINIDETOUR_EXPORT(void *) MiniDetourHookTRestoreFunction(minidetour_hook_handle_t handle)
{
    std::lock_guard<std::recursive_mutex> lock(GetMemoryManager().Mutex());
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t *>(handle);
    return hook != nullptr ? hook->RestoreFunc() : nullptr;
}

MINIDETOUR_EXPORT(void *) MiniDetourHookTGetHookFunction(minidetour_hook_handle_t handle)
{
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t *>(handle);
    return hook != nullptr ? hook->_DetourCallFunc : nullptr;
}

MINIDETOUR_EXPORT(void *) MiniDetourHookTGetOriginalFunction(minidetour_hook_handle_t handle)
{
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t *>(handle);
    return hook != nullptr ? hook->_OriginalTrampolineCallAddress : nullptr;
}

MINIDETOUR_EXPORT(int) MiniDetourHookTReplaceFunction(void *function_to_replace, void *new_function)
{
    if (function_to_replace == nullptr || new_function == nullptr)
        return 0;

    std::lock_guard<std::recursive_mutex> lock(GetMemoryManager().Mutex());
    return MiniDetour::Implementation::Hook_t::ReplaceFunction(function_to_replace, new_function) ? 1 : 0;
}
