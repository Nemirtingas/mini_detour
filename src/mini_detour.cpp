#include <mini_detour/mini_detour.h>

#include <string.h>

#include <algorithm>
#include <mutex>
#include <new>
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
#define SPDLOG_TRACE(...)
#define SPDLOG_CRITICAL(...)
#endif

#include <capstone/capstone.h>

// The system types the globals need. The platform headers include them too, with the same options.
#if defined(MINIDETOUR_OS_WINDOWS)
#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <windows.h>
#endif

class CodeDisasm_t
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
    CodeDisasm_t()
        : _DisasmHandle{}
        , _CurrentInstruction{}
        , _InstructionImplementation{}
    {
        _CurrentInstruction.detail = &_InstructionImplementation;
    }

    ~CodeDisasm_t() { _CloseHandle(); }

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

// The free regions of the process.
static std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> _GetFreeRegions()
{
    // Regions can appear between the two calls: room is left for them.
    auto freeRegionCount = MiniDetour::MemoryManipulation::GetFreeRegions(nullptr, 0);
    std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> freeRegions((size_t)(freeRegionCount * 1.5));
    freeRegionCount = MiniDetour::MemoryManipulation::GetFreeRegions(freeRegions.data(), freeRegions.size());
    if (freeRegionCount < freeRegions.size())
        freeRegions.resize(freeRegionCount);

    return freeRegions;
}

// Sorts the regions, the closest to address first.
static void _SortByDistance(std::vector<MiniDetour::MemoryManipulation::RegionInfos_t> &regions, uintptr_t address)
{
    std::sort(
        regions.begin(),
        regions.end(),
        [address](MiniDetour::MemoryManipulation::RegionInfos_t const &l, MiniDetour::MemoryManipulation::RegionInfos_t const &r)
        { return _DistanceToRegion(address, l) < _DistanceToRegion(address, r); });
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

inline size_t _RegionSize()
{
    return MiniDetour::MemoryManipulation::PageSize();
}

inline size_t _JumpsInRegion()
{
    return _RegionSize() / AbsJump_t::GetMaxOpcodeSize();
}

inline size_t _PageAddrSize(void *addr, size_t len, size_t page_size)
{
    uintptr_t start_addr = reinterpret_cast<uintptr_t>(MiniDetour::MemoryManipulation::PageRound(addr, page_size));
    uintptr_t end_addr   = reinterpret_cast<uintptr_t>(MiniDetour::MemoryManipulation::PageRoundUp(reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(addr) + len), page_size));
    return end_addr - start_addr;
}

namespace MiniDetour
{
namespace MemoryManipulation
{
namespace Implementation
{
// The code the library writes (jump slots, trampolines) is in memory from AllocCode, readable and executable. It is
// only written between BeginCodeWrite and EndCodeWrite, which also flushes the instruction cache.
void *AllocCode(void *addressHint, size_t size);
bool BeginCodeWrite(void *address, size_t size);
void EndCodeWrite(void *address, size_t size);
} // namespace Implementation
} // namespace MemoryManipulation
} // namespace MiniDetour

class MemoryManager_t
{
    struct JumpRegion_t
    {
        std::vector<bool> bitmap;
        struct JumpSlot_t
        {
            uint8_t code[AbsJump_t::GetMaxOpcodeSize()];
        };
        JumpSlot_t *jump_table;
    };

    std::vector<JumpRegion_t> jumps_regions;             // Jumps next to functions addresses
    std::vector<TrampolineSlot_t *> trampolines_regions; // memory regions for trampolines

  public:
    // Allocates near hint_addr. When the closest free memory isn't usable from reference (for example below a module
    // that needs a positive RVA), the other free regions are tried, closest first.
    void *_AllocUsableJumpsRegion(void *hint_addr, void *reference, bool (*isUsable)(void *, void *))
    {
        const size_t regionSize = _RegionSize();
        void *jump_table        = MiniDetour::MemoryManipulation::Implementation::AllocCode(hint_addr, regionSize);
        if (jump_table == nullptr || isUsable(reference, jump_table))
            return jump_table;

        MiniDetour::MemoryManipulation::MemoryFree(jump_table, regionSize);

        auto freeRegions = _GetFreeRegions();
        _SortByDistance(freeRegions, reinterpret_cast<uintptr_t>(hint_addr));

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

                jump_table = MiniDetour::MemoryManipulation::Implementation::AllocCode(reinterpret_cast<void *>(candidate), regionSize);
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

        // _AllocUsableJumpsRegion only returns a region usable from reference.
        if (jump_table != nullptr)
        {
            SPDLOG_INFO("Jump region {} is usable from {}", jump_table, reference);

            if (!MiniDetour::MemoryManipulation::Implementation::BeginCodeWrite(jump_table, _RegionSize()))
            {
                MiniDetour::MemoryManipulation::MemoryFree(jump_table, _RegionSize());
                return nullptr;
            }

            memset(jump_table, 0xCC, _RegionSize());
            MiniDetour::MemoryManipulation::Implementation::EndCodeWrite(jump_table, _RegionSize());

            jumps_regions.emplace_back();
            auto &region = *jumps_regions.rbegin();
            region.bitmap.resize(_JumpsInRegion(), false);
            region.bitmap[0]  = true;
            region.jump_table = (JumpRegion_t::JumpSlot_t *)jump_table;
        }

        return jump_table;
    }

    void *GetFreeJump(void *address_hint) { return GetFreeJump(address_hint, address_hint, _AddressesAreRelativeJumpable); }

    // Free jump slot for which isUsable(reference, slot) is true. A new region is allocated near address_hint if needed.
    void *GetFreeJump(void *address_hint, void *reference, bool (*isUsable)(void *, void *))
    {
        for (auto &region : jumps_regions)
        {
            for (size_t i = 0; i < region.bitmap.size(); ++i)
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
        SPDLOG_DEBUG("Freeing jump {}", jump);

        JumpRegion_t::JumpSlot_t *jump_addr = reinterpret_cast<JumpRegion_t::JumpSlot_t *>(jump);

        for (auto &region : jumps_regions)
        {
            if (region.jump_table <= jump_addr && jump_addr < (region.jump_table + region.bitmap.size()))
            {
                region.bitmap[jump_addr - region.jump_table] = false;
                break;
            }
        }
    }

    TrampolineSlot_t *AllocTrampolineRegion(void *addressHint, void *reference, bool (*isUsable)(void *, void *))
    {
        TrampolineSlot_t *mem = (TrampolineSlot_t *)MiniDetour::MemoryManipulation::Implementation::AllocCode(addressHint, _RegionSize());
        if (mem == nullptr || (isUsable != nullptr && !isUsable(reference, mem->data)))
        {
            if (mem != nullptr)
            {
                MiniDetour::MemoryManipulation::MemoryFree(mem, _RegionSize());
                mem = nullptr;
            }

            if (isUsable == nullptr)
                return nullptr;

            auto freeRegions = _GetFreeRegions();
            _SortByDistance(freeRegions, reinterpret_cast<uintptr_t>(addressHint));

            for (auto const &region : freeRegions)
            {
                const size_t regionSize = _RegionSize();
                if (region.End - region.Start < regionSize)
                    continue;

                const uintptr_t candidates[] = {region.Start, region.End - regionSize};
                for (auto candidate : candidates)
                {
                    if (!isUsable(reference, reinterpret_cast<void *>(candidate)))
                        continue;

                    mem = (TrampolineSlot_t *)MiniDetour::MemoryManipulation::Implementation::AllocCode(reinterpret_cast<void *>(candidate), regionSize);
                    if (mem != nullptr && isUsable(reference, mem->data))
                        break;

                    if (mem != nullptr)
                    {
                        MiniDetour::MemoryManipulation::MemoryFree(mem, regionSize);
                        mem = nullptr;
                    }
                }

                if (mem != nullptr)
                    break;
            }

            if (mem == nullptr)
                return nullptr;
        }

        if (!MiniDetour::MemoryManipulation::Implementation::BeginCodeWrite(mem, _RegionSize()))
        {
            MiniDetour::MemoryManipulation::MemoryFree(mem, _RegionSize());
            return nullptr;
        }

        memset(mem, 0, _RegionSize());
        MiniDetour::MemoryManipulation::Implementation::EndCodeWrite(mem, _RegionSize());

        trampolines_regions.emplace_back(mem);
        return mem;
    }

    uint8_t *GetFreeTrampoline(size_t mem_size, void *addressHint = nullptr, void *reference = nullptr, bool (*isUsable)(void *, void *) = nullptr)
    {
        // A larger trampoline would be written over the next slot.
        if (mem_size > sizeof(TrampolineSlot_t::data))
        {
            SPDLOG_ERROR("Trampoline of {} bytes doesn't fit in a {} bytes slot.", mem_size, sizeof(TrampolineSlot_t::data));
            return nullptr;
        }

        for (auto memory : trampolines_regions)
        {
            TrampolineSlot_t *end = memory + _RegionSize() / sizeof(TrampolineSlot_t);
            for (; memory != end; ++memory)
            {
                if (!memory->used && (isUsable == nullptr || isUsable(reference, memory->data)))
                {
                    SPDLOG_DEBUG("Using free memory at {}", (void *)memory);
                    if (!MiniDetour::MemoryManipulation::Implementation::BeginCodeWrite(memory, sizeof(TrampolineSlot_t)))
                        return nullptr;

                    memory->used = 1;
                    MiniDetour::MemoryManipulation::Implementation::EndCodeWrite(memory, sizeof(TrampolineSlot_t));
                    return memory->data;
                }
            }
        }

        TrampolineSlot_t *mem_region = AllocTrampolineRegion(addressHint, reference, isUsable);
        if (mem_region == nullptr || !MiniDetour::MemoryManipulation::Implementation::BeginCodeWrite(mem_region, sizeof(TrampolineSlot_t)))
            return nullptr;

        mem_region->used = 1;
        MiniDetour::MemoryManipulation::Implementation::EndCodeWrite(mem_region, sizeof(TrampolineSlot_t));
        SPDLOG_DEBUG("Using new memory at {}", (void *)mem_region);

        return mem_region->data;
    }

    void FreeTrampoline(void *trampoline)
    {
        SPDLOG_DEBUG("Freeing trampoline {}", trampoline);
        TrampolineSlot_t *mem = reinterpret_cast<TrampolineSlot_t *>(reinterpret_cast<uint8_t *>(trampoline) - offsetof(TrampolineSlot_t, data));

        if (!MiniDetour::MemoryManipulation::Implementation::BeginCodeWrite(mem, sizeof(TrampolineSlot_t)))
            return;

        mem->used = 0;
        MiniDetour::MemoryManipulation::Implementation::EndCodeWrite(mem, sizeof(TrampolineSlot_t));
    }
};

namespace MiniDetour
{
// The system functions the library calls to find the modules and their symbols. Calling them through the imports of the
// image that links the library (the executable, when it is linked statically) would call their replacements once they are
// replaced there, and the loader functions often are.
struct ModuleFunctions_t
{
#if defined(MINIDETOUR_OS_WINDOWS)
    // Finds a module from its name, or from an address in it (GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS).
    BOOL(WINAPI *GetModuleHandleExA)(DWORD flags, LPCSTR moduleName, HMODULE *module);
    FARPROC(WINAPI *GetProcAddress)(HMODULE module, LPCSTR name);
    DWORD(WINAPI *GetModuleFileNameW)(HMODULE module, LPWSTR fileName, DWORD size);
#elif defined(MINIDETOUR_OS_LINUX)
    int (*dlinfo)(void *handle, int request, void *info);
#elif defined(MINIDETOUR_OS_APPLE)
    void *(*dlopen)(const char *path, int mode);
    int (*dlclose)(void *handle);
    void *(*dlsym)(void *handle, const char *name);
#endif
};

// Holds what the library keeps between calls, instead of separate statics: the objects it needs (with a constructor or a
// destructor) and the values computed once and cached (like the page size, queried from the system). They are built in
// the order they are declared here, which C++ doesn't guarantee for statics.
class Globals_t
{
    // Defined once the platform functions are known. It must not use Instance(): it runs while the instance is built.
    Globals_t();

  public:
    // Values that don't change while the process runs, queried once.
    size_t PageSize;
    // Allocations are placed at a multiple of it.
    size_t AllocationGranularity;
    // Bounds of the user address space, MaxUserAddress being its end.
    uintptr_t MinUserAddress;
    uintptr_t MaxUserAddress;
    // Whether memory can be writable and executable at the same time, which code writes rely on. When it can't (Apple
    // Silicon, hardened runtime on macOS), they go through the platform JIT memory instead.
    bool WritableExecutableMemory;
    // Taken when the library starts, before any import of its image can be replaced.
    ModuleFunctions_t ModuleFunctions;

    // Serializes the operations that write code or import/export tables: they share the memory manager slots and
    // change the rights of pages shared between hooks, and hooks can be set from several threads.
    std::mutex HookMutex;
    MemoryManager_t Memory;

    // Never destroyed: Hook_t objects with static storage restore their hook (and use the globals) during static
    // destruction, possibly after the globals would have been destroyed.
    static Globals_t &Instance()
    {
        static Globals_t *instance = new Globals_t();
        return *instance;
    }
};
} // namespace MiniDetour

// Writes an absolute jump in a jump slot.
static bool _WriteJumpSlot(void *jump, void *destination, int sourceMode, int destinationMode)
{
    const size_t jumpSize = AbsJump_t::GetMaxOpcodeSize();
    if (!MiniDetour::MemoryManipulation::Implementation::BeginCodeWrite(jump, jumpSize))
        return false;

    AbsJump_t::WriteOpcodes(jump, destination, sourceMode, destinationMode);
    MiniDetour::MemoryManipulation::Implementation::EndCodeWrite(jump, jumpSize);
    return true;
}

// Writes value in a table entry (import slot, export address) and gives its previous value. The other rights of its
// page are kept: the entry is data, so execution is never added, but it may share a page with code that must stay
// executable.
template <typename T>
static bool _ExchangeTableEntry(T *entry, T value, T *previous)
{
    MiniDetour::MemoryManipulation::RegionInfos_t infos;
    MiniDetour::MemoryManipulation::GetRegionInfos(entry, &infos);
    if (infos.Rights == MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
        return false;

    auto writable = static_cast<MiniDetour::MemoryManipulation::MemoryRights>(infos.Rights | MiniDetour::MemoryManipulation::MemoryRights::mem_w);
    if (!MiniDetour::MemoryManipulation::MemoryProtect(entry, sizeof(*entry), writable))
        return false;

    *previous = *entry;
    *entry    = value;
    MiniDetour::MemoryManipulation::MemoryProtect(entry, sizeof(*entry), infos.Rights);
    return true;
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
// The platform gives _QueryPageSize, _QueryAllocationGranularity, _QueryMinUserAddress, _QueryMaxUserAddress,
// _QueryWritableExecutableMemory and _QueryModuleFunctions.
Globals_t::Globals_t()
    : PageSize(MemoryManipulation::Implementation::_QueryPageSize())
    , AllocationGranularity(MemoryManipulation::Implementation::_QueryAllocationGranularity())
    , MinUserAddress(MemoryManipulation::Implementation::_QueryMinUserAddress())
    , MaxUserAddress(MemoryManipulation::Implementation::_QueryMaxUserAddress())
    , WritableExecutableMemory(MemoryManipulation::Implementation::_QueryWritableExecutableMemory())
    , ModuleFunctions(ModuleManipulation::Implementation::_QueryModuleFunctions())
{
}
} // namespace MiniDetour

namespace MiniDetour
{
namespace MemoryManipulation
{
namespace Implementation
{

// Allocates as close as possible to the hint, so hooks can reach the memory with relative jumps: allocAt(address, size)
// allocates at this exact address, allocAnywhere(size) anywhere.
template <typename AllocAt, typename AllocAnywhere>
static void *_AllocNear(void *_addressHint, size_t size, AllocAt allocAt, AllocAnywhere allocAnywhere)
{
    const uintptr_t minAddress = Globals_t::Instance().MinUserAddress;
    const uintptr_t maxAddress = Globals_t::Instance().MaxUserAddress;
    if (reinterpret_cast<uintptr_t>(_addressHint) >= maxAddress)
        _addressHint = reinterpret_cast<void *>(maxAddress - 1);

    auto pageSize    = Globals_t::Instance().PageSize;
    auto addressHint = reinterpret_cast<uintptr_t>(PageRound(_addressHint, pageSize));
    size             = _PageAddrSize((void *)addressHint, size, pageSize);

    if (_addressHint == nullptr)
        return allocAnywhere(size);

    auto freeRegions = _GetFreeRegions();

    // Only keep the part of the free regions the process can allocate.
    for (auto &region : freeRegions)
    {
        region.Start = std::max<uintptr_t>(region.Start, minAddress);
        region.End   = std::min<uintptr_t>(region.End, maxAddress);
    }
    freeRegions.erase(std::remove_if(freeRegions.begin(), freeRegions.end(), [](RegionInfos_t const &region) { return region.Start >= region.End; }), freeRegions.end());

    _SortByDistance(freeRegions, addressHint);

    const size_t granularity = Globals_t::Instance().AllocationGranularity;
    for (auto const &region : freeRegions)
    {
        void *address = _AllocInFreeRegion(region, addressHint, size, granularity, [&](uintptr_t allocAddress) { return allocAt((void *)allocAddress, size); });

        if (address != nullptr)
            return address;
    }

    // Fallback to anywhere alloc
    return allocAnywhere(size);
}

// The platform gives _MemoryAllocAt and _MemoryAllocAnywhere.
void *MemoryAlloc(void *addressHint, size_t size, MemoryRights rights)
{
    return _AllocNear(
        addressHint,
        size,
        [rights](void *address, size_t allocSize) { return _MemoryAllocAt(address, allocSize, rights); },
        [rights](size_t allocSize) { return _MemoryAllocAnywhere(allocSize, rights); });
}

// Code memory is read/execute, and made writable while it is written. Without writable and executable memory, it is
// the platform JIT memory.
static void *_CodeAllocAt(void *address, size_t size)
{
#if defined(MINIDETOUR_JIT_CODE_MEMORY)
    if (!Globals_t::Instance().WritableExecutableMemory)
        return _JitCodeAllocAt(address, size);
#endif

    return _MemoryAllocAt(address, size, MemoryRights::mem_rx);
}

static void *_CodeAllocAnywhere(size_t size)
{
#if defined(MINIDETOUR_JIT_CODE_MEMORY)
    if (!Globals_t::Instance().WritableExecutableMemory)
        return _JitCodeAllocAnywhere(size);
#endif

    return _MemoryAllocAnywhere(size, MemoryRights::mem_rx);
}

bool BeginCodeWrite(void *address, size_t size)
{
#if defined(MINIDETOUR_JIT_CODE_MEMORY)
    if (!Globals_t::Instance().WritableExecutableMemory)
        return _BeginJitCodeWrite(address, size);
#endif

    return MemoryProtect(address, size, MemoryRights::mem_rwx, nullptr);
}

void EndCodeWrite(void *address, size_t size)
{
#if defined(MINIDETOUR_JIT_CODE_MEMORY)
    if (!Globals_t::Instance().WritableExecutableMemory)
        _EndJitCodeWrite(address, size);
    else
#endif
        MemoryProtect(address, size, MemoryRights::mem_rx, nullptr);

    FlushInstructionCache(address, size);
}

void *AllocCode(void *addressHint, size_t size)
{
    return _AllocNear(
        addressHint,
        size,
        [](void *address, size_t allocSize) { return _CodeAllocAt(address, allocSize); },
        [](size_t allocSize) { return _CodeAllocAnywhere(allocSize); });
}

size_t WriteAbsoluteJump(void *address, void *destination)
{
    int source_mode      = _GetCodeMode(address);
    int destination_mode = _GetCodeMode(destination);

    if (address == nullptr)
        return AbsJump_t::GetOpcodeSize(destination, source_mode, destination_mode);

    return AbsJump_t::WriteOpcodes(address, destination, source_mode, destination_mode);
}
} // namespace Implementation
} // namespace MemoryManipulation
} // namespace MiniDetour

// Writes over the code of a hooked function, which the library doesn't own. Prepare runs before the other threads are
// frozen (it may allocate), Write while they are, and Finish once they run again.
class FunctionCodeWriter_t
{
    void *_Address;
    size_t _Size;
    bool _ByRemap;
    MiniDetour::MemoryManipulation::MemoryRights _OldRights;

  public:
    FunctionCodeWriter_t()
        : _Address(nullptr)
        , _Size(0)
        , _ByRemap(false)
        , _OldRights(MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
    {
    }

    bool Prepare(void *address, size_t size)
    {
#if defined(MINIDETOUR_JIT_CODE_MEMORY)
        // Without writable and executable memory, the code is written in a copy of its pages, which replaces them: they
        // stay executable all along.
        if (!MiniDetour::Globals_t::Instance().WritableExecutableMemory)
        {
            _Address = address;
            _Size    = size;
            _ByRemap = true;
            return true;
        }
#endif

        // Otherwise the code is made writable. Its rights are given back after: forcing mem_rx would remove the write
        // access of code that needs it (JIT buffers). If they couldn't be read, the code is at least made executable
        // again.
        if (!MiniDetour::MemoryManipulation::MemoryProtect(address, size, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx, &_OldRights))
            return false;

        _Address = address;
        _Size    = size;
        return true;
    }

    bool Write(const void *data)
    {
#if defined(MINIDETOUR_JIT_CODE_MEMORY)
        if (_ByRemap)
        {
            if (!MiniDetour::MemoryManipulation::Implementation::_WriteFunctionCodeByRemap(_Address, data, _Size))
                return false;
        }
        else
#endif
            memcpy(_Address, data, _Size);

        MiniDetour::MemoryManipulation::FlushInstructionCache(_Address, _Size);
        return true;
    }

    void Finish()
    {
        if (_Address == nullptr || _ByRemap)
            return;

        if (_OldRights == MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
            _OldRights = MiniDetour::MemoryManipulation::MemoryRights::mem_rx;

        MiniDetour::MemoryManipulation::MemoryProtect(_Address, _Size, _OldRights);
        _Address = nullptr;
    }
};

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

    // Only used through a handle: never copied nor moved.
    Hook_t(Hook_t const &)            = delete;
    Hook_t &operator=(Hook_t const &) = delete;

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
                Globals_t::Instance().Memory.FreeJump(_TrampolineAddress);
                _TrampolineAddress = nullptr;
            }

            Globals_t::Instance().Memory.FreeTrampoline(_OriginalTrampolineAddress);
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

        CodeDisasm_t disasm;

        // Before reading the mode: on ARM, a PLT entry and the function it leads to can use different modes.
        _EnterRecursiveThunk(func);
        const int code_mode = _GetCodeMode(func);
        func                = _GetCodeAddress(func);

        if (_InitDisasm(disasm, code_mode) != cs_err::CS_ERR_OK)
            return false;

        size_t relativeJumpSize          = RelJump_t::GetOpcodeSize(func, reinterpret_cast<void *>(static_cast<uintptr_t>(0xfffffff0)), code_mode, code_mode);
        size_t absoluteJumpSize          = AbsJump_t::GetOpcodeSize(func, code_mode, code_mode);
        size_t smallest_jump_size        = std::min(relativeJumpSize, absoluteJumpSize);
        size_t relocatedOriginalCodeSize = 0;

        return _GetRelocatableSize(func, relocatedOriginalCodeSize, false, disasm, absoluteJumpSize) >= smallest_jump_size;
    }

    static bool _InitializeHookState(
        void *&functionToHook,
        void *&newFunction,
        bool ignoreRelocations,
        CodeDisasm_t &disasm,
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
        relativeJumpSize = RelJump_t::GetMaxOpcodeSize();
        absoluteJumpSize = AbsJump_t::GetOpcodeSize(newFunction, func_mode, hook_mode);
        relocatableSize  = _GetRelocatableSize(functionToHook, relocatedOriginalCodeSize, ignoreRelocations, disasm, absoluteJumpSize);

        return true;
    }

    static bool ReplaceFunction(void *functionToReplace, void *newFunction)
    {
        int func_mode;
        int hook_mode;
        CodeDisasm_t disasm;

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

        // The new start of the function, with the original bytes after the jump.
        std::vector<uint8_t> code(reinterpret_cast<uint8_t *>(functionToReplace), reinterpret_cast<uint8_t *>(functionToReplace) + relocatableSize);
        void *jump_mem = nullptr;
        if (relocatableSize >= absoluteJumpSize)
        {
            AbsJump_t::WriteOpcodes(code.data(), newFunction, func_mode, hook_mode);
        }
        else
        {
            // Setup the trampoline
            jump_mem = Globals_t::Instance().Memory.GetFreeJump(functionToReplace);
            if (jump_mem == nullptr)
                return false;

            if (!_WriteJumpSlot(jump_mem, newFunction, func_mode, hook_mode))
            {
                Globals_t::Instance().Memory.FreeJump(jump_mem);
                return false;
            }

            RelJump_t::WriteOpcodes(code.data(), functionToReplace, jump_mem, func_mode, hook_mode);
        }

        FunctionCodeWriter_t writer;
        bool written = false;
        if (writer.Prepare(functionToReplace, relocatableSize))
        {
            OtherThreadsFreezer_t freezer;
            written = freezer.Freeze(functionToReplace, relocatableSize) && writer.Write(code.data());
        }
        writer.Finish();

        if (!written && jump_mem != nullptr)
            Globals_t::Instance().Memory.FreeJump(jump_mem);

        return written;
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
        CodeDisasm_t disasm;

        size_t relativeJumpSize          = 0;
        size_t absoluteJumpSize          = 0;
        size_t relocatableSize           = 0;
        size_t relocatedOriginalCodeSize = 0;

        if (!_InitializeHookState(functionToHook, newFunction, false, disasm, relativeJumpSize, absoluteJumpSize, relocatableSize, relocatedOriginalCodeSize, func_mode, hook_mode))
            return nullptr;

        size_t totalOriginalTrampolineSize = 0;
        // Finished in the error path too once the function was prepared for writing.
        FunctionCodeWriter_t writer;
        // The jump slot the hook goes through, freed in the error path. The size of the jump written in the function.
        void *jump_mem  = nullptr;
        size_t hookSize = relativeJumpSize;
        SPDLOG_INFO("Needed relocatable size: found({}), rel({})", relocatableSize, relativeJumpSize);

        if (relocatableSize < relativeJumpSize)
        {
            SPDLOG_ERROR("Relocatable size was too small {} < {}", relocatableSize, relativeJumpSize);
            goto error;
        }

        // The function jumps to a jump slot next to it, which jumps to the detour. When no slot can be reached from the
        // function (no free memory in range of a relative jump, like next to the macOS shared cache on ARM64), the
        // function jumps straight to the detour with an absolute jump, if it is long enough for one.
        jump_mem = Globals_t::Instance().Memory.GetFreeJump(functionToHook);
        if (jump_mem == nullptr)
        {
            if (relocatableSize < absoluteJumpSize)
            {
                SPDLOG_ERROR("Failed to get memory for jump, and the function is too small for an absolute jump.");
                goto error;
            }

            hookSize = absoluteJumpSize;
        }

        // Only the bytes overwritten by the jump are saved and restored: the next ones may be changed by someone else
        // while the hook is set.
        _SavedCode.assign(reinterpret_cast<uint8_t *>(functionToHook), reinterpret_cast<uint8_t *>(functionToHook) + hookSize);

        // Upper bound of the trampoline code: the relocated code + the jump back to the function (its size can depend
        // on its destination). Used to check the slot size, and to protect and flush the whole trampoline.
        totalOriginalTrampolineSize = relocatedOriginalCodeSize + AbsJump_t::GetMaxOpcodeSize();

#if defined(MINIDETOUR_ARCH_ARM64)
        _OriginalTrampolineAddress = Globals_t::Instance().Memory.GetFreeTrampoline(totalOriginalTrampolineSize, functionToHook, functionToHook, _IsTrampolineNearFunction);
#else
        _OriginalTrampolineAddress = Globals_t::Instance().Memory.GetFreeTrampoline(totalOriginalTrampolineSize);
#endif
        if (_OriginalTrampolineAddress == nullptr)
        {
            SPDLOG_ERROR("Failed to get memory for trampoline.");
            goto error;
        }

        if (!MemoryManipulation::Implementation::BeginCodeWrite(_OriginalTrampolineAddress, totalOriginalTrampolineSize))
        {
            SPDLOG_ERROR("Failed to make the trampoline memory writable ({} : {}).", _OriginalTrampolineAddress, totalOriginalTrampolineSize);
            goto error;
        }

        {
            // A failed relocation leaves the trampoline without its jump back to the original function.
            const size_t relocatedSize = _RelocateCode(functionToHook, _OriginalTrampolineAddress, disasm, hookSize, func_mode);
            MemoryManipulation::Implementation::EndCodeWrite(_OriginalTrampolineAddress, totalOriginalTrampolineSize);
            if (relocatedSize < hookSize)
            {
                SPDLOG_ERROR("Failed to relocate code.");
                goto error;
            }
        }

        if (!writer.Prepare(functionToHook, _SavedCode.size()))
        {
            MiniDetour::MemoryManipulation::RegionInfos_t regionInfos;
            MemoryManipulation::GetRegionInfos(functionToHook, &regionInfos);
            SPDLOG_ERROR("Failed to make the function memory writable ({} : {}), current rights: {}.", functionToHook, _SavedCode.size(), regionInfos.Rights);
            goto error;
        }

        {
            if (jump_mem != nullptr)
            {
                SPDLOG_INFO("Relative hook, through the jump slot at {}", jump_mem);
                if (!_WriteJumpSlot(jump_mem, newFunction, func_mode, hook_mode))
                {
                    SPDLOG_ERROR("Failed to write the jump slot.");
                    goto error;
                }
            }
            else
            {
                SPDLOG_INFO("Absolute hook");
            }

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

            // The relative jump has the mode of the hooked function, as its jump slot. A shorter encoding than the saved
            // size keeps the original bytes after it.
            _HookCode = _SavedCode;
            if (jump_mem != nullptr)
                RelJump_t::WriteOpcodes(_HookCode.data(), functionToHook, jump_mem, func_mode, func_mode);
            else
                AbsJump_t::WriteOpcodes(_HookCode.data(), newFunction, func_mode, hook_mode);
            {
                // Nothing can be logged while the other threads are suspended: it would allocate.
                bool frozen  = false;
                bool written = false;
                {
                    OtherThreadsFreezer_t freezer;
                    frozen  = freezer.Freeze(functionToHook, _HookCode.size());
                    written = frozen && writer.Write(_HookCode.data());
                }

                if (!written)
                {
                    SPDLOG_ERROR(frozen ? "Failed to write the hook." : "A thread is running the code to hook.");
                    goto error;
                }
            }

#ifdef USE_SPDLOG
            {
                size_t dbg_opcode_size = hookSize;
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

        writer.Finish();

        _OriginalFuncAddress = functionToHook;
        _DetourFunc          = newFunction;

        _OriginalTrampolineCallAddress = _GetCallAddress(_OriginalTrampolineAddress, func_mode);
        _DetourCallFunc                = _GetCallAddress(_DetourFunc, hook_mode);

        return _OriginalTrampolineCallAddress;
    error:
        // The function code wasn't modified: only its rights may have been.
        writer.Finish();

        if (jump_mem != nullptr)
            Globals_t::Instance().Memory.FreeJump(jump_mem);

        _SavedCode.clear();
        _HookCode.clear();

        if (_OriginalTrampolineAddress != nullptr)
        {
            Globals_t::Instance().Memory.FreeTrampoline(_OriginalTrampolineAddress);
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

        // buffer has the size of _HookCode.
        if (std::equal(buffer.begin(), buffer.end(), _HookCode.begin()))
        { // Our hook code is still there, we can restore the old instructions.
            FunctionCodeWriter_t writer;
            if (!writer.Prepare(_OriginalFuncAddress, _SavedCode.size()))
            {
                writer.Finish();
                return res;
            }

            bool written = false;
            {
                OtherThreadsFreezer_t freezer;
                written = freezer.Freeze(_OriginalFuncAddress, _SavedCode.size()) && writer.Write(_SavedCode.data());
            }
            writer.Finish();

            if (!written)
            {
                // The hook stays in place: restoring it can be tried again.
                SPDLOG_ERROR("The hooked code couldn't be restored (a thread may be running it).");
                return nullptr;
            }

            Reset(true);
            SPDLOG_INFO("Restored hook");
        }
        else
        {
            // Our Hook code has been modified, we have to nullify the hook:
            // the jump to the detour now goes to the original function trampoline, which stays allocated.
            // An absolute hook jumps to the detour directly: nothing can be redirected, the hook stays in place.
            if (_TrampolineAddress == nullptr)
            {
                SPDLOG_ERROR("The hooked code was changed by someone else, and the hook has no jump slot to bypass the detour.");
                return nullptr;
            }

            // The jump is reached from the hooked function and goes to its relocated code: both use the function mode.
            const int func_mode = _GetCodeMode(_OriginalTrampolineCallAddress);
            if (!_WriteJumpSlot(_TrampolineAddress, _OriginalTrampolineAddress, func_mode, func_mode))
                return res;

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
    return MiniDetour::Globals_t::Instance().PageSize;
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

    std::lock_guard<std::mutex> lock(MiniDetour::Globals_t::Instance().HookMutex);
    return MiniDetour::ModuleManipulation::Implementation::ReplaceModuleExports(moduleHandle, exportReplaceDetails, exportReplaceDetailsCount);
}

MINIDETOUR_EXPORT(size_t)
MiniDetourModuleManipulationRestoreModuleExports(void *moduleHandle, MiniDetourModuleManipulationExportReplaceParameter_t *exportReplaceDetails, size_t exportReplaceDetailsCount)
{
    if (exportReplaceDetails == nullptr && exportReplaceDetailsCount != 0)
        return 0;

    std::lock_guard<std::mutex> lock(MiniDetour::Globals_t::Instance().HookMutex);
    return MiniDetour::ModuleManipulation::Implementation::RestoreModuleExports(moduleHandle, exportReplaceDetails, exportReplaceDetailsCount);
}

MINIDETOUR_EXPORT(size_t)
MiniDetourModuleManipulationReplaceModuleIATs(void *moduleHandle, MiniDetourModuleManipulationIATReplaceParameter_t *iatReplaceDetails, size_t iatReplaceDetailsCount)
{
    if (iatReplaceDetails == nullptr && iatReplaceDetailsCount != 0)
        return 0;

    std::lock_guard<std::mutex> lock(MiniDetour::Globals_t::Instance().HookMutex);
    return MiniDetour::ModuleManipulation::Implementation::ReplaceModuleIATs(moduleHandle, iatReplaceDetails, iatReplaceDetailsCount);
}

MINIDETOUR_EXPORT(size_t)
MiniDetourModuleManipulationRestoreModuleIATs(void *moduleHandle, MiniDetourModuleManipulationIATReplaceParameter_t *iatReplaceDetails, size_t iatReplaceDetailsCount)
{
    if (iatReplaceDetails == nullptr && iatReplaceDetailsCount != 0)
        return 0;

    std::lock_guard<std::mutex> lock(MiniDetour::Globals_t::Instance().HookMutex);
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
    std::lock_guard<std::mutex> lock(MiniDetour::Globals_t::Instance().HookMutex);
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
    std::lock_guard<std::mutex> lock(MiniDetour::Globals_t::Instance().HookMutex);
    auto hook = reinterpret_cast<MiniDetour::Implementation::Hook_t *>(handle);
    if (hook == nullptr || function_to_hook == nullptr || new_function == nullptr)
        return nullptr;

    return hook->HookFunc(function_to_hook, new_function);
}

MINIDETOUR_EXPORT(void *) MiniDetourHookTRestoreFunction(minidetour_hook_handle_t handle)
{
    std::lock_guard<std::mutex> lock(MiniDetour::Globals_t::Instance().HookMutex);
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

    std::lock_guard<std::mutex> lock(MiniDetour::Globals_t::Instance().HookMutex);
    return MiniDetour::Implementation::Hook_t::ReplaceFunction(function_to_replace, new_function) ? 1 : 0;
}
