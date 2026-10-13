#ifndef MINI_DETOUR_MACOS_H
#define MINI_DETOUR_MACOS_H

#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_prot.h>
#include <mach/vm_map.h>
#include <mach/vm_param.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <dlfcn.h>
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <libproc.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>

#if defined(MINIDETOUR_ARCH_X64) || defined(MINIDETOUR_ARCH_ARM64)

using MachHeader_t     = mach_header_64;
using LoadCommand_t    = load_command;
using SegmentCommand_t = segment_command_64;
using Section_t        = section_64;
using SymTabCommand_t  = symtab_command;
using NList_t          = nlist_64;

#define MachHeaderMagic MH_MAGIC_64
#define LC_SEGMENT_ARCH LC_SEGMENT_64

#elif defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_ARM)

using MachHeader_t     = mach_header;
using LoadCommand_t    = load_command;
using SegmentCommand_t = segment_command;
using Section_t        = section;
using SymTabCommand_t  = symtab_command;
using NList_t          = nlist;

#define MachHeaderMagic MH_MAGIC
#define LC_SEGMENT_ARCH LC_SEGMENT

#endif

#ifdef USE_SPDLOG

static std::string kern_return_t_2_str(kern_return_t v)
{
#define CASE_TO_STRING(x) \
    case x: return #x;
    switch (v)
    {
        CASE_TO_STRING(KERN_SUCCESS);
        CASE_TO_STRING(KERN_INVALID_ADDRESS);
        CASE_TO_STRING(KERN_PROTECTION_FAILURE);
        CASE_TO_STRING(KERN_NO_SPACE);
        CASE_TO_STRING(KERN_INVALID_ARGUMENT);
        CASE_TO_STRING(KERN_FAILURE);
        CASE_TO_STRING(KERN_RESOURCE_SHORTAGE);
        CASE_TO_STRING(KERN_NOT_RECEIVER);
        CASE_TO_STRING(KERN_NO_ACCESS);
        CASE_TO_STRING(KERN_MEMORY_FAILURE);
        CASE_TO_STRING(KERN_MEMORY_ERROR);
        CASE_TO_STRING(KERN_ALREADY_IN_SET);
        CASE_TO_STRING(KERN_NOT_IN_SET);
        CASE_TO_STRING(KERN_NAME_EXISTS);
        CASE_TO_STRING(KERN_ABORTED);
        CASE_TO_STRING(KERN_INVALID_NAME);
        CASE_TO_STRING(KERN_INVALID_TASK);
        CASE_TO_STRING(KERN_INVALID_RIGHT);
        CASE_TO_STRING(KERN_INVALID_VALUE);
        CASE_TO_STRING(KERN_UREFS_OVERFLOW);
        CASE_TO_STRING(KERN_INVALID_CAPABILITY);
        CASE_TO_STRING(KERN_RIGHT_EXISTS);
        CASE_TO_STRING(KERN_INVALID_HOST);
        CASE_TO_STRING(KERN_MEMORY_PRESENT);
        CASE_TO_STRING(KERN_MEMORY_DATA_MOVED);
        CASE_TO_STRING(KERN_MEMORY_RESTART_COPY);
        CASE_TO_STRING(KERN_INVALID_PROCESSOR_SET);
        CASE_TO_STRING(KERN_POLICY_LIMIT);
        CASE_TO_STRING(KERN_INVALID_POLICY);
        CASE_TO_STRING(KERN_INVALID_OBJECT);
        CASE_TO_STRING(KERN_ALREADY_WAITING);
        CASE_TO_STRING(KERN_DEFAULT_SET);
        CASE_TO_STRING(KERN_EXCEPTION_PROTECTED);
        CASE_TO_STRING(KERN_INVALID_LEDGER);
        CASE_TO_STRING(KERN_INVALID_MEMORY_CONTROL);
        CASE_TO_STRING(KERN_INVALID_SECURITY);
        CASE_TO_STRING(KERN_NOT_DEPRESSED);
        CASE_TO_STRING(KERN_TERMINATED);
        CASE_TO_STRING(KERN_LOCK_SET_DESTROYED);
        CASE_TO_STRING(KERN_LOCK_UNSTABLE);
        CASE_TO_STRING(KERN_LOCK_OWNED);
        CASE_TO_STRING(KERN_LOCK_OWNED_SELF);
        CASE_TO_STRING(KERN_SEMAPHORE_DESTROYED);
        CASE_TO_STRING(KERN_RPC_SERVER_TERMINATED);
        CASE_TO_STRING(KERN_RPC_TERMINATE_ORPHAN);
        CASE_TO_STRING(KERN_RPC_CONTINUE_ORPHAN);
        CASE_TO_STRING(KERN_NOT_SUPPORTED);
        CASE_TO_STRING(KERN_NODE_DOWN);
        CASE_TO_STRING(KERN_NOT_WAITING);
        CASE_TO_STRING(KERN_OPERATION_TIMED_OUT);
        CASE_TO_STRING(KERN_CODESIGN_ERROR);
        CASE_TO_STRING(KERN_POLICY_STATIC);
        CASE_TO_STRING(KERN_INSUFFICIENT_BUFFER_SIZE);
    }
#undef CASE_TO_STRING

    return std::string("Unknown value: ") + std::to_string(v);
}

#endif

// Suspends the other threads of the process while hooked code is written: a thread running the bytes being written
// could execute half of the old and half of the new instructions.
class _OtherThreadsFreezer_t
{
    // Allocated by task_threads (not on the heap). The threads that aren't suspended are set to MACH_PORT_NULL.
    thread_act_array_t _Threads;
    mach_msg_type_number_t _ThreadCount;

    static bool _GetInstructionPointer(thread_act_t thread, uintptr_t &ip)
    {
#if defined(MINIDETOUR_ARCH_X64)
        x86_thread_state64_t state;
        mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
        if (thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)&state, &count) != KERN_SUCCESS)
            return false;

        ip = static_cast<uintptr_t>(state.__rip);
#elif defined(MINIDETOUR_ARCH_X86)
        x86_thread_state32_t state;
        mach_msg_type_number_t count = x86_THREAD_STATE32_COUNT;
        if (thread_get_state(thread, x86_THREAD_STATE32, (thread_state_t)&state, &count) != KERN_SUCCESS)
            return false;

        ip = static_cast<uintptr_t>(state.__eip);
#elif defined(MINIDETOUR_ARCH_ARM64)
        arm_thread_state64_t state;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count) != KERN_SUCCESS)
            return false;

        ip = static_cast<uintptr_t>(arm_thread_state64_get_pc(state));
#elif defined(MINIDETOUR_ARCH_ARM)
        arm_thread_state_t state;
        mach_msg_type_number_t count = ARM_THREAD_STATE_COUNT;
        if (thread_get_state(thread, ARM_THREAD_STATE, (thread_state_t)&state, &count) != KERN_SUCCESS)
            return false;

        ip = static_cast<uintptr_t>(state.__pc);
#endif
        return true;
    }

    // Suspends every other thread. Fails if one of them is inside the code (at its first byte is fine, the instruction
    // there is replaced as a whole). No heap allocation is done while threads are suspended: one of them can hold the
    // malloc lock. thread_suspend returns once the thread is stopped.
    bool _TryFreeze(uintptr_t code, size_t size)
    {
        if (task_threads(mach_task_self(), &_Threads, &_ThreadCount) != KERN_SUCCESS)
        {
            _Threads     = nullptr;
            _ThreadCount = 0;
            return false;
        }

        const thread_act_t self = mach_thread_self();
        bool inside             = false;
        for (mach_msg_type_number_t i = 0; i < _ThreadCount; ++i)
        {
            if (_Threads[i] == self || thread_suspend(_Threads[i]) != KERN_SUCCESS)
            {
                mach_port_deallocate(mach_task_self(), _Threads[i]);
                _Threads[i] = MACH_PORT_NULL;
                continue;
            }

            uintptr_t ip;
            if (_GetInstructionPointer(_Threads[i], ip) && ip > code && ip < code + size)
                inside = true;
        }
        mach_port_deallocate(mach_task_self(), self);

        return !inside;
    }

  public:
    _OtherThreadsFreezer_t()
        : _Threads(nullptr)
        , _ThreadCount(0)
    {
    }

    ~_OtherThreadsFreezer_t() { Unfreeze(); }

    // Retries a few times when a thread is inside the code: it is most likely only passing through.
    bool Freeze(void *code, size_t size)
    {
        for (int attempt = 0; attempt < 5; ++attempt)
        {
            if (_TryFreeze(reinterpret_cast<uintptr_t>(code), size))
                return true;

            Unfreeze();
            usleep(1000);
        }

        return false;
    }

    void Unfreeze()
    {
        if (_Threads == nullptr)
            return;

        // Every thread is resumed before anything else is called: those functions could be hooked, and their detour
        // must not run while threads are still suspended (one of them could hold a lock it needs).
        for (mach_msg_type_number_t i = 0; i < _ThreadCount; ++i)
        {
            if (_Threads[i] != MACH_PORT_NULL)
                thread_resume(_Threads[i]);
        }

        for (mach_msg_type_number_t i = 0; i < _ThreadCount; ++i)
        {
            if (_Threads[i] != MACH_PORT_NULL)
                mach_port_deallocate(mach_task_self(), _Threads[i]);
        }

        vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(_Threads), _ThreadCount * sizeof(thread_act_t));
        _Threads     = nullptr;
        _ThreadCount = 0;
    }
};

// Calls callback(loadCommand) for the load commands of an image, until it returns false.
template <typename Callback>
static void _ForEachLoadCommand(const MachHeader_t *header, Callback callback)
{
    auto loadCommand = reinterpret_cast<const LoadCommand_t *>(header + 1);
    for (uint32_t i = 0; i < header->ncmds; ++i, loadCommand = reinterpret_cast<const LoadCommand_t *>(reinterpret_cast<uintptr_t>(loadCommand) + loadCommand->cmdsize))
    {
        if (!callback(loadCommand))
            return;
    }
}

// First load command of an image with this cmd, nullptr if it has none.
template <typename Command>
static const Command *_FindLoadCommand(const MachHeader_t *header, uint32_t cmd)
{
    const Command *result = nullptr;
    _ForEachLoadCommand(
        header,
        [&](const LoadCommand_t *loadCommand)
        {
            if (loadCommand->cmd != cmd)
                return true;

            result = reinterpret_cast<const Command *>(loadCommand);
            return false;
        });

    return result;
}

// Segment of an image by name, nullptr if it has none.
static const SegmentCommand_t *_FindSegment(const MachHeader_t *header, const char *name)
{
    const SegmentCommand_t *result = nullptr;
    _ForEachLoadCommand(
        header,
        [&](const LoadCommand_t *loadCommand)
        {
            auto segment = reinterpret_cast<const SegmentCommand_t *>(loadCommand);
            if (loadCommand->cmd != LC_SEGMENT_ARCH || strncmp(segment->segname, name, sizeof(segment->segname)) != 0)
                return true;

            result = segment;
            return false;
        });

    return result;
}

// Where the file offsets of the __LINKEDIT data (symbol tables, export trie) are mapped, 0 without __LINKEDIT. Images in
// the shared cache too: their __LINKEDIT is mapped, at the link address of the cache plus its slide.
static uintptr_t _GetLinkEditBase(const MachHeader_t *header, uintptr_t slide)
{
    const SegmentCommand_t *linkEdit = _FindSegment(header, SEG_LINKEDIT);
    return linkEdit != nullptr ? slide + linkEdit->vmaddr - linkEdit->fileoff : 0;
}

namespace MiniDetour
{
namespace MemoryManipulation
{
namespace Implementation
{
static size_t _MemoryProtectRightsToNative(MemoryRights rights)
{
    switch (rights)
    {
        case MemoryRights::mem_r: return VM_PROT_READ;
        case MemoryRights::mem_w: return VM_PROT_WRITE;
        case MemoryRights::mem_x: return VM_PROT_EXECUTE;
        case MemoryRights::mem_rw: return VM_PROT_WRITE | VM_PROT_READ;
        case MemoryRights::mem_rx: return VM_PROT_READ | VM_PROT_EXECUTE;
        case MemoryRights::mem_wx: return VM_PROT_WRITE | VM_PROT_EXECUTE;
        case MemoryRights::mem_rwx: return VM_PROT_WRITE | VM_PROT_READ | VM_PROT_EXECUTE;

        default: return VM_PROT_NONE;
    }
}

// __PAGEZERO is reserved from 0 up to the main executable (its end moves with the ASLR slide), but mach_vm_region
// doesn't report it: nothing can be allocated there.
static mach_vm_address_t _PageZeroEnd()
{
    // The executable isn't always image 0: libraries inserted with DYLD_INSERT_LIBRARIES come first.
    const MachHeader_t *header = nullptr;
    uint32_t imageIndex        = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); ++i)
    {
        auto imageHeader = reinterpret_cast<const MachHeader_t *>(_dyld_get_image_header(i));
        if (imageHeader != nullptr && imageHeader->filetype == MH_EXECUTE)
        {
            header     = imageHeader;
            imageIndex = i;
            break;
        }
    }

    if (header == nullptr)
        return 0;

    const SegmentCommand_t *pageZero = _FindSegment(header, SEG_PAGEZERO);
    return pageZero != nullptr ? pageZero->vmaddr + pageZero->vmsize + _dyld_get_image_vmaddr_slide(imageIndex) : 0;
}

// The file mapped at address (image, shared cache, mapped file), as much as fits in a name of nameSize bytes.
static void _GetRegionName(uintptr_t address, char *name, size_t nameSize)
{
    name[0] = '\0';
    if (nameSize < 2)
        return;

    char path[PROC_PIDPATHINFO_MAXSIZE];
    const int length = proc_regionfilename(getpid(), address, path, sizeof(path));
    if (length <= 0)
        return;

    const size_t copySize = std::min(static_cast<size_t>(length), nameSize - 1);
    memcpy(name, path, copySize);
    name[copySize] = '\0';
}

static MemoryRights _NativeToMemoryRights(vm_prot_t protection)
{
    MemoryRights rights = MemoryRights::mem_none;
    if (protection & VM_PROT_READ)
        rights = static_cast<MemoryRights>(rights | MemoryRights::mem_r);

    if (protection & VM_PROT_WRITE)
        rights = static_cast<MemoryRights>(rights | MemoryRights::mem_w);

    if (protection & VM_PROT_EXECUTE)
        rights = static_cast<MemoryRights>(rights | MemoryRights::mem_x);

    return rights;
}

// The first mapping at or after *address. The dyld shared cache is a submap: mach_vm_region describes it as one 1 GB
// region with the protection of the submap entry (read only), not the ones of its pages (code is read/execute), so the
// submaps are walked down to their mappings. *submapEnd is the end of the submap holding the mapping, 0 if there is
// none: the memory between the mappings of a submap is reserved, not free.
static bool _NextMapping(mach_vm_address_t *address, mach_vm_size_t *size, vm_prot_t *protection, mach_vm_address_t *submapEnd)
{
    natural_t depth = 0;
    *submapEnd      = 0;
    for (;;)
    {
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count    = VM_REGION_SUBMAP_INFO_COUNT_64;
        mach_vm_address_t regionAddress = *address;
        mach_vm_size_t regionSize       = 0;
        if (mach_vm_region_recurse(mach_task_self(), &regionAddress, &regionSize, &depth, (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS)
            return false;

        // Past the submap walked down: the mapping found is outside of it.
        if (*submapEnd != 0 && regionAddress >= *submapEnd)
            *submapEnd = 0;

        if (info.is_submap)
        {
            if (*submapEnd == 0)
                *submapEnd = regionAddress + regionSize;

            if (*address < regionAddress)
                *address = regionAddress;

            ++depth;
            continue;
        }

        *address    = regionAddress;
        *size       = regionSize;
        *protection = info.protection;
        return true;
    }
}

static size_t _GetRegions(MiniDetourMemoryManipulationRegionInfos_t *regions, size_t regionCount, bool onlyFree)
{
    mach_vm_address_t oldEnd  = Globals_t::Instance().MinUserAddress;
    size_t writtenRegionCount = 0;
    size_t currentRegionCount = 0;

    auto addRegion = [&](uintptr_t start, uintptr_t end, MemoryRights rights)
    {
        if (regions != nullptr && writtenRegionCount < regionCount && regions->StructSize >= sizeof(*regions))
        {
            auto &region = *regions;
            regions      = reinterpret_cast<MiniDetourMemoryManipulationRegionInfos_t *>(reinterpret_cast<uintptr_t>(regions) + regions->StructSize);

            region.Rights = rights;
            region.Start  = start;
            region.End    = end;
            if (rights == MemoryRights::mem_unset)
                region.ModuleName[0] = '\0';
            else
                _GetRegionName(start, region.ModuleName, region.StructSize - (sizeof(region) - sizeof(region.ModuleName)));

            ++writtenRegionCount;
        }
        ++currentRegionCount;
    };

    // __PAGEZERO.
    if (!onlyFree && oldEnd != 0)
        addRegion(0, static_cast<uintptr_t>(oldEnd), MemoryRights::mem_none);

    mach_vm_address_t address     = 0;
    mach_vm_address_t reservedEnd = 0;
    mach_vm_size_t size;
    vm_prot_t protection;
    mach_vm_address_t submapEnd;
    while (_NextMapping(&address, &size, &protection, &submapEnd))
    {
        // Free memory before the mapping, if it isn't the reserved memory of a submap.
        const mach_vm_address_t freeStart = std::max(oldEnd, reservedEnd);
        if (address > freeStart)
            addRegion(static_cast<uintptr_t>(freeStart), static_cast<uintptr_t>(address), MemoryRights::mem_unset);

        if (!onlyFree)
            addRegion(static_cast<uintptr_t>(address), static_cast<uintptr_t>(address + size), _NativeToMemoryRights(protection));

        reservedEnd = std::max(reservedEnd, submapEnd);
        address += size;
        oldEnd = address;
    }

    return currentRegionCount;
}

static size_t _QueryPageSize()
{
    return sysconf(_SC_PAGESIZE);
}

static void GetRegionInfos(void *address, MiniDetourMemoryManipulationRegionInfos_t *regionInfos)
{
    // Values for a free address, replaced below if the address is mapped.
    regionInfos->Rights        = MemoryRights::mem_unset;
    regionInfos->Start         = 0;
    regionInfos->End           = 0;
    regionInfos->ModuleName[0] = '\0';

    // The mapping holding the address, or the next one if the address isn't mapped.
    mach_vm_address_t mapping = reinterpret_cast<mach_vm_address_t>(address);
    mach_vm_size_t size;
    vm_prot_t protection;
    mach_vm_address_t submapEnd;
    if (_NextMapping(&mapping, &size, &protection, &submapEnd) && mapping <= reinterpret_cast<mach_vm_address_t>(address) &&
        reinterpret_cast<mach_vm_address_t>(address) < mapping + size)
    {
        regionInfos->Start  = static_cast<uintptr_t>(mapping);
        regionInfos->End    = static_cast<uintptr_t>(mapping + size);
        regionInfos->Rights = _NativeToMemoryRights(protection);
        _GetRegionName(regionInfos->Start, regionInfos->ModuleName, regionInfos->StructSize - (sizeof(*regionInfos) - sizeof(regionInfos->ModuleName)));
    }
}

static size_t GetAllRegions(MiniDetourMemoryManipulationRegionInfos_t *regions, size_t regionCount)
{
    return _GetRegions(regions, regionCount, false);
}

static size_t GetFreeRegions(MiniDetourMemoryManipulationRegionInfos_t *regions, size_t regionCount)
{
    return _GetRegions(regions, regionCount, true);
}

static bool MemoryProtect(void *address, size_t size, MemoryRights rights, MemoryRights *oldRights)
{
    if (oldRights != nullptr)
    {
        RegionInfos_t infos;
        GetRegionInfos(address, &infos);
        *oldRights = infos.Rights;
    }

    kern_return_t kret = mach_vm_protect(mach_task_self(), (mach_vm_address_t)address, (mach_vm_size_t)size, FALSE, _MemoryProtectRightsToNative(rights));

    if (kret != KERN_SUCCESS)
        SPDLOG_ERROR("mach_vm_protect failed with code: {}", kern_return_t_2_str(kret));

    return kret == KERN_SUCCESS;
}

static void MemoryFree(void *address, size_t size)
{
    if (address != nullptr)
        mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)address, size);
}

static inline kern_return_t MemoryAllocWithProtection(mach_port_t task, void **address, size_t size, MemoryRights rights, int flags)
{
    mach_vm_address_t mach_address = (mach_vm_address_t)*address;
    mach_vm_size_t mach_size       = (mach_vm_size_t)size;
    kern_return_t kret             = mach_vm_allocate(task, &mach_address, mach_size, flags);
    if (kret != KERN_SUCCESS)
    {
        *address = nullptr;
        SPDLOG_ERROR("mach_vm_allocate failed with code: {}", kern_return_t_2_str(kret));
    }
    else
    {
        *address = (void *)mach_address;
        if (!MemoryProtect(*address, mach_size, rights, nullptr))
        {
            MemoryFree(*address, size);
            *address = nullptr;
        }
    }

    return kret;
}

// Allocates at this exact address, fails if it isn't free.
static inline void *_MemoryAllocAt(void *address, size_t size, MemoryRights rights)
{
    MemoryAllocWithProtection(mach_task_self(), &address, size, rights, VM_FLAGS_FIXED);
    return address;
}

static inline void *_MemoryAllocAnywhere(size_t size, MemoryRights rights)
{
    void *address = nullptr;
    MemoryAllocWithProtection(mach_task_self(), &address, size, rights, VM_FLAGS_ANYWHERE);
    return address;
}

// Nothing can be allocated in __PAGEZERO.
static inline uintptr_t _QueryMinUserAddress()
{
    return static_cast<uintptr_t>(_PageZeroEnd());
}

// End of the user address space.
static inline uintptr_t _QueryMaxUserAddress()
{
    return static_cast<uintptr_t>(MACH_VM_MAX_ADDRESS);
}

// mach_vm_allocate places a mapping at any page.
static inline size_t _QueryAllocationGranularity()
{
    return _QueryPageSize();
}

static bool SafeMemoryRead(void *address, uint8_t *buffer, size_t size)
{
    mach_port_t task          = mach_task_self();
    mach_vm_size_t read_count = 0;

    if (mach_vm_read_overwrite(task, (mach_vm_address_t)address, (mach_vm_size_t)size, (mach_vm_address_t)buffer, &read_count) != KERN_SUCCESS || read_count != size)
        return false;

    return true;
}

static bool SafeMemoryWrite(void *address, const uint8_t *buffer, size_t size)
{
    mach_port_t task = mach_task_self();

    if (mach_vm_write(task, (mach_vm_address_t)address, (vm_offset_t)buffer, (mach_msg_type_number_t)size) != KERN_SUCCESS)
        return false;

    return true;
}

static int FlushInstructionCache(void *address, size_t size)
{
    // Required on Apple Silicon after writing code, a no-op on x86.
    sys_icache_invalidate(address, size);
    return 1;
}

// Apple Silicon never maps memory writable and executable at the same time (W^X), and neither do the processes with
// the hardened runtime: code can't be made rwx to be written. Globals_t tells it once. The code memory of the library is
// then MAP_JIT memory: a thread switches it between writable and executable for itself only (Apple Silicon), the other
// threads keep running it. The hooked functions are written in a copy of their pages, which replaces them in one call:
// they stay executable all along.
#define MINIDETOUR_JIT_CODE_MEMORY

// Tries to map a page writable and executable.
static bool _QueryWritableExecutableMemory()
{
    const size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    void *memory          = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED)
        return false;

    munmap(memory, pageSize);
    return true;
}

// MAP_JIT can't be used with MAP_FIXED: the address is a hint, taken when it is free.
static void *_JitCodeAllocAt(void *address, size_t size)
{
    void *code = mmap(address, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    if (code == MAP_FAILED)
        return nullptr;

    if (code != address)
    {
        munmap(code, size);
        return nullptr;
    }

    return code;
}

static void *_JitCodeAllocAnywhere(size_t size)
{
    void *code = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    return code == MAP_FAILED ? nullptr : code;
}

// The switch is for the whole thread: nested writes only switch back at the end of the outermost one. On x64, MAP_JIT
// memory is writable and executable: there is nothing to switch.
static thread_local int _JitCodeWriteDepth = 0;

static bool _BeginJitCodeWrite(void *, size_t)
{
#if defined(MINIDETOUR_ARCH_ARM64)
    if (_JitCodeWriteDepth++ == 0)
        pthread_jit_write_protect_np(0);
#endif

    return true;
}

static void _EndJitCodeWrite(void *, size_t)
{
#if defined(MINIDETOUR_ARCH_ARM64)
    if (--_JitCodeWriteDepth == 0)
        pthread_jit_write_protect_np(1);
#endif
}

// Writes size bytes of code at address: its pages are copied in new memory, written there, given the rights of the
// original pages, then mapped over them. Only system calls are made: the other threads may be suspended. The instruction
// cache isn't flushed.
static bool _WriteFunctionCodeByRemap(void *address, const void *data, size_t size)
{
    const size_t pageSize         = Globals_t::Instance().PageSize;
    const mach_vm_address_t start = reinterpret_cast<mach_vm_address_t>(address) & ~static_cast<mach_vm_address_t>(pageSize - 1);
    const mach_vm_address_t end   = (reinterpret_cast<mach_vm_address_t>(address) + size + pageSize - 1) & ~static_cast<mach_vm_address_t>(pageSize - 1);
    const mach_vm_size_t length   = end - start;
    mach_vm_address_t mapping     = start;
    mach_vm_size_t mappingSize    = 0;
    vm_prot_t protection          = VM_PROT_NONE;
    mach_vm_address_t submapEnd   = 0;
    if (!_NextMapping(&mapping, &mappingSize, &protection, &submapEnd) || mapping > start)
        return false;

    void *copy = mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (copy == MAP_FAILED)
        return false;

    memcpy(copy, reinterpret_cast<void *>(start), length);
    memcpy(static_cast<uint8_t *>(copy) + (reinterpret_cast<mach_vm_address_t>(address) - start), data, size);

    // Never writable and executable: the code is executable.
    if ((protection & VM_PROT_EXECUTE) != 0)
        protection &= ~VM_PROT_WRITE;

    if (mach_vm_protect(mach_task_self(), reinterpret_cast<mach_vm_address_t>(copy), length, FALSE, protection) != KERN_SUCCESS)
    {
        munmap(copy, length);
        return false;
    }

    vm_prot_t current;
    vm_prot_t maximum;
    mach_vm_address_t target   = start;
    const kern_return_t result = mach_vm_remap(
        mach_task_self(),
        &target,
        length,
        0,
        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
        mach_task_self(),
        reinterpret_cast<mach_vm_address_t>(copy),
        FALSE,
        &current,
        &maximum,
        VM_INHERIT_COPY);

    // The pages stay mapped over the original ones.
    munmap(copy, length);
    return result == KERN_SUCCESS;
}
} // namespace Implementation
} // namespace MemoryManipulation

namespace ModuleManipulation
{
namespace Implementation
{
// Their addresses are asked to dyld when the library starts: see ModuleFunctions_t. Not &dlopen: the address of an
// imported function can be the stub of the image, which jumps through the import slot.
static ModuleFunctions_t _QueryModuleFunctions()
{
    ModuleFunctions_t functions;
    functions.dlopen  = reinterpret_cast<decltype(functions.dlopen)>(dlsym(RTLD_DEFAULT, "dlopen"));
    functions.dlclose = reinterpret_cast<decltype(functions.dlclose)>(dlsym(RTLD_DEFAULT, "dlclose"));
    functions.dlsym   = reinterpret_cast<decltype(functions.dlsym)>(dlsym(RTLD_DEFAULT, "dlsym"));
    return functions;
}

// Finds the loaded image whose dlopen handle is moduleHandle. Only dyld's public API is used: its internal structures
// and the shared cache format change between macOS versions. An image's handle is the one dlopen returns for its path
// (RTLD_NOLOAD never loads anything), and dlopen(NULL) gives the main executable, as on Linux. slide can be null.
static bool _FindLoadedImage(void *moduleHandle, const MachHeader_t **header, uintptr_t *slide)
{
    if (moduleHandle == nullptr)
        return false;

    // dlopen(NULL) gives a handle of its own, not the one of the executable path. The main executable is image 0.
    ModuleFunctions_t const &dyld = Globals_t::Instance().ModuleFunctions;
    void *mainHandle              = dyld.dlopen(nullptr, RTLD_NOW | RTLD_NOLOAD);
    if (mainHandle != nullptr)
        dyld.dlclose(mainHandle);

    const uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; ++i)
    {
        const char *path = _dyld_get_image_name(i);
        if (path == nullptr)
            continue;

        if (i != 0 || moduleHandle != mainHandle)
        {
            void *handle = dyld.dlopen(path, RTLD_NOW | RTLD_NOLOAD);
            if (handle == nullptr)
                continue;

            dyld.dlclose(handle);
            if (handle != moduleHandle)
                continue;
        }

        *header = reinterpret_cast<const MachHeader_t *>(_dyld_get_image_header(i));
        if (slide != nullptr)
            *slide = static_cast<uintptr_t>(_dyld_get_image_vmaddr_slide(i));

        return *header != nullptr && (*header)->magic == MachHeaderMagic;
    }

    // No loaded image has this handle.
    return false;
}

// slide: what the image was moved by from its link address, to add to symbol values.
static bool _LoadModuleExportDetails(void *moduleHandle, uintptr_t *slide, NList_t **dynamicSymbols, const char **dynamicSymbolsNames, uint32_t *dynamicSymbolsCount)
{
    const MachHeader_t *machHeader;
    if (!_FindLoadedImage(moduleHandle, &machHeader, slide))
        return false;

    if (machHeader->flags & MH_DYLIB_IN_CACHE) // TODO: Handle shared cache
        return false;

    const SymTabCommand_t *symTabCommand = _FindLoadCommand<SymTabCommand_t>(machHeader, LC_SYMTAB);
    const uintptr_t linkEditBase         = _GetLinkEditBase(machHeader, *slide);
    if (symTabCommand == nullptr || linkEditBase == 0)
        return false;

    *dynamicSymbols      = (NList_t *)(linkEditBase + symTabCommand->symoff);
    *dynamicSymbolsNames = (const char *)(linkEditBase + symTabCommand->stroff);
    *dynamicSymbolsCount = symTabCommand->nsyms;

    return true;
}

static size_t GetAllExportedSymbols(void *moduleHandle, ExportDetails_t *exportDetails, size_t exportDetailsCount)
{
    uintptr_t slide;
    NList_t *dynamicSymbols;
    uint32_t dynamicSymbolsCount;
    const char *dynamicSymbolsNames;
    size_t result = 0;

    if (!_LoadModuleExportDetails(moduleHandle, &slide, &dynamicSymbols, &dynamicSymbolsNames, &dynamicSymbolsCount))
        return result;

    // Without exportDetails, the exports are only counted. The undefined external symbols are the imports.
    for (uint32_t i = 0; i < dynamicSymbolsCount; ++i)
    {
        if (!(dynamicSymbols[i].n_type & N_EXT) || (dynamicSymbols[i].n_type & N_TYPE) == N_UNDF)
            continue;

        if (exportDetails != nullptr)
        {
            if (result >= exportDetailsCount)
                break;

            // C symbols start with '_' on macOS.
            const char *symbolName                  = dynamicSymbolsNames + dynamicSymbols[i].n_un.n_strx;
            exportDetails[result].ExportName        = symbolName[0] == '_' ? symbolName + 1 : symbolName;
            exportDetails[result].ExportCallAddress = (void *)(slide + dynamicSymbols[i].n_value);
            exportDetails[result].ExportOrdinal     = i;
        }

        ++result;
    }

    return result;
}

// Import slots of a Mach-O image: the lazy (__la_symbol_ptr) and non lazy (__got, __auth_got, __nl_symbol_ptr) symbol
// pointers, named by the indirect symbol table. This is what the image calls its imports through.
//
// Shared cache images don't use their own symbol pointers anymore on recent macOS (seen from macOS 14 on, arm64 and x64):
// the cache builder made their stubs jump through slots of the cache, one per symbol, shared by every image of the cache
// importing it. Their own sections lose their type and stay empty. These slots are found from the stubs, which the
// indirect symbol table names too. Replacing one replaces the import in every shared cache image calling it through a
// stub.
struct _ImportSlot_t
{
    // Without the leading '_' of C symbols.
    const char *Name;
    // Install name of the library the symbol is imported from, "" when not known (flat namespace, the image itself).
    const char *ModuleName;
    void **Slot;
    // Before its first call, a lazy slot points to dyld's binding stub.
    bool Lazy;
};

// The slot a symbol stub jumps through, nullptr when the stub isn't one that loads its target from a slot.
// x64: jmp *slot(%rip).
// arm64: adrp x16, slot@page; ldr x16, [x16, slot@pageoff]; br x16. Authenticated stubs (arm64e shared cache):
// adrp x17, slot@page; add x17, x17, slot@pageoff; ldr x16, [x17]; braa x16, x17.
static void **_GetStubSlot(const uint8_t *stub)
{
#if defined(MINIDETOUR_ARCH_X64)
    if (stub[0] != 0xff || stub[1] != 0x25)
        return nullptr;

    int32_t displacement;
    memcpy(&displacement, stub + 2, sizeof(displacement));
    return reinterpret_cast<void **>(reinterpret_cast<uintptr_t>(stub) + 6 + displacement);
#elif defined(MINIDETOUR_ARCH_ARM64)
    uint32_t instructions[3];
    memcpy(instructions, stub, sizeof(instructions));
    if ((instructions[0] & 0x9f000000) != 0x90000000)
        return nullptr;

    // adrp: a signed 21 bits count of 4 KB pages, immlo in bits 29-30 and immhi in bits 5-23.
    const uint32_t pageRegister = instructions[0] & 0x1f;
    int64_t pages               = ((instructions[0] >> 3) & 0x1ffffc) | ((instructions[0] >> 29) & 3);
    pages                       = (pages ^ 0x100000) - 0x100000;
    const uintptr_t page        = (reinterpret_cast<uintptr_t>(stub) & ~static_cast<uintptr_t>(0xfff)) + static_cast<uintptr_t>(pages * 0x1000);
    const uint32_t offset       = (instructions[1] >> 10) & 0xfff;

    // ldr x, [pageRegister, #offset * 8]
    if ((instructions[1] & 0xffc003e0) == (0xf9400000 | pageRegister << 5))
        return reinterpret_cast<void **>(page + offset * 8);

    // add x, pageRegister, #offset; ldr x, [x]
    const uint32_t slotRegister = instructions[1] & 0x1f;
    if ((instructions[1] & 0xffc003e0) == (0x91000000 | pageRegister << 5) && (instructions[2] & 0xffffffe0) == (0xf9400000 | slotRegister << 5))
        return reinterpret_cast<void **>(page + offset);

    return nullptr;
#else
    (void)stub;
    return nullptr;
#endif
}

// Calls callback(_ImportSlot_t const&) for every import slot of the image, until it returns false.
template <typename Callback>
static bool _ForEachImportSlot(void *moduleHandle, Callback callback)
{
    const MachHeader_t *header;
    uintptr_t slide;
    if (!_FindLoadedImage(moduleHandle, &header, &slide))
        return false;

    // Library ordinals are 8 bits, starting at 1, in the order of the dylib load commands.
    const char *libraries[256];
    uint32_t libraryCount = 0;
    _ForEachLoadCommand(
        header,
        [&](const LoadCommand_t *loadCommand)
        {
            switch (loadCommand->cmd)
            {
                case LC_LOAD_DYLIB:
                case LC_LOAD_WEAK_DYLIB:
                case LC_REEXPORT_DYLIB:
                case LC_LOAD_UPWARD_DYLIB:
                case LC_LAZY_LOAD_DYLIB:
                {
                    auto dylib = reinterpret_cast<const dylib_command *>(loadCommand);
                    if (libraryCount < sizeof(libraries) / sizeof(*libraries))
                        libraries[libraryCount++] = reinterpret_cast<const char *>(dylib) + dylib->dylib.name.offset;

                    break;
                }
            }

            return true;
        });

    const SymTabCommand_t *symTab    = _FindLoadCommand<SymTabCommand_t>(header, LC_SYMTAB);
    const dysymtab_command *dySymTab = _FindLoadCommand<dysymtab_command>(header, LC_DYSYMTAB);
    const uintptr_t linkEditBase     = _GetLinkEditBase(header, slide);
    if (symTab == nullptr || dySymTab == nullptr || linkEditBase == 0)
        return false;

    const NList_t *symbols          = reinterpret_cast<const NList_t *>(linkEditBase + symTab->symoff);
    const char *symbolNames         = reinterpret_cast<const char *>(linkEditBase + symTab->stroff);
    const uint32_t *indirectSymbols = reinterpret_cast<const uint32_t *>(linkEditBase + dySymTab->indirectsymoff);

    // A stub jumping through one of the image's own symbol pointers: that slot is already listed with them.
    auto isOwnSymbolPointer = [&](void **slot)
    {
        bool found = false;
        _ForEachLoadCommand(
            header,
            [&](const LoadCommand_t *loadCommand)
            {
                if (loadCommand->cmd != LC_SEGMENT_ARCH)
                    return true;

                auto segment  = reinterpret_cast<const SegmentCommand_t *>(loadCommand);
                auto sections = reinterpret_cast<const Section_t *>(segment + 1);
                for (uint32_t i = 0; i < segment->nsects && !found; ++i)
                {
                    const uint32_t type   = sections[i].flags & SECTION_TYPE;
                    const uintptr_t start = slide + sections[i].addr;
                    found                 = (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS) && reinterpret_cast<uintptr_t>(slot) >= start &&
                                            reinterpret_cast<uintptr_t>(slot) < start + sections[i].size;
                }

                return !found;
            });

        return found;
    };

    const bool inSharedCache = (header->flags & MH_DYLIB_IN_CACHE) != 0;
    _ForEachLoadCommand(
        header,
        [&](const LoadCommand_t *loadCommand)
        {
            if (loadCommand->cmd != LC_SEGMENT_ARCH)
                return true;

            auto segment  = reinterpret_cast<const SegmentCommand_t *>(loadCommand);
            auto sections = reinterpret_cast<const Section_t *>(segment + 1);
            for (uint32_t i = 0; i < segment->nsects; ++i)
            {
                const Section_t &section = sections[i];
                const uint32_t type      = section.flags & SECTION_TYPE;
                const bool stubs         = inSharedCache && type == S_SYMBOL_STUBS && section.reserved2 != 0;
                if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS && !stubs)
                    continue;

                // Symbol pointers, or stubs of reserved2 bytes.
                const size_t entrySize = stubs ? section.reserved2 : sizeof(void *);
                for (size_t j = 0; j < section.size / entrySize; ++j)
                {
                    const uintptr_t entry = slide + section.addr + j * entrySize;
                    void **slot           = stubs ? _GetStubSlot(reinterpret_cast<const uint8_t *>(entry)) : reinterpret_cast<void **>(entry);
                    if (slot == nullptr || (stubs && isOwnSymbolPointer(slot)))
                        continue;

                    const uint32_t indirectIndex = section.reserved1 + static_cast<uint32_t>(j);
                    if (indirectIndex >= dySymTab->nindirectsyms)
                        break;

                    // Local and absolute entries aren't imports.
                    const uint32_t symbolIndex = indirectSymbols[indirectIndex];
                    if ((symbolIndex & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) != 0 || symbolIndex >= symTab->nsyms)
                        continue;

                    const NList_t &symbol = symbols[symbolIndex];
                    if (symbol.n_un.n_strx >= symTab->strsize)
                        continue;

                    const char *name = symbolNames + symbol.n_un.n_strx;
                    if (name[0] == '_')
                        ++name;

                    const uint32_t ordinal = GET_LIBRARY_ORDINAL(symbol.n_desc);
                    _ImportSlot_t importSlot;
                    importSlot.Name       = name;
                    importSlot.ModuleName = ordinal >= 1 && ordinal <= libraryCount ? libraries[ordinal - 1] : "";
                    importSlot.Slot       = slot;
                    importSlot.Lazy       = type == S_LAZY_SYMBOL_POINTERS;
                    if (!callback(importSlot))
                        return false;
                }
            }

            return true;
        });

    return true;
}

// The address a slot leads to. An unresolved lazy slot points to dyld's binding stub: calling it would bind the slot
// again, over a replacement. The function is then resolved from the library the symbol is imported from.
static void *_GetImportTarget(_ImportSlot_t const &importSlot)
{
    if (!importSlot.Lazy)
        return *importSlot.Slot;

    ModuleFunctions_t const &dyld = Globals_t::Instance().ModuleFunctions;
    void *library                 = importSlot.ModuleName[0] != '\0' ? dyld.dlopen(importSlot.ModuleName, RTLD_NOW | RTLD_NOLOAD) : nullptr;
    void *target                  = dyld.dlsym(library != nullptr ? library : RTLD_DEFAULT, importSlot.Name);
    if (library != nullptr)
        dyld.dlclose(library);

    return target != nullptr ? target : *importSlot.Slot;
}

// The import module name can be the library install name or its file name. No name matches any library.
static bool _ImportModuleMatches(const char *wantedModuleName, const char *moduleName)
{
    if (wantedModuleName == nullptr || wantedModuleName[0] == '\0' || strcmp(wantedModuleName, moduleName) == 0)
        return true;

    const char *fileName = strrchr(moduleName, '/');
    return fileName != nullptr && strcmp(wantedModuleName, fileName + 1) == 0;
}

// Writes to pages whose maximum rights may not include writing: the import slots are in __DATA_CONST (read-only once the
// image is bound), the export trie in __LINKEDIT, and shared cache pages are never writable. VM_PROT_COPY gives the
// process its own writable copy of the pages. The rights are restored (those of the first page, for the whole range).
static bool _WriteProtected(void *address, const void *data, size_t size)
{
    MiniDetour::MemoryManipulation::RegionInfos_t infos;
    MiniDetour::MemoryManipulation::GetRegionInfos(address, &infos);
    if (infos.Rights == MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
        return false;

    const size_t pageSize          = Globals_t::Instance().PageSize;
    const mach_vm_address_t start  = reinterpret_cast<mach_vm_address_t>(MiniDetour::MemoryManipulation::PageRound(address, pageSize));
    const mach_vm_address_t end    = (reinterpret_cast<mach_vm_address_t>(address) + size + pageSize - 1) & ~static_cast<mach_vm_address_t>(pageSize - 1);
    const vm_prot_t originalRights = static_cast<vm_prot_t>(MemoryManipulation::Implementation::_MemoryProtectRightsToNative(infos.Rights));
    if (mach_vm_protect(mach_task_self(), start, end - start, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
        return false;

    memcpy(address, data, size);
    mach_vm_protect(mach_task_self(), start, end - start, FALSE, originalRights);
    return true;
}

static bool _WriteImportSlot(void **slot, void *value)
{
    return _WriteProtected(slot, &value, sizeof(value));
}

// Where dyld looks the exports of an image up (dlsym, binding of the images loaded later): the export trie. Its location
// is read once when the image is loaded, so it can only be modified in place. The padding between the load commands and
// the first section of __TEXT is kept too: it is where the export jumps are written.
struct _ExportTrie_t
{
    uintptr_t Base;
    uint8_t *Start;
    uint8_t *End;
    uintptr_t PaddingStart;
    uintptr_t PaddingEnd;
};

// LC_DYLD_INFO_ONLY, or LC_DYLD_INFO for old images.
static const dyld_info_command *_FindDyldInfo(const MachHeader_t *header)
{
    auto dyldInfo = _FindLoadCommand<dyld_info_command>(header, LC_DYLD_INFO_ONLY);
    return dyldInfo != nullptr ? dyldInfo : _FindLoadCommand<dyld_info_command>(header, LC_DYLD_INFO);
}

static bool _GetExportTrie(void *moduleHandle, _ExportTrie_t *exportTrie)
{
    const MachHeader_t *header;
    uintptr_t slide;
    if (!_FindLoadedImage(moduleHandle, &header, &slide))
        return false;

    uint32_t trieOffset = 0;
    uint32_t trieSize   = 0;
    if (auto exportsTrie = _FindLoadCommand<linkedit_data_command>(header, LC_DYLD_EXPORTS_TRIE))
    {
        trieOffset = exportsTrie->dataoff;
        trieSize   = exportsTrie->datasize;
    }
    else if (auto dyldInfo = _FindDyldInfo(header))
    {
        trieOffset = dyldInfo->export_off;
        trieSize   = dyldInfo->export_size;
    }

    const uintptr_t linkEditBase = _GetLinkEditBase(header, slide);
    if (linkEditBase == 0 || trieSize == 0)
        return false;

    exportTrie->Base  = reinterpret_cast<uintptr_t>(header);
    exportTrie->Start = reinterpret_cast<uint8_t *>(linkEditBase + trieOffset);
    exportTrie->End   = exportTrie->Start + trieSize;

    // The padding goes from the end of the load commands to the first section of __TEXT.
    exportTrie->PaddingStart = reinterpret_cast<uintptr_t>(header + 1) + header->sizeofcmds;
    exportTrie->PaddingEnd   = exportTrie->PaddingStart;
    if (const SegmentCommand_t *text = _FindSegment(header, SEG_TEXT))
    {
        uintptr_t firstSection = 0;
        auto sections          = reinterpret_cast<const Section_t *>(text + 1);
        for (uint32_t i = 0; i < text->nsects; ++i)
        {
            const uintptr_t sectionStart = slide + sections[i].addr;
            if (sections[i].size != 0 && (firstSection == 0 || sectionStart < firstSection))
                firstSection = sectionStart;
        }

        if (firstSection > exportTrie->PaddingStart)
            exportTrie->PaddingEnd = firstSection;
    }

    return true;
}

static bool _ReadUleb128(const uint8_t *&p, const uint8_t *end, uint64_t &value)
{
    value          = 0;
    unsigned shift = 0;
    for (;;)
    {
        if (p >= end || shift > 63)
            return false;

        const uint8_t byte = *p++;
        value |= static_cast<uint64_t>(byte & 0x7F) << shift;
        shift += 7;
        if ((byte & 0x80) == 0)
            return true;
    }
}

// Encodes value on exactly size bytes: ULEB128 can be padded with continuation bytes, dyld reads it the same way.
static bool _WriteUleb128(uint64_t value, uint8_t *buffer, size_t size)
{
    for (size_t i = 0; i < size; ++i)
    {
        buffer[i] = static_cast<uint8_t>((value & 0x7F) | (i + 1 < size ? 0x80 : 0));
        value >>= 7;
    }

    return value == 0;
}

// Finds the address of an exported symbol in the trie: an offset from the image header, encoded on *fieldSize bytes.
// Re-exports, resolvers, absolute and thread local symbols are refused.
static uint8_t *_FindExportAddressField(_ExportTrie_t const &exportTrie, const char *exportName, size_t *fieldSize)
{
    // C symbols start with '_' on macOS.
    const std::string symbolName = std::string("_") + exportName;
    const char *name             = symbolName.c_str();

    const uint8_t *node = exportTrie.Start;
    for (;;)
    {
        const uint8_t *p = node;
        uint64_t terminalSize;
        if (!_ReadUleb128(p, exportTrie.End, terminalSize) || terminalSize > static_cast<uint64_t>(exportTrie.End - p))
            return nullptr;

        const uint8_t *children = p + terminalSize;
        if (*name == '\0')
        {
            uint64_t flags;
            if (terminalSize == 0 || !_ReadUleb128(p, children, flags))
                return nullptr;

            if ((flags & (EXPORT_SYMBOL_FLAGS_REEXPORT | EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER)) != 0 ||
                (flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) != EXPORT_SYMBOL_FLAGS_KIND_REGULAR)
                return nullptr;

            const uint8_t *field = p;
            uint64_t offset;
            if (!_ReadUleb128(p, children, offset))
                return nullptr;

            *fieldSize = static_cast<size_t>(p - field);
            return const_cast<uint8_t *>(field);
        }

        // Each edge is at least one character long: name gets shorter at every node, so the walk ends.
        p = children;
        if (p >= exportTrie.End)
            return nullptr;

        const uint8_t childCount = *p++;
        const uint8_t *next      = nullptr;
        for (uint8_t i = 0; i < childCount && next == nullptr; ++i)
        {
            const char *edge        = reinterpret_cast<const char *>(p);
            const size_t edgeLength = strnlen(edge, static_cast<size_t>(exportTrie.End - p));
            if (edgeLength == static_cast<size_t>(exportTrie.End - p))
                return nullptr;

            p += edgeLength + 1;
            uint64_t childOffset;
            if (!_ReadUleb128(p, exportTrie.End, childOffset) || childOffset >= static_cast<uint64_t>(exportTrie.End - exportTrie.Start))
                return nullptr;

            if (edgeLength != 0 && strncmp(name, edge, edgeLength) == 0)
            {
                name += edgeLength;
                next = exportTrie.Start + childOffset;
            }
        }

        if (next == nullptr)
            return nullptr;

        node = next;
    }
}

static size_t _ExportJumpSlotSize()
{
    return (AbsJump::GetMaxOpcodeSize() + 15) & ~static_cast<size_t>(15);
}

static bool _IsExportJump(_ExportTrie_t const &exportTrie, uintptr_t address)
{
    return address >= exportTrie.PaddingStart && address + _ExportJumpSlotSize() <= exportTrie.PaddingEnd;
}

// The export offset keeps its encoded size, often 2 bytes (16 KB from the header): a jump above the image is out of
// reach, but the zero filled padding after the load commands isn't. A slot is free when it is all zeros (a jump never is).
static void *_WriteExportJump(_ExportTrie_t const &exportTrie, void *target)
{
    const size_t slotSize = _ExportJumpSlotSize();
    uint8_t code[AbsJump::GetMaxOpcodeSize()];
    const size_t jumpSize = MiniDetour::MemoryManipulation::WriteAbsoluteJump(code, target);

    for (uintptr_t slot = (exportTrie.PaddingStart + 15) & ~static_cast<uintptr_t>(15); slot + slotSize <= exportTrie.PaddingEnd; slot += slotSize)
    {
        const uint8_t *bytes = reinterpret_cast<const uint8_t *>(slot);
        bool isFree          = true;
        for (size_t i = 0; i < slotSize && isFree; ++i)
            isFree = bytes[i] == 0;

        if (!isFree)
            continue;

        if (!_WriteProtected(reinterpret_cast<void *>(slot), code, jumpSize))
            return nullptr;

        MemoryManipulation::Implementation::FlushInstructionCache(reinterpret_cast<void *>(slot), jumpSize);
        return reinterpret_cast<void *>(slot);
    }

    return nullptr;
}

static void _FreeExportJump(void *jump)
{
    uint8_t zeros[AbsJump::GetMaxOpcodeSize() + 16] = {};
    _WriteProtected(jump, zeros, _ExportJumpSlotSize());
}

static size_t GetAllIATSymbols(void *moduleHandle, IATDetails_t *iatDetails, size_t iatDetailsCount)
{
    size_t result = 0;
    _ForEachImportSlot(
        moduleHandle,
        [&](_ImportSlot_t const &importSlot)
        {
            if (iatDetails != nullptr)
            {
                if (result >= iatDetailsCount)
                    return false;

                iatDetails[result].ImportOrdinal     = static_cast<uint32_t>(result);
                iatDetails[result].ImportName        = importSlot.Name;
                iatDetails[result].ImportModuleName  = importSlot.ModuleName;
                iatDetails[result].ImportCallAddress = _GetImportTarget(importSlot);
            }

            ++result;
            return true;
        });

    return result;
}

// Only what dyld looks up from now on changes (dlsym, images loaded later): the images already bound keep calling the
// original export, their imports can be replaced with ReplaceModuleIATs.
static size_t ReplaceModuleExports(void *moduleHandle, ExportReplaceParameter_t *exportReplaceDetails, size_t exportReplaceDetailsCount)
{
    size_t result = 0;
    for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
        exportReplaceDetails[i].ExportCallAddress = nullptr;

    _ExportTrie_t exportTrie;
    if (!_GetExportTrie(moduleHandle, &exportTrie))
        return result;

    for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
    {
        if (exportReplaceDetails[i].ExportName == nullptr || exportReplaceDetails[i].NewExportAddress == nullptr)
            continue;

        size_t fieldSize;
        uint8_t *field = _FindExportAddressField(exportTrie, exportReplaceDetails[i].ExportName, &fieldSize);
        uint8_t encoded[16];
        if (field == nullptr || fieldSize > sizeof(encoded))
            continue;

        const uint8_t *p = field;
        uint64_t oldOffset;
        _ReadUleb128(p, field + fieldSize, oldOffset);

        // The offset is unsigned and keeps its size: the new address is used as is when it fits, otherwise a jump to it.
        const uintptr_t target = reinterpret_cast<uintptr_t>(exportReplaceDetails[i].NewExportAddress);
        void *jump             = nullptr;
        if (target <= exportTrie.Base || !_WriteUleb128(target - exportTrie.Base, encoded, fieldSize))
        {
            jump = _WriteExportJump(exportTrie, exportReplaceDetails[i].NewExportAddress);
            if (jump == nullptr)
                continue;

            if (!_WriteUleb128(reinterpret_cast<uintptr_t>(jump) - exportTrie.Base, encoded, fieldSize))
            {
                _FreeExportJump(jump);
                continue;
            }
        }

        if (!_WriteProtected(field, encoded, fieldSize))
        {
            if (jump != nullptr)
                _FreeExportJump(jump);

            continue;
        }

        exportReplaceDetails[i].ExportCallAddress = reinterpret_cast<void *>(exportTrie.Base + static_cast<uintptr_t>(oldOffset));
        ++result;
    }

    return result;
}

static size_t RestoreModuleExports(void *moduleHandle, ExportReplaceParameter_t *exportReplaceDetails, size_t exportReplaceDetailsCount)
{
    size_t result = 0;
    for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
        exportReplaceDetails[i].NewExportAddress = nullptr;

    _ExportTrie_t exportTrie;
    if (!_GetExportTrie(moduleHandle, &exportTrie))
        return result;

    for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
    {
        if (exportReplaceDetails[i].ExportName == nullptr)
            continue;

        size_t fieldSize;
        uint8_t *field = _FindExportAddressField(exportTrie, exportReplaceDetails[i].ExportName, &fieldSize);
        uint8_t encoded[16];
        const uintptr_t original = reinterpret_cast<uintptr_t>(exportReplaceDetails[i].ExportCallAddress);
        if (field == nullptr || fieldSize > sizeof(encoded) || original <= exportTrie.Base || !_WriteUleb128(original - exportTrie.Base, encoded, fieldSize))
            continue;

        const uint8_t *p = field;
        uint64_t currentOffset;
        _ReadUleb128(p, field + fieldSize, currentOffset);

        // Only this entry fails: the next ones can still be restored.
        if (!_WriteProtected(field, encoded, fieldSize))
            continue;

        const uintptr_t current                  = exportTrie.Base + static_cast<uintptr_t>(currentOffset);
        exportReplaceDetails[i].NewExportAddress = reinterpret_cast<void *>(current);
        if (current != original && _IsExportJump(exportTrie, current))
            _FreeExportJump(reinterpret_cast<void *>(current));

        ++result;
    }

    return result;
}

// Writes value in every slot of each symbol and gives what the first one held in previous. A symbol can have several
// slots (a lazy one for its calls, a non lazy one where its address is taken). An unbound lazy slot holds dyld's
// binding stub: when replacing, the function it would bind is given instead, so calling it doesn't bind the slot again
// over the replacement. Mach-O imports have no ordinal, they are found by name.
static size_t _ExchangeModuleIATs(
    void *moduleHandle,
    IATReplaceParameter_t *iatReplaceDetails,
    size_t iatReplaceDetailsCount,
    void *IATReplaceParameter_t::*value,
    void *IATReplaceParameter_t::*previous,
    bool resolveLazySlots)
{
    size_t result = 0;

    for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
    {
        IATReplaceParameter_t &parameter = iatReplaceDetails[i];
        parameter.*previous              = nullptr;
        if (parameter.IATName == nullptr || parameter.*value == nullptr)
            continue;

        bool exchanged = false;
        _ForEachImportSlot(
            moduleHandle,
            [&](_ImportSlot_t const &importSlot)
            {
                if (strcmp(importSlot.Name, parameter.IATName) != 0 || !_ImportModuleMatches(parameter.IATModuleName, importSlot.ModuleName))
                    return true;

                void *current = resolveLazySlots ? _GetImportTarget(importSlot) : *importSlot.Slot;
                if (_WriteImportSlot(importSlot.Slot, parameter.*value) && !exchanged)
                {
                    parameter.*previous = current;
                    exchanged           = true;
                }

                return true;
            });

        if (exchanged)
            ++result;
    }

    return result;
}

static size_t ReplaceModuleIATs(void *moduleHandle, IATReplaceParameter_t *iatReplaceDetails, size_t iatReplaceDetailsCount)
{
    return _ExchangeModuleIATs(moduleHandle, iatReplaceDetails, iatReplaceDetailsCount, &IATReplaceParameter_t::NewIATAddress, &IATReplaceParameter_t::IATCallAddress, true);
}

static size_t RestoreModuleIATs(void *moduleHandle, IATReplaceParameter_t *iatReplaceDetails, size_t iatReplaceDetailsCount)
{
    return _ExchangeModuleIATs(moduleHandle, iatReplaceDetails, iatReplaceDetailsCount, &IATReplaceParameter_t::IATCallAddress, &IATReplaceParameter_t::NewIATAddress, false);
}

} // namespace Implementation
} // namespace ModuleManipulation
} // namespace MiniDetour

#endif // MINI_DETOUR_MACOS_H
