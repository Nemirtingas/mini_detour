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
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <dlfcn.h>
#include <libkern/OSCacheControl.h>

#include <unistd.h>
#include <errno.h>

#if defined(MINIDETOUR_ARCH_X64) || defined(MINIDETOUR_ARCH_ARM64)

using MachHeader_t    = mach_header_64;
using LoadCommand_t   = load_command;
using Section_t       = section_64;
using SymTabCommand_t = symtab_command;
using NList_t         = nlist_64;

#define MachHeaderMagic MH_MAGIC_64

#elif defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_ARM)

using MachHeader_t    = mach_header;
using LoadCommand_t   = load_command;
using Section_t       = section;
using SymTabCommand_t = symtab_command;
using NList_t         = nlist;

#define MachHeaderMagic MH_MAGIC

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

    auto loadCommand = reinterpret_cast<const LoadCommand_t *>(header + 1);
    for (uint32_t i = 0; i < header->ncmds; ++i, loadCommand = reinterpret_cast<const LoadCommand_t *>(reinterpret_cast<uintptr_t>(loadCommand) + loadCommand->cmdsize))
    {
        if (loadCommand->cmd == LC_SEGMENT_64)
        {
            auto segment = reinterpret_cast<const segment_command_64 *>(loadCommand);
            if (strncmp(segment->segname, SEG_PAGEZERO, sizeof(segment->segname)) == 0)
                return segment->vmaddr + segment->vmsize + _dyld_get_image_vmaddr_slide(imageIndex);
        }
        else if (loadCommand->cmd == LC_SEGMENT)
        {
            auto segment = reinterpret_cast<const segment_command *>(loadCommand);
            if (strncmp(segment->segname, SEG_PAGEZERO, sizeof(segment->segname)) == 0)
                return segment->vmaddr + segment->vmsize + _dyld_get_image_vmaddr_slide(imageIndex);
        }
    }

    return 0;
}

static size_t _GetRegions(MiniDetourMemoryManipulationRegionInfos_t *regions, size_t regionCount, bool onlyFree)
{
    mach_port_t self_task     = mach_task_self();
    mach_vm_address_t oldEnd  = _PageZeroEnd();
    size_t writtenRegionCount = 0;
    size_t currentRegionCount = 0;

    if (!onlyFree && oldEnd != 0)
    {
        if (regions != nullptr && writtenRegionCount < regionCount && regions->StructSize >= sizeof(*regions))
        {
            auto &region = *regions;
            regions      = reinterpret_cast<MiniDetourMemoryManipulationRegionInfos_t *>(reinterpret_cast<uintptr_t>(regions) + regions->StructSize);

            region.Rights        = MemoryRights::mem_none;
            region.Start         = 0;
            region.End           = static_cast<uintptr_t>(oldEnd);
            region.ModuleName[0] = '\0';
            ++writtenRegionCount;
        }
        ++currentRegionCount;
    }

    mach_vm_address_t vm_address = 0;
    mach_vm_size_t size;
    vm_region_basic_info_data_64_t infos;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name      = MACH_PORT_NULL;

    while (mach_vm_region(self_task, &vm_address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&infos, &count, &object_name) == KERN_SUCCESS)
    {
        if (vm_address > oldEnd)
        {
            if (regions != nullptr && writtenRegionCount < regionCount)
            {
                auto &region = *regions;
                if (region.StructSize >= sizeof(region))
                {
                    regions = reinterpret_cast<MiniDetourMemoryManipulationRegionInfos_t *>(reinterpret_cast<uintptr_t>(regions) + regions->StructSize);

                    region.Rights        = MemoryRights::mem_unset;
                    region.Start         = oldEnd;
                    region.End           = static_cast<uintptr_t>(vm_address);
                    region.ModuleName[0] = '\0';
                    ++writtenRegionCount;
                }
            }
            ++currentRegionCount;
        }

        if (!onlyFree)
        {
            if (regions != nullptr && writtenRegionCount < regionCount)
            {
                auto &region = *regions;

                if (region.StructSize >= sizeof(region))
                {
                    regions = reinterpret_cast<MiniDetourMemoryManipulationRegionInfos_t *>(reinterpret_cast<uintptr_t>(regions) + regions->StructSize);

                    region.Rights        = MemoryRights::mem_none;
                    region.Start         = static_cast<uintptr_t>(vm_address);
                    region.End           = static_cast<uintptr_t>(vm_address + size);
                    region.ModuleName[0] = '\0';

                    if (infos.protection & VM_PROT_READ)
                        region.Rights = static_cast<MemoryRights>(region.Rights | MemoryRights::mem_r);

                    if (infos.protection & VM_PROT_WRITE)
                        region.Rights = static_cast<MemoryRights>(region.Rights | MemoryRights::mem_w);

                    if (infos.protection & VM_PROT_EXECUTE)
                        region.Rights = static_cast<MemoryRights>(region.Rights | MemoryRights::mem_x);

                    ++writtenRegionCount;
                }
            }

            ++currentRegionCount;
        }

        vm_address += size;
        oldEnd = vm_address;
    }

    return currentRegionCount;
}

static size_t PageSize()
{
    return sysconf(_SC_PAGESIZE);
}

static void GetRegionInfos(void *address, MiniDetourMemoryManipulationRegionInfos_t *regionInfos)
{
    mach_vm_address_t vm_address = (mach_vm_address_t)address;
    kern_return_t ret;
    mach_vm_size_t size;
    vm_region_basic_info_data_64_t infos;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name      = MACH_PORT_NULL;

    // Values for a free address, replaced below if the address is mapped.
    regionInfos->Rights        = MemoryRights::mem_unset;
    regionInfos->Start         = 0;
    regionInfos->End           = 0;
    regionInfos->ModuleName[0] = '\0';

    // mach_vm_region returns the region or the next region to vm_address, so if the region queried is free, it will not return the free region but the next one.
    ret = mach_vm_region(mach_task_self(), &vm_address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&infos, &count, &object_name);

    if (ret == KERN_SUCCESS)
    {
        if (static_cast<uintptr_t>(vm_address) <= reinterpret_cast<uintptr_t>(address) && reinterpret_cast<uintptr_t>(address) < static_cast<uintptr_t>(vm_address) + size)
        {
            regionInfos->Start         = (uintptr_t)vm_address;
            regionInfos->End           = regionInfos->Start + size;
            regionInfos->Rights        = MemoryRights::mem_none;
            regionInfos->ModuleName[0] = '\0';

            if (infos.protection & VM_PROT_READ)
                regionInfos->Rights = static_cast<MemoryRights>(regionInfos->Rights | MemoryRights::mem_r);

            if (infos.protection & VM_PROT_WRITE)
                regionInfos->Rights = static_cast<MemoryRights>(regionInfos->Rights | MemoryRights::mem_w);

            if (infos.protection & VM_PROT_EXECUTE)
                regionInfos->Rights = static_cast<MemoryRights>(regionInfos->Rights | MemoryRights::mem_x);
        }
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
static inline uintptr_t _MinUserAddress()
{
    return static_cast<uintptr_t>(_PageZeroEnd());
}

// End of the user address space.
static inline uintptr_t _MaxUserAddress()
{
    return static_cast<uintptr_t>(MACH_VM_MAX_ADDRESS);
}

// mach_vm_allocate places a mapping at any page.
static inline size_t _AllocationGranularity()
{
    return PageSize();
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
} // namespace Implementation
} // namespace MemoryManipulation

namespace ModuleManipulation
{
namespace Implementation
{
// slide: what the image was moved by from its link address, to add to symbol values.
static bool _LoadModuleExportDetails(void *moduleHandle, uintptr_t *slide, NList_t **dynamicSymbols, const char **dynamicSymbolsNames, uint32_t *dynamicSymbolsCount)
{
    task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t ret;
    ret = task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    if (ret != KERN_SUCCESS)
        return false;

    // This is the most reliable and safest way to find the module base address. dyld seems to change its internal structure quite often.
    dyld_all_image_infos *infos = (dyld_all_image_infos *)dyld_info.all_image_info_addr;
    void *cacheBase             = nullptr;
    void *foundModuleBase       = nullptr;

    for (uint32_t i = 0; i < infos->infoArrayCount && (foundModuleBase == nullptr || cacheBase == nullptr); ++i)
    {
        if (foundModuleBase == nullptr)
        {
            // RTLD_NOLOAD: only get the handle of images already loaded, never load a new one.
            void *loadedHandle = dlopen(infos->infoArray[i].imageFilePath, RTLD_NOW | RTLD_NOLOAD);
            if (loadedHandle != nullptr)
            {
                if (loadedHandle == moduleHandle)
                    foundModuleBase = (void *)infos->infoArray[i].imageLoadAddress;

                dlclose(loadedHandle);
            }
        }

        if (cacheBase == nullptr)
            cacheBase = (void *)infos->sharedCacheBaseAddress;
    }

    // No loaded image has this handle (dlopen(NULL) handle, invalid handle).
    if (foundModuleBase == nullptr)
        return false;

    MachHeader_t *machHeader = (MachHeader_t *)foundModuleBase;

    if (machHeader->magic != MachHeaderMagic)
        return false;

    bool fromSharedCache = machHeader->flags & MH_DYLIB_IN_CACHE;
    if (fromSharedCache) // TODO: Handle shared cache
        return false;

    LoadCommand_t *loadCommandStart = (LoadCommand_t *)(((uintptr_t)foundModuleBase) + sizeof(*machHeader));
    LoadCommand_t *loadCommandEnd   = (LoadCommand_t *)(((uintptr_t)loadCommandStart) + machHeader->sizeofcmds);

    SymTabCommand_t *symTabCommand = nullptr;
    bool hasText                   = false;
    bool hasLinkEdit               = false;
    uintptr_t textVmAddr           = 0;
    uintptr_t linkEditVmAddr       = 0;
    uintptr_t linkEditFileOffset   = 0;

    for (auto *loadCommand = loadCommandStart; loadCommand < loadCommandEnd; loadCommand = (LoadCommand_t *)((uintptr_t)loadCommand + loadCommand->cmdsize))
    {
        const char *segmentName = nullptr;
        uintptr_t vmAddr        = 0;
        uintptr_t fileOffset    = 0;
        if (loadCommand->cmd == LC_SYMTAB)
        {
            symTabCommand = (SymTabCommand_t *)loadCommand;
        }
        else if (loadCommand->cmd == LC_SEGMENT)
        {
            segmentName = ((segment_command *)loadCommand)->segname;
            vmAddr      = ((segment_command *)loadCommand)->vmaddr;
            fileOffset  = ((segment_command *)loadCommand)->fileoff;
        }
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            segmentName = ((segment_command_64 *)loadCommand)->segname;
            vmAddr      = ((segment_command_64 *)loadCommand)->vmaddr;
            fileOffset  = ((segment_command_64 *)loadCommand)->fileoff;
        }

        if (segmentName == nullptr)
            continue;

        if (strncmp(segmentName, SEG_TEXT, sizeof(segment_command::segname)) == 0)
        {
            hasText    = true;
            textVmAddr = vmAddr;
        }
        else if (strncmp(segmentName, SEG_LINKEDIT, sizeof(segment_command::segname)) == 0)
        {
            hasLinkEdit        = true;
            linkEditVmAddr     = vmAddr;
            linkEditFileOffset = fileOffset;
        }
    }

    if (symTabCommand == nullptr || !hasText || !hasLinkEdit)
        return false;

    // The header is at the start of __TEXT. Its link address is 0 for a dylib, but not for an executable (0x100000000).
    *slide                       = (uintptr_t)foundModuleBase - textVmAddr;
    const uintptr_t linkEditBase = *slide + linkEditVmAddr - linkEditFileOffset;

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

    if (exportDetails == nullptr)
    {
        for (uint32_t i = 0; i < dynamicSymbolsCount; ++i)
            if (dynamicSymbols[i].n_type & N_EXT && (dynamicSymbols[i].n_type & N_TYPE) != N_UNDF)
                ++result;

        return result;
    }

    SPDLOG_INFO("{} - slide {:x}", moduleHandle, slide);
    for (uint32_t i = 0; i < dynamicSymbolsCount && result < exportDetailsCount; ++i)
    {
        if (!(dynamicSymbols[i].n_type & N_EXT))
            continue;

        // uint8_t type = dynamicSymbols[i].n_type & N_TYPE;
        //  If type == N_INDR, might need to do some extra work to figure its address.
        SPDLOG_INFO("{} - ext: {}, type: {}", dynamicSymbolsNames + dynamicSymbols[i].n_un.n_strx, dynamicSymbols[i].n_type & N_EXT, dynamicSymbols[i].n_type & N_TYPE);

        if ((dynamicSymbols[i].n_type & N_TYPE) == N_UNDF)
            continue;

        // C symbols start with '_' on macOS.
        const char *symbolName                  = dynamicSymbolsNames + dynamicSymbols[i].n_un.n_strx;
        exportDetails[result].ExportName        = symbolName[0] == '_' ? symbolName + 1 : symbolName;
        exportDetails[result].ExportCallAddress = (void *)(slide + dynamicSymbols[i].n_value);
        exportDetails[result++].ExportOrdinal   = i;
    }

    return result;
}

static size_t GetAllIATSymbols(void * /*moduleHandle*/, IATDetails_t * /*exportDetails*/, size_t /*iatDetailsCount*/)
{
    return 0;
}

static size_t ReplaceModuleExports(void * /*moduleHandle*/, ExportReplaceParameter_t *exportReplaceDetails, size_t exportReplaceDetailsCount)
{
    // TODO: Read MachO and modify export address
    for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
        exportReplaceDetails[i].ExportCallAddress = nullptr;

    return 0;
}

static size_t RestoreModuleExports(void * /*moduleHandle*/, ExportReplaceParameter_t *exportReplaceDetails, size_t exportReplaceDetailsCount)
{
    // TODO: Read MachO and modify export address
    for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
        exportReplaceDetails[i].NewExportAddress = nullptr;

    return 0;
}

static size_t ReplaceModuleIATs(void * /*moduleHandle*/, IATReplaceParameter_t *iatReplaceDetails, size_t iatReplaceDetailsCount)
{
    for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
        iatReplaceDetails[i].IATCallAddress = nullptr;

    return 0;
}

static size_t RestoreModuleIATs(void * /*moduleHandle*/, IATReplaceParameter_t *iatReplaceDetails, size_t iatReplaceDetailsCount)
{
    for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
        iatReplaceDetails[i].NewIATAddress = nullptr;

    return 0;
}

} // namespace Implementation
} // namespace ModuleManipulation
} // namespace MiniDetour

#endif // MINI_DETOUR_MACOS_H
