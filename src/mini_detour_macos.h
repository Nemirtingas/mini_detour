#ifndef MINI_DETOUR_MACOS_H
#define MINI_DETOUR_MACOS_H

#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_prot.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <dlfcn.h>

#include <unistd.h>
#include <errno.h>

#if defined(MINIDETOUR_ARCH_X64) || defined(MINIDETOUR_ARCH_ARM64)

using MachHeader_t = mach_header_64;
using LoadCommand_t = load_command;
using Section_t = section_64;
using SymTabCommand_t = symtab_command;
using NList_t = nlist_64;

#define MachHeaderMagic MH_MAGIC_64

#elif defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_ARM)

using MachHeader_t = mach_header;
using LoadCommand_t = load_command;
using Section_t = section;
using SymTabCommand_t = symtab_command;
using NList_t = nlist;

#define MachHeaderMagic MH_MAGIC

#endif

#ifdef USE_SPDLOG

std::string kern_return_t_2_str(kern_return_t v)
{
#define CASE_TO_STRING(x) case x: return #x;
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

namespace MiniDetour {
namespace MemoryManipulation {
namespace Implementation {
#if defined(MINIDETOUR_ARCH_X64) || defined(MINIDETOUR_ARCH_ARM64)
    const void* max_user_address = reinterpret_cast<void*>(0x7ffefffff000);
#elif defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_ARM)
    const void* max_user_address = reinterpret_cast<void*>(0x7ffff000);
#endif

    size_t _MemoryProtectRightsToNative(MemoryRights rights)
    {
        switch (rights)
        {
            case MemoryRights::mem_r  : return VM_PROT_READ;
            case MemoryRights::mem_w  : return VM_PROT_WRITE;
            case MemoryRights::mem_x  : return VM_PROT_EXECUTE;
            case MemoryRights::mem_rw : return VM_PROT_WRITE | VM_PROT_READ;
            case MemoryRights::mem_rx : return VM_PROT_READ  | VM_PROT_EXECUTE;
            case MemoryRights::mem_wx : return VM_PROT_WRITE | VM_PROT_EXECUTE;
            case MemoryRights::mem_rwx: return VM_PROT_WRITE | VM_PROT_READ | VM_PROT_EXECUTE;

            default: return VM_PROT_NONE;
        }
    }

    size_t PageSize()
    {
        return sysconf(_SC_PAGESIZE);
    }

    RegionInfos_t GetRegionInfos(void* address)
    {
        RegionInfos_t res{};

        mach_vm_address_t vm_address = (mach_vm_address_t)address;
        kern_return_t ret;
        mach_vm_size_t size;
        vm_region_basic_info_data_64_t infos;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name = MACH_PORT_NULL;

        unsigned int rights = MemoryRights::mem_unset;

        // mach_vm_region returns the region or the next region to vm_address, so if the region queried is free, it will not return the free region but the next one.
        ret = mach_vm_region(mach_task_self(), &vm_address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&infos, &count, &object_name);

        if (ret == KERN_SUCCESS)
        {
            if (static_cast<uintptr_t>(vm_address) <= reinterpret_cast<uintptr_t>(address) && reinterpret_cast<uintptr_t>(address) < static_cast<uintptr_t>(vm_address) + size)
            {
                res.start = (uintptr_t)vm_address;
                res.end = res.start + size;

                rights = MemoryRights::mem_none;

                if (infos.protection & VM_PROT_READ)
                    rights |= MemoryRights::mem_r;

                if (infos.protection & VM_PROT_WRITE)
                    rights |= MemoryRights::mem_w;

                if (infos.protection & VM_PROT_EXECUTE)
                    rights |= MemoryRights::mem_x;
            }
        }

        res.rights = (MemoryRights)rights;

        return res;
    }

    std::vector<RegionInfos_t> GetAllRegions()
    {
        std::vector<RegionInfos_t> mappings;

        mach_port_t self_task = mach_task_self();
        mach_vm_address_t old_end = 0;

        mach_vm_address_t vm_address = 0;
        mach_vm_size_t size;
        vm_region_basic_info_data_64_t infos;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name = MACH_PORT_NULL;

        std::string module_name;
        unsigned int rights;

        while (mach_vm_region(self_task, &vm_address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&infos, &count, &object_name) == KERN_SUCCESS)
        {
            if (old_end != vm_address)
            {
                mappings.emplace_back(
                    MemoryRights::mem_unset,
                    (uintptr_t)old_end,
                    (uintptr_t)vm_address,
                    std::string()
                );
            }

            rights = MemoryRights::mem_none;

            if (infos.protection & VM_PROT_READ)
                rights |= MemoryRights::mem_r;

            if (infos.protection & VM_PROT_WRITE)
                rights |= MemoryRights::mem_w;

            if (infos.protection & VM_PROT_EXECUTE)
                rights |= MemoryRights::mem_x;

            mappings.emplace_back(RegionInfos_t{
                (MemoryRights)rights,
                static_cast<uintptr_t>(vm_address),
                static_cast<uintptr_t>(vm_address + size),
                std::move(module_name)
            });

            vm_address += size;
            old_end = vm_address;
        }

        return mappings;
    }

    std::vector<RegionInfos_t> GetFreeRegions()
    {
        std::vector<RegionInfos_t> mappings;

        mach_port_t self_task = mach_task_self();
        mach_vm_address_t old_end = 0;

        mach_vm_address_t vm_address = 0;
        mach_vm_size_t size;
        vm_region_basic_info_data_64_t infos;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name = MACH_PORT_NULL;

        while (mach_vm_region(self_task, &vm_address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&infos, &count, &object_name) == KERN_SUCCESS)
        {
            if (old_end != vm_address)
            {
                mappings.emplace_back(
                    MemoryRights::mem_unset,
                    (uintptr_t)old_end,
                    (uintptr_t)vm_address,
                    std::string()
                );
            }

            vm_address += size;
            old_end = vm_address;
        }

        return mappings;
    }

    bool MemoryProtect(void* address, size_t size, MemoryRights rights, MemoryRights* old_rights)
    {
        kern_return_t kret;
        RegionInfos_t infos;
        if (old_rights != nullptr)
            infos = GetRegionInfos(address);

        kret = mach_vm_protect(mach_task_self(), (mach_vm_address_t)address, (mach_vm_size_t)size, FALSE, _MemoryProtectRightsToNative(rights));

        if (old_rights != nullptr)
            *old_rights = infos.rights;

        if (kret != KERN_SUCCESS)
            SPDLOG_ERROR("mach_vm_protect failed with code: {}", kern_return_t_2_str(kret));

        return kret == KERN_SUCCESS;
    }

    void MemoryFree(void* address, size_t size)
    {
        if (address != nullptr)
            mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)address, size);
    }

    static inline kern_return_t MemoryAllocWithProtection(mach_port_t task, void** address, size_t size, MemoryRights rights, int flags)
    {
        mach_vm_address_t mach_address = (mach_vm_address_t)*address;
        mach_vm_size_t mach_size = (mach_vm_size_t)size;
        kern_return_t kret = mach_vm_allocate(task, &mach_address, mach_size, flags);
        if (kret != KERN_SUCCESS)
        {
            *address = nullptr;
            SPDLOG_ERROR("mach_vm_allocate failed with code: {}", kern_return_t_2_str(kret));
        }
        else
        {
            *address = (void*)mach_address;
            if (!MemoryProtect(*address, mach_size, rights, nullptr))
            {
                MemoryFree(*address, size);
                *address = nullptr;
            }
        }

        return kret;
    }

    static inline void* MemoryAllocNear(mach_port_t task, uintptr_t addressHint, size_t size, MemoryRights rights, size_t pageSize)
    {
        void* address;

        auto freeRegions = GetFreeRegions();

        std::sort(freeRegions.begin(), freeRegions.end(), [addressHint](MemoryManipulation::RegionInfos_t const& l, MemoryManipulation::RegionInfos_t const& r)
        {
            return std::max(addressHint, l.start) - std::min(addressHint, l.start) <
                std::max(addressHint, r.start) - std::min(addressHint, r.start);
        });

        for (auto const& region : freeRegions)
        {
            auto start = region.start > addressHint ? region.start : (region.end - pageSize);
            auto increment = static_cast<int32_t>(region.start > addressHint ? pageSize : -pageSize);

            for (auto allocAddress = start; allocAddress >= region.start && (allocAddress + size) < region.end; allocAddress += increment)
            {
                if (allocAddress > (uintptr_t)max_user_address)
                    break;

                address = (void*)allocAddress;
                MemoryAllocWithProtection(task, &address, (mach_vm_size_t)size, rights, VM_FLAGS_FIXED);
                if (address != nullptr)
                    return address;
            }
        }

        // Fallback to anywhere alloc
        address = nullptr;
        MemoryAllocWithProtection(task, &address, size, rights, VM_FLAGS_ANYWHERE);

        return address;
    }

    void* MemoryAlloc(void* _addressHint, size_t size, MemoryRights rights)
    {
        if (_addressHint > max_user_address)
            _addressHint = (void*)max_user_address;

        auto pageSize = PageSize();
        auto addressHint = reinterpret_cast<uintptr_t>(PageRound(_addressHint, pageSize));
        size = _PageAddrSize((void*)addressHint, size, pageSize);

        mach_port_t task = mach_task_self();

        if (_addressHint == nullptr)
        {
            void* address = nullptr;
            MemoryAllocWithProtection(task, &address, size, rights, VM_FLAGS_ANYWHERE);
            return address;
        }

        return MemoryAllocNear(task, addressHint, size, rights, pageSize);
    }

    bool SafeMemoryRead(void* address, uint8_t* buffer, size_t size)
    {
        mach_port_t task = mach_task_self();
        mach_vm_size_t read_count = 0;

        if (mach_vm_read_overwrite(task, (mach_vm_address_t)address, (mach_vm_size_t)size, (mach_vm_address_t)buffer, &read_count) != KERN_SUCCESS || read_count != size)
            return false;

        return true;
    }

    bool SafeMemoryWrite(void* address, const uint8_t* buffer, size_t size)
    {
        mach_port_t task = mach_task_self();

        if (mach_vm_write(task, (mach_vm_address_t)address, (vm_offset_t)buffer, (mach_msg_type_number_t)size) != KERN_SUCCESS)
            return false;

        return true;
    }

    int FlushInstructionCache(void* address, size_t size)
    {
        return 1;
    }
}//namespace Implementation
}//namespace MemoryManipulation

namespace ModuleManipulation {
namespace Implementation {
    /*
    static void* _LoadModuleBaseFromHandleDYLDPre941(void* moduleHandle)
    {
        struct ImageLoader
        {
#if __x86_64__
            const char*                 fAotPath;
#endif
            const char*					fPath;
            const char*					fRealPath;
            dev_t						fDevice;
            ino_t						fInode;
            time_t						fLastModified;
            uint32_t					fPathHash;
            uint32_t					fDlopenReferenceCount;	// count of how many dlopens have been done on this image
            struct recursive_lock*		fInitializerRecursiveLock;

            union {
                struct {
                    uint16_t					fLoadOrder;
                    uint16_t					fDepth : 15,
                    fObjCMappedNotified : 1;
                    uint32_t					fState : 8,
                    fLibraryCount : 9,
                    fMadeReadOnly : 1,
                    fAllLibraryChecksumsAndLoadAddressesMatch : 1,
                    fLeaveMapped : 1,		// when unloaded, leave image mapped in cause some other code may have pointers into it
                    fNeverUnload : 1,		// image was statically loaded by main executable
                    fHideSymbols : 1,		// ignore this image's exported symbols when linking other images
                    fMatchByInstallName : 1,// look at image's install-path not its load path
                    fInterposed : 1,
                    fRegisteredDOF : 1,
                    fAllLazyPointersBound : 1,
                    fMarkedInUse : 1,
                    fBeingRemoved : 1,
                    fAddFuncNotified : 1,
                    fPathOwnedByImage : 1,
                    fIsReferencedDownward : 1,
                    fWeakSymbolsBound : 1;
                };
                uint64_t 						sizeOfData;
            };
        };

        struct ImageLoaderMachO : public ImageLoader
        {
            uint64_t								fCoveredCodeLength;
            const uint8_t*							fMachOData;
            const uint8_t*							fLinkEditBase; // add any internal "offset" to this to get mapped address
            uintptr_t								fSlide;
        };

        // 4 first bits are mode bits
        // moduleHandle == ImageLoader* & (~0xf)
        // return ((ImageLoaderMachO_x86*)((uintptr_t)moduleHandle & (~1)))->fMachOData;

        // From cache, use ImageLoaderMegaDylib
        return nullptr;
    }

    static void* _LoadModuleBaseFromHandlePre1066(void* moduleHandle)
    {
        struct Loader
        {
            struct LoaderRef {
                uint16_t    index       : 15,   // index into PrebuiltLoaderSet
                            app         :  1;   // app vs dyld cache PrebuiltLoaderSet
            };

            enum { kMagic = 'l4yd' };
    
            const uint32_t      magic;
            const uint16_t      isPrebuilt         :  1,  // PrebuiltLoader vs JustInTimeLoader
                                dylibInDyldCache   :  1,
                                hasObjC            :  1,
                                mayHavePlusLoad    :  1,
                                hasReadOnlyData    :  1,  // __DATA_CONST.  Don't use directly.  Use hasConstantSegmentsToProtect()
                                neverUnload        :  1,  // part of launch or has non-unloadable data (e.g. objc, tlv)
                                leaveMapped        :  1,  // RTLD_NODELETE
                                hasReadOnlyObjC    :  1,  // Has __DATA_CONST,__objc_selrefs section
                                pre2022Binary      :  1,
                                isPremapped        :  1,  // mapped by exclave core
                                hasUUIDLoadCommand :  1,
                                hasWeakDefs        :  1,
                                hasTLVs            :  1,
                                belowLibSystem     :  1,
                                padding            :  2;
            LoaderRef           ref;
        };

        struct JustInTimeLoader : public Loader
        {
            const mach_header*   mappedAddress;
            mutable uint64_t     pathOffset         : 16,
                                 dependentsSet      :  1,
                                 fixUpsApplied      :  1,
                                 inited             :  1,
                                 hidden             :  1,
                                 altInstallName     :  1,
                                 lateLeaveMapped    :  1,
                                 overridesCache     :  1,
                                 allDepsAreNormal   :  1,
                                 overrideIndex      : 15,
                                 depCount           : 16,
                                 padding            :  9;
            uint64_t             sliceOffset;
        };

        Loader* loader = (Loader*)((uintptr_t)moduleHandle >> 1);
        if (loader->magic == Loader::kMagic)
        {
            if (loader->isPrebuilt)// TODO PrebuiltLoader
                return nullptr;
        
            return (void*)((JustInTimeLoader*)loader)->mappedAddress;
        }
        return nullptr;
    }

    static void* _LoadModuleBaseFromHandlePost1066(void* moduleHandle)
    {
        uintptr_t dyldStart = (uintptr_t)&__dso_handle;
        Loader* loader = (Loader*)((((uintptr_t)h) & ~1) ^ dyldStart);
        if (loader->magic == Loader::kMagic)
        {
            if (loader->isPrebuilt)// TODO PrebuiltLoader
                return nullptr;
        
            return (void*)((JustInTimeLoader*)loader)->mappedAddress;
        }
        return nullptr;
    }
    */

    static bool _LoadModuleExportDetails(void* moduleHandle, void** moduleBase, NList_t** dynamicSymbols, const char** dynamicSymbolsNames, uint32_t* dynamicSymbolsCount)
    {
        task_dyld_info dyld_info;
        mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
        kern_return_t ret;
        ret = task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
        if (ret != KERN_SUCCESS)
            return false;

        // This is the most reliable and safest way to find the module base address. dyld seems to change its internal structure quite often.
        dyld_all_image_infos *infos = (dyld_all_image_infos *)dyld_info.all_image_info_addr;
        void* cacheBase = nullptr;
        void* foundModuleBase = nullptr;

        for (int i = 0; i < infos->infoArrayCount && (foundModuleBase == nullptr || cacheBase == nullptr); ++i)
        {
            if (foundModuleBase == nullptr)
            {
                void* loadedHandle = dlopen(infos->infoArray[i].imageFilePath, RTLD_NOW);
                if (loadedHandle == moduleHandle)
                    foundModuleBase = (void*)infos->infoArray[i].imageLoadAddress;
                dlclose(loadedHandle);
            }

            if (cacheBase == nullptr)
                cacheBase = (void*)infos->sharedCacheBaseAddress;

        }

        MachHeader_t* machHeader = (MachHeader_t*)foundModuleBase;

        if (machHeader->magic != MachHeaderMagic)
            return false;

        // cache rx base: void* cache_rx_base
        // syscall(294, &cache_rx_base);

        bool fromSharedCache = machHeader->flags & MH_DYLIB_IN_CACHE;
        if (fromSharedCache)// TODO: Handle shared cache
            return false;

        LoadCommand_t* loadCommandStart = (LoadCommand_t*)(((uintptr_t)foundModuleBase) + sizeof(*machHeader));
        LoadCommand_t* loadCommandEnd = (LoadCommand_t*)(((uintptr_t)loadCommandStart) + machHeader->sizeofcmds);

        SymTabCommand_t* symTabCommand = nullptr;       
        uintptr_t linkEditBase = 0;

        for (auto* loadCommand = loadCommandStart; loadCommand < loadCommandEnd && (symTabCommand == nullptr || linkEditBase == 0); loadCommand = (LoadCommand_t*)((uintptr_t)loadCommand + loadCommand->cmdsize))
        {
            if (loadCommand->cmd == LC_SYMTAB)
            {
                symTabCommand = (SymTabCommand_t*)loadCommand;
            }
            else if (loadCommand->cmd == LC_SEGMENT && strncmp(((segment_command*)loadCommand)->segname, SEG_LINKEDIT, sizeof(((segment_command*)loadCommand)->segname)) == 0)
            {
                linkEditBase = (uintptr_t)foundModuleBase + ((segment_command*)loadCommand)->vmaddr - ((segment_command*)loadCommand)->fileoff;
            }
            else if (loadCommand->cmd == LC_SEGMENT_64 && strncmp(((segment_command_64*)loadCommand)->segname, SEG_LINKEDIT, sizeof(((segment_command_64*)loadCommand)->segname)) == 0)
            {
                linkEditBase = (uintptr_t)foundModuleBase + ((segment_command_64*)loadCommand)->vmaddr - ((segment_command_64*)loadCommand)->fileoff;
            }
        }

        if (symTabCommand == nullptr || linkEditBase == 0)
            return false;

        *moduleBase = foundModuleBase;
        *dynamicSymbols = (NList_t*)(linkEditBase + symTabCommand->symoff);
        *dynamicSymbolsNames = (const char*)(linkEditBase + symTabCommand->stroff);
        *dynamicSymbolsCount = symTabCommand->nsyms;

        return true;
    }

    size_t GetAllExportedSymbols(void* moduleHandle, ExportDetails_t* exportDetails, size_t exportDetailsCount)
    {
        void* moduleBase;
        NList_t* dynamicSymbols;
        uint32_t dynamicSymbolsCount;
        const char* dynamicSymbolsNames;
        size_t result = 0;
        
        if (!_LoadModuleExportDetails(moduleHandle, &moduleBase, &dynamicSymbols, &dynamicSymbolsNames, &dynamicSymbolsCount))
            return result;

        if (exportDetails == nullptr)
        {
            for (uint32_t i = 0; i < dynamicSymbolsCount; ++i)
                if (dynamicSymbols[i].n_type & N_EXT && (dynamicSymbols[i].n_type & N_TYPE) != N_UNDF)
                    ++result;

            return result;
        }

        SPDLOG_INFO("{} - {}", moduleHandle, moduleBase);
        for (uint32_t i = 0; i < dynamicSymbolsCount && result < exportDetailsCount; ++i)
        {
            if (!(dynamicSymbols[i].n_type & N_EXT))
                continue;

            //uint8_t type = dynamicSymbols[i].n_type & N_TYPE;
            // If type == N_INDR, might need to do some extra work to figure its address.
            SPDLOG_INFO("{} - ext: {}, type: {}", dynamicSymbolsNames + dynamicSymbols[i].n_un.n_strx, dynamicSymbols[i].n_type & N_EXT, dynamicSymbols[i].n_type & N_TYPE);

            if ((dynamicSymbols[i].n_type & N_TYPE) == N_UNDF)
                continue;

            exportDetails[result].ExportName = dynamicSymbolsNames + dynamicSymbols[i].n_un.n_strx + 1; // NOTE: on macos, export starts with '_'.
            exportDetails[result].ExportCallAddress = (void*)((uintptr_t)moduleBase + dynamicSymbols[i].n_value);
            exportDetails[result++].ExportOrdinal = i;
        }

        return result;
    }

    size_t GetAllIATSymbols(void* moduleHandle, IATDetails_t* exportDetails, size_t iatDetailsCount)
    {
        return 0;
    }

    size_t ReplaceModuleExports(void* moduleHandle, ExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount)
    {
        // TODO: Read MachO and modify export address
        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
            exportReplaceDetails[i].ExportCallAddress = nullptr;

        return 0;
    }

    size_t RestoreModuleExports(void* moduleHandle, ExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount)
    {
        // TODO: Read MachO and modify export address
        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
            exportReplaceDetails[i].NewExportAddress = nullptr;

        return 0;
    }

    size_t ReplaceModuleIATs(void* moduleHandle, IATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount)
    {
        for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
            iatReplaceDetails[i].IATCallAddress = nullptr;

        return 0;
    }

    size_t RestoreModuleIATs(void* moduleHandle, IATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount)
    {
        return 0;
    }

}//namespace Implementation
}//namespace ModuleManipulation
}//namespace MiniDetour

#endif//MINI_DETOUR_MACOS_H
