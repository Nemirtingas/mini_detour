#ifndef MINI_DETOUR_MACOS_H
#define MINI_DETOUR_MACOS_H

#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_prot.h>
#include <mach/vm_map.h>

#include <unistd.h>
#include <errno.h>

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

namespace MemoryManipulation {
    size_t memory_protect_rights_to_native(memory_rights rights)
    {
        switch (rights)
        {
            case mem_r  : return VM_PROT_READ;
            case mem_w  : return VM_PROT_WRITE;
            case mem_x  : return VM_PROT_EXECUTE;
            case mem_rw : return VM_PROT_WRITE | VM_PROT_READ;
            case mem_rx : return VM_PROT_READ  | VM_PROT_EXECUTE;
            case mem_wx : return VM_PROT_WRITE | VM_PROT_EXECUTE;
            case mem_rwx: return VM_PROT_WRITE | VM_PROT_READ | VM_PROT_EXECUTE;

            default: return VM_PROT_NONE;
        }
    }

    region_infos_t GetRegionInfos(void* address)
    {
        region_infos_t res{};

        mach_vm_address_t vm_address = (mach_vm_address_t)address;
        kern_return_t ret;
        mach_vm_size_t size;
        vm_region_basic_info_data_64_t infos;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name = MACH_PORT_NULL;

        unsigned int rights = mem_unset;

        // mach_vm_region returns the region or the next region to vm_address, so if the region queried is free, it will not return the free region but the next one.
        ret = mach_vm_region(mach_task_self(), &vm_address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&infos, &count, &object_name);

        if (ret == KERN_SUCCESS)
        {
            if (static_cast<uintptr_t>(vm_address) <= reinterpret_cast<uintptr_t>(address) && reinterpret_cast<uintptr_t>(address) < static_cast<uintptr_t>(vm_address) + size)
            {
                res.start = (uintptr_t)vm_address;
                res.end = res.start + size;

                rights = mem_none;

                if (infos.protection & VM_PROT_READ)
                    rights |= mem_r;

                if (infos.protection & VM_PROT_WRITE)
                    rights |= mem_w;

                if (infos.protection & VM_PROT_EXECUTE)
                    rights |= mem_x;
            }
        }

        res.rights = (memory_rights)rights;

        return res;
    }

    std::vector<region_infos_t> GetAllRegions()
    {
        std::vector<region_infos_t> mappings;

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
                    memory_rights::mem_unset,
                    (uintptr_t)old_end,
                    (uintptr_t)vm_address,
                    std::string()
                );
            }

            rights = memory_rights::mem_none;

            if (infos.protection & VM_PROT_READ)
                rights |= mem_r;

            if (infos.protection & VM_PROT_WRITE)
                rights |= mem_w;

            if (infos.protection & VM_PROT_EXECUTE)
                rights |= mem_x;

            mappings.emplace_back(region_infos_t{
                (memory_rights)rights,
                static_cast<uintptr_t>(vm_address),
                static_cast<uintptr_t>(vm_address + size),
                std::move(module_name)
            });

            vm_address += size;
            old_end = vm_address;
        }

        return mappings;
    }

    std::vector<region_infos_t> GetFreeRegions()
    {
        std::vector<region_infos_t> mappings;

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
                    memory_rights::mem_unset,
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

    size_t PageSize()
    {
        return sysconf(_SC_PAGESIZE);
    }

    bool MemoryProtect(void* address, size_t size, memory_rights rights, memory_rights* old_rights)
    {
        kern_return_t kret;
        region_infos_t infos;
        if (old_rights != nullptr)
            infos = GetRegionInfos(address);

        kret = mach_vm_protect(mach_task_self(), (mach_vm_address_t)address, size, FALSE, memory_protect_rights_to_native(rights));

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

    void* MemoryAlloc(void* address_hint, size_t size, memory_rights rights)
    {
        kern_return_t kret;
        mach_vm_address_t address;
        mach_port_t task = mach_task_self();

#if defined(MINIDETOUR_ARCH_X64) || defined(MINIDETOUR_ARCH_ARM64)
        void* max_user_address = reinterpret_cast<void*>(0x7ffefffff000);
#elif defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_ARM)
        void* max_user_address = reinterpret_cast<void*>(0x70000000);
#endif

        if (address_hint > max_user_address)
            address_hint = max_user_address;

        if (address_hint != nullptr)
        {
            region_infos_t infos;
            address = reinterpret_cast<mach_vm_address_t>(PageRound(address_hint, PageSize())) - PageSize();

            size = page_addr_size((void*)address, size, PageSize());
            int pages = size / PageSize();

            for (int i = 0; i < 100000; ++i, address -= PageSize())
            {
                bool found = true;
                for (int j = 0; j < pages; ++j)
                {
                    infos = GetRegionInfos((void*)address);
                    if (infos.start == (uintptr_t)address)
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    kret = mach_vm_allocate(task, &address, (mach_vm_size_t)size, VM_FLAGS_FIXED);
                    if (kret == KERN_SUCCESS)
                    {
                        SPDLOG_INFO("Allocated {} for hint {}", (void*)address, address_hint);
                        MemoryProtect(reinterpret_cast<void*>(address), size, rights);
                        return reinterpret_cast<void*>(address);
                    }
                }
            }

            address = reinterpret_cast<mach_vm_address_t>(PageRound(address_hint, PageSize())) + PageSize();
            for (int i = 0; i < 100000 && (void*)address < max_user_address; ++i, address += PageSize())
            {
                bool found = true;
                for (int j = 0; j < pages; ++j)
                {
                    infos = GetRegionInfos((void*)address);
                    if (infos.start == (uintptr_t)address)
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    kret = mach_vm_allocate(task, &address, (mach_vm_size_t)size, VM_FLAGS_FIXED);
                    if (kret == KERN_SUCCESS)
                    {
                        SPDLOG_INFO("Allocated {} for hint {}", (void*)address, address_hint);
                        MemoryProtect(reinterpret_cast<void*>(address), size, rights);
                        return reinterpret_cast<void*>(address);
                    }
                }
            }

            // Fallback to hint alloc
        }

        address = (mach_vm_address_t)0;
        kret = mach_vm_allocate(task, &address, (mach_vm_size_t)size, VM_FLAGS_ANYWHERE);
        if (kret != KERN_SUCCESS)
        {
            address = (mach_vm_address_t)0;
        }
        else
        {
            MemoryProtect(reinterpret_cast<void*>(address), size, rights);
        }

        return reinterpret_cast<void*>(address);
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

#endif//MINI_DETOUR_MACOS_H
