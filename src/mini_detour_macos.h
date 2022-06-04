#ifndef MINI_DETOUR_MACOS_H
#define MINI_DETOUR_MACOS_H

#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_prot.h>
#include <mach/vm_map.h>
#include <unistd.h>
#include <errno.h>

namespace memory_manipulation {
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
        kern_return_t kret;
        mach_vm_address_t address;
        mach_port_t task;

#if defined(MINIDETOUR_ARCH_X64)
        void* max_user_address = reinterpret_cast<void*>(0x7ffefffff000);
#elif defined(MINIDETOUR_ARCH_X86)
        void* max_user_address = reinterpret_cast<void*>(0x70000000);
#endif

        if (address_hint > max_user_address)
            address_hint = max_user_address;

        if (address_hint != nullptr)
        {
            address = reinterpret_cast<mach_vm_address_t>(page_round(address_hint, page_size())) + page_size();
            region_infos_t infos;
            size = page_addr_size((void*)address, size, page_size());
            int pages = size / page_size();

            for (int i = 0; i < 100000; ++i, address += page_size())
            {
                bool found = true;
                for (int j = 0; j < pages; ++j)
                {
                    infos = get_region_infos((void*)address);
                    if (infos.start != nullptr)
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
                        memory_protect(reinterpret_cast<void*>(address), size, rights);
                        return reinterpret_cast<void*>(address);
                    }
                }
            }

            address = reinterpret_cast<uintptr_t>(page_round(address_hint, page_size())) - page_size();
            for (int i = 0; i < 100000; ++i, address -= page_size())
            {
                bool found = true;
                for (int j = 0; j < pages; ++j)
                {
                    infos = get_region_infos((void*)address);
                    if (infos.start != nullptr)
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
                        memory_protect(reinterpret_cast<void*>(address), size, rights);
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
            memory_protect(reinterpret_cast<void*>(address), size, rights);
        }

        return reinterpret_cast<void*>(address);
    }

    int flush_instruction_cache(void* address, size_t size)
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