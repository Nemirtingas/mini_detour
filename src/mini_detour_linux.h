#ifndef MINI_DETOUR_LINUX_H
#define MINI_DETOUR_LINUX_H

#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

namespace memory_manipulation {
    int memory_protect_rights_to_native(memory_rights rights)
    {
        switch (rights)
        {
            case mem_r  : return PROT_READ;
            case mem_w  : return PROT_WRITE;
            case mem_x  : return PROT_EXEC;
            case mem_rw : return PROT_WRITE | PROT_READ;
            case mem_rx : return PROT_READ  | PROT_EXEC;
            case mem_wx : return PROT_WRITE | PROT_EXEC;
            case mem_rwx: return PROT_WRITE | PROT_READ | PROT_EXEC;

            default: return PROT_NONE;
        }
    }

    size_t page_size()
    {
        return sysconf(_SC_PAGESIZE);
    }

    region_infos_t get_region_infos(void* address)
    {
        region_infos_t res{};

        uintptr_t target = (uintptr_t)address;
        std::ifstream f("/proc/self/maps");
        std::string s;
        while (std::getline(f, s))
        {
            if (!s.empty() && s.find("vdso") == std::string::npos && s.find("vsyscall") == std::string::npos)
            {
                char* strend = &s[0];
                uintptr_t start = (uintptr_t)strtoul(strend, &strend, 16);
                uintptr_t end = (uintptr_t)strtoul(strend + 1, &strend, 16);
                if (start != 0 && end != 0 && start <= target && target < end) {
                    res.start = (void*)start;
                    res.end = (void*)end;

                    ++strend;
                    if (strend[0] == 'r')
                        (unsigned int&)res.rights |= mem_r;

                    if (strend[1] == 'w')
                        (unsigned int&)res.rights |= mem_w;

                    if (strend[2] == 'x')
                        (unsigned int&)res.rights |= mem_x;

                    break;
                }
            }
        }
        return res;
    }

    bool memory_protect(void* address, size_t size, memory_rights rights, memory_rights* old_rights)
    {
        region_infos_t infos;
        if(old_rights != nullptr)
            infos = get_region_infos(address);

        bool res = mprotect(page_round(address, page_size()), page_addr_size(address, size, page_size()), memory_protect_rights_to_native(rights)) == 0;

        if (old_rights != nullptr)
            *old_rights = infos.rights;

        return res;
    }

    void memory_free(void* address, size_t size)
    {
        if (address != nullptr)
            munmap(address, size);
    }

    void* memory_alloc(void* address_hint, size_t size, memory_rights rights)
    {
        if (address_hint != nullptr)
        {
            uintptr_t address = reinterpret_cast<uintptr_t>(page_round(address_hint, page_size())) + page_size();
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
                    void* r = mmap((void*)address, size, memory_protect_rights_to_native(rights), MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                    if (r != nullptr)
                        return r;
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
                    void* r = mmap((void*)address, size, memory_protect_rights_to_native(rights), MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                    if (r != nullptr)
                        return r;
                }
            }

            // Fallback to hint alloc
        }

        return mmap(address_hint, size, memory_protect_rights_to_native(rights), MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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

#endif//MINI_DETOUR_LINUX_H