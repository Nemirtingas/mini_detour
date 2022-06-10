#ifndef MINI_DETOUR_WINDOWS_H
#define MINI_DETOUR_WINDOWS_H

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <Windows.h>

namespace memory_manipulation {
    DWORD memory_protect_rights_to_native(memory_rights rights)
    {
        switch (rights)
        {
            case mem_r  : return PAGE_READONLY;
            case mem_w  : return PAGE_READWRITE;
            case mem_x  : return PAGE_EXECUTE;
            case mem_rw : return PAGE_READWRITE;
            case mem_rx : return PAGE_EXECUTE_READ;
            case mem_wx : return PAGE_EXECUTE_READWRITE;
            case mem_rwx: return PAGE_EXECUTE_READWRITE;

            default: return PAGE_NOACCESS;
        }
    }

    memory_rights memory_native_to_protect_rights(DWORD rights)
    {
        switch (rights)
        {
            case PAGE_READONLY         : return mem_r;
            case PAGE_READWRITE        : return mem_rw;
            case PAGE_EXECUTE          : return mem_x;
            case PAGE_EXECUTE_READ     : return mem_rx;
            case PAGE_EXECUTE_READWRITE: return mem_rwx;
            default                    : return mem_none;
        }
    }

    size_t page_size()
    {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return sysInfo.dwPageSize;
    }

    region_infos_t get_region_infos(void* address)
    {
        MEMORY_BASIC_INFORMATION infos;
        region_infos_t res{};

        res.rights = mem_unset;
        if (VirtualQuery(address, &infos, sizeof(infos)) != 0)
        {
            res.start = infos.BaseAddress;
            res.end = (uint8_t*)res.start + infos.RegionSize;
            res.rights = memory_native_to_protect_rights(infos.Protect);
        }

        return res;
    }

    bool memory_protect(void* address, size_t size, memory_rights rights, memory_rights* old_rights)
    {
        DWORD oldProtect;
        bool res = VirtualProtect(address, size, memory_protect_rights_to_native(rights), &oldProtect) != FALSE;

        if (old_rights != nullptr)
            *old_rights = memory_native_to_protect_rights(oldProtect);

        return res;
    }

    void memory_free(void* address, size_t size)
    {
        if (address != nullptr)
            VirtualFree(address, 0, MEM_RELEASE);
    }

    void* memory_alloc(void* address_hint, size_t size, memory_rights rights)
    {
        MEMORY_BASIC_INFORMATION mbi;

        HANDLE hProcess = GetCurrentProcess();

        PBYTE pbBase = (PBYTE)address_hint;
        PBYTE pbLast = pbBase;
        for (;; pbLast = (PBYTE)mbi.BaseAddress + mbi.RegionSize)
        {

            ZeroMemory(&mbi, sizeof(mbi));
            if (VirtualQueryEx(hProcess, (PVOID)pbLast, &mbi, sizeof(mbi)) == 0)
                continue;

            // Usermode address space has such an unaligned region size always at the
            // end and only at the end.
            //
            if ((mbi.RegionSize & 0xfff) == 0xfff)
            {
                break;
            }

            // Skip anything other than a pure free region.
            //
            if (mbi.State != MEM_FREE)
                continue;

            // Use the max of mbi.BaseAddress and pbBase, in case mbi.BaseAddress < pbBase.
            PBYTE pbAddress = (PBYTE)mbi.BaseAddress > pbBase ? (PBYTE)mbi.BaseAddress : pbBase;

            // Round pbAddress up to the nearest MM allocation boundary.
            const DWORD_PTR mmGranularityMinusOne = (DWORD_PTR)(0x10000 - 1);
            pbAddress = (PBYTE)(((DWORD_PTR)pbAddress + mmGranularityMinusOne) & ~mmGranularityMinusOne);

            for (; pbAddress < (PBYTE)mbi.BaseAddress + mbi.RegionSize; pbAddress += 0x10000)
            {
                PBYTE pbAlloc = (PBYTE)VirtualAllocEx(hProcess, pbAddress, size,
                    MEM_RESERVE | MEM_COMMIT, memory_protect_rights_to_native(rights));

                if (pbAlloc == nullptr)
                    continue;

                return pbAlloc;
            }
        }

        return nullptr;
    }

    int flush_instruction_cache(void* pBase, size_t size)
    {
        return FlushInstructionCache(GetCurrentProcess(), pBase, size);
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

#endif//MINI_DETOUR_WINDOWS_H