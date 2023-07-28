#ifndef MINI_DETOUR_WINDOWS_H
#define MINI_DETOUR_WINDOWS_H

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <Windows.h>

namespace MemoryManipulation {
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

    size_t PageSize()
    {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return sysInfo.dwPageSize;
    }

    region_infos_t GetRegionInfos(void* address)
    {
        MEMORY_BASIC_INFORMATION infos;
        region_infos_t res{};

        res.rights = mem_unset;
        if (VirtualQuery(address, &infos, sizeof(infos)) != 0)
        {
            res.start = reinterpret_cast<uintptr_t>(infos.BaseAddress);
            res.end = res.start + infos.RegionSize;
            res.rights = memory_native_to_protect_rights(infos.Protect & 0xFF);
        }

        return res;
    }

    std::vector<region_infos_t> GetAllRegions()
    {
        HANDLE process_handle = GetCurrentProcess();
        LPVOID search_addr = nullptr;
        MEMORY_BASIC_INFORMATION mem_infos{};
        memory_rights rights;
        std::string module_name;
        std::wstring wmodule_name(1024, L'\0');
        DWORD wmodule_name_size = 1024;
        HMODULE module_handle;

        std::vector<region_infos_t> mappings;

        mappings.reserve(256);
        while (VirtualQueryEx(process_handle, search_addr, &mem_infos, sizeof(mem_infos)) != 0)
        {
            rights = memory_rights::mem_unset;

            if (mem_infos.State != MEM_FREE)
            {
                rights = MemoryManipulation::memory_native_to_protect_rights(mem_infos.Protect);

                if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT|GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)mem_infos.BaseAddress, &module_handle) != FALSE && module_handle != nullptr)
                {
                    while (wmodule_name_size != 0)
                    {
                        wmodule_name_size = GetModuleFileNameW(module_handle, &wmodule_name[0], wmodule_name.size());
                        if (wmodule_name_size == wmodule_name.size())
                        {
                            if (wmodule_name_size > 0x100000)
                                break;

                            wmodule_name.resize(wmodule_name_size * 2);
                        }
                        else if (wmodule_name_size != 0)
                        {
                            wmodule_name.resize(wmodule_name_size);
                            wmodule_name_size = WideCharToMultiByte(CP_UTF8, 0, wmodule_name.c_str(), wmodule_name.length(), nullptr, 0, nullptr, nullptr);
                            if (wmodule_name_size != 0)
                            {
                                module_name.resize(wmodule_name_size);
                                WideCharToMultiByte(CP_UTF8, 0, wmodule_name.c_str(), wmodule_name.length(), &module_name[0], module_name.size(), nullptr, nullptr);
                            }

                            wmodule_name.resize(wmodule_name.capacity());
                            break;
                        }
                    }
                }
            }

            mappings.emplace_back(region_infos_t{
                rights,
                reinterpret_cast<uintptr_t>(mem_infos.BaseAddress),
                reinterpret_cast<uintptr_t>(mem_infos.BaseAddress) + mem_infos.RegionSize,
                std::move(module_name),
            });
            search_addr = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(mem_infos.BaseAddress) + mem_infos.RegionSize);
        }

        return mappings;
    }

    bool MemoryProtect(void* address, size_t size, memory_rights rights, memory_rights* old_rights)
    {
        DWORD oldProtect;
        bool res = VirtualProtect(address, size, memory_protect_rights_to_native(rights), &oldProtect) != FALSE;

        if (old_rights != nullptr)
            *old_rights = memory_native_to_protect_rights(oldProtect & 0xFF);

        return res;
    }

    void MemoryFree(void* address, size_t size)
    {
        if (address != nullptr)
            VirtualFree(address, 0, MEM_RELEASE);
    }

    void* MemoryAlloc(void* address_hint, size_t size, memory_rights rights)
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
    
    bool SafeMemoryRead(void* address, uint8_t* buffer, size_t size)
    {
        auto hProcess = GetCurrentProcess();
        size_t readSize = 0;

        if (ReadProcessMemory(hProcess, address, buffer, size, &readSize) == FALSE || readSize != size)
            return false;

        return true;
    }

    bool SafeMemoryWrite(void* address, const uint8_t* buffer, size_t size)
    {
        auto hProcess = GetCurrentProcess();
        size_t writeSize = 0;

        if (WriteProcessMemory(hProcess, address, buffer, size, &writeSize) == FALSE || writeSize != size)
            return false;

        return true;
    }

    int FlushInstructionCache(void* pBase, size_t size)
    {
        return ::FlushInstructionCache(GetCurrentProcess(), pBase, size);
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