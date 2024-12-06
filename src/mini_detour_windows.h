#ifndef MINI_DETOUR_WINDOWS_H
#define MINI_DETOUR_WINDOWS_H

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <Windows.h>

namespace MiniDetour {
namespace MemoryManipulation {
#if defined(MINIDETOUR_ARCH_X64) || defined(MINIDETOUR_ARCH_ARM64)
    const void* max_user_address = reinterpret_cast<void*>(0x7ffffffff000);
#elif defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_ARM)
    const void* max_user_address = reinterpret_cast<void*>(0x7ffff000);
#endif

    DWORD _MemoryProtectRightsToNative(MemoryRights rights)
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

    MemoryRights _MemoryNativeToProtectRights(DWORD rights)
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

    RegionInfos_t GetRegionInfos(void* address)
    {
        MEMORY_BASIC_INFORMATION infos;
        RegionInfos_t res{};

        res.rights = mem_unset;
        if (VirtualQuery(address, &infos, sizeof(infos)) != 0)
        {
            res.start = reinterpret_cast<uintptr_t>(infos.BaseAddress);
            res.end = res.start + infos.RegionSize;
            res.rights = _MemoryNativeToProtectRights(infos.Protect & 0xFF);
        }

        return res;
    }

    std::vector<RegionInfos_t> GetAllRegions()
    {
        HANDLE process_handle = GetCurrentProcess();
        LPVOID search_addr = nullptr;
        MEMORY_BASIC_INFORMATION mem_infos{};
        MemoryRights rights;
        std::string module_name;
        std::wstring wmodule_name(1024, L'\0');
        DWORD wmodule_name_size = 1024;
        HMODULE module_handle;

        std::vector<RegionInfos_t> mappings;

        mappings.reserve(256);
        while (VirtualQueryEx(process_handle, search_addr, &mem_infos, sizeof(mem_infos)) != 0)
        {
            rights = MemoryRights::mem_unset;

            if (mem_infos.State != MEM_FREE)
            {
                rights = _MemoryNativeToProtectRights(mem_infos.Protect);

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

            mappings.emplace_back(
                rights,
                reinterpret_cast<uintptr_t>(mem_infos.BaseAddress),
                reinterpret_cast<uintptr_t>(mem_infos.BaseAddress) + mem_infos.RegionSize,
                std::move(module_name)
            );
            search_addr = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(mem_infos.BaseAddress) + mem_infos.RegionSize);
        }

        return mappings;
    }

    std::vector<RegionInfos_t> GetFreeRegions()
    {
        HANDLE process_handle = GetCurrentProcess();
        LPVOID search_addr = nullptr;
        MEMORY_BASIC_INFORMATION mem_infos{};
        std::string module_name;
        std::wstring wmodule_name(1024, L'\0');
        DWORD wmodule_name_size = 1024;
        HMODULE module_handle;

        std::vector<RegionInfos_t> mappings;

        mappings.reserve(256);
        while (VirtualQueryEx(process_handle, search_addr, &mem_infos, sizeof(mem_infos)) != 0)
        {
            if (mem_infos.State == MEM_FREE)
            {
                mappings.emplace_back(
                    MemoryRights::mem_unset,
                    reinterpret_cast<uintptr_t>(mem_infos.BaseAddress),
                    reinterpret_cast<uintptr_t>(mem_infos.BaseAddress) + mem_infos.RegionSize,
                    std::move(module_name)
                );
            }

            search_addr = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(mem_infos.BaseAddress) + mem_infos.RegionSize);
        }

        return mappings;
    }

    bool MemoryProtect(void* address, size_t size, MemoryRights rights, MemoryRights* old_rights)
    {
        DWORD oldProtect;
        bool res = VirtualProtect(address, size, _MemoryProtectRightsToNative(rights), &oldProtect) != FALSE;

        if (old_rights != nullptr)
            *old_rights = _MemoryNativeToProtectRights(oldProtect & 0xFF);

        return res;
    }

    void MemoryFree(void* address, size_t size)
    {
        if (address != nullptr)
            VirtualFree(address, 0, MEM_RELEASE);
    }

    static inline BOOL MemoryAllocWithProtection(HANDLE hProcess, LPVOID* address, SIZE_T size, MemoryRights rights)
    {
        *address = VirtualAllocEx(hProcess, *address, size, MEM_RESERVE | MEM_COMMIT, _MemoryProtectRightsToNative(rights));
        return *address != nullptr;
    }

    static inline void* MemoryAllocNear(HANDLE hProcess, uintptr_t addressHint, size_t size, MemoryRights rights, size_t pageSize)
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
                MemoryAllocWithProtection(hProcess, &address, size, rights);
                if (address != nullptr)
                    return address;
            }
        }

        // Fallback to anywhere alloc
        address = nullptr;
        MemoryAllocWithProtection(hProcess, &address, size, rights);

        return address;
    }

    void* MemoryAlloc(void* _addressHint, size_t size, MemoryRights rights)
    {
        if (_addressHint > max_user_address)
            _addressHint = (void*)max_user_address;

        auto pageSize = PageSize();
        auto addressHint = reinterpret_cast<uintptr_t>(PageRound(_addressHint, pageSize));
        size = _PageAddrSize((void*)addressHint, size, pageSize);

        HANDLE hProcess = GetCurrentProcess();

        if (_addressHint == nullptr)
        {
            LPVOID address = nullptr;
            MemoryAllocWithProtection(hProcess, &address, size, rights);
            return (void*)address;
        }

        return MemoryAllocNear(hProcess, addressHint, size, rights, pageSize);
    }
    
    bool SafeMemoryRead(void* address, uint8_t* buffer, size_t size)
    {
        auto hProcess = GetCurrentProcess();
        SIZE_T readSize = 0;

        if (ReadProcessMemory(hProcess, address, buffer, size, &readSize) == FALSE || readSize != size)
            return false;

        return true;
    }

    bool SafeMemoryWrite(void* address, const uint8_t* buffer, size_t size)
    {
        auto hProcess = GetCurrentProcess();
        SIZE_T writeSize = 0;

        if (WriteProcessMemory(hProcess, address, buffer, size, &writeSize) == FALSE || writeSize != size)
            return false;

        return true;
    }

    int FlushInstructionCache(void* pBase, size_t size)
    {
        return ::FlushInstructionCache(GetCurrentProcess(), pBase, size);
    }

    static bool LoadModuleExportDetails(void* moduleHandle, PIMAGE_EXPORT_DIRECTORY* exportDirectory, PDWORD* address, PDWORD* name, PWORD* ordinal)
    {
        PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)moduleHandle;

        if (pImgDOSHead->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)moduleHandle + pImgDOSHead->e_lfanew);

        if (pImgNTHead->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
            return false;

        *exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)moduleHandle + pImgNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        if (*exportDirectory == nullptr)
            return false;

        *address = (PDWORD)((LPBYTE)moduleHandle + (*exportDirectory)->AddressOfFunctions);
        *name = (PDWORD)((LPBYTE)moduleHandle + (*exportDirectory)->AddressOfNames);
        *ordinal = (PWORD)((LPBYTE)moduleHandle + (*exportDirectory)->AddressOfNameOrdinals);

        return true;
    }

    bool ReplaceModuleExport(void* moduleHandle, const char* exportName, void** exportCallAddress, void* newExportAddress)
    {
        PIMAGE_EXPORT_DIRECTORY pImgExpDir;
        PDWORD Address;
        PDWORD Name;
        PWORD Ordinal;

        if (!LoadModuleExportDetails(moduleHandle, &pImgExpDir, &Address, &Name, &Ordinal))
            return false;

        if (pImgExpDir->NumberOfNames > 0 && pImgExpDir->AddressOfNames != 0 && pImgExpDir->AddressOfNameOrdinals != 0)
        {
            for (DWORD i = 0; i < pImgExpDir->NumberOfNames; ++i)
            {
                if (strcmp((const char*)moduleHandle + Name[i], exportName) != 0)
                    continue;

                uint16_t nameOrdinal = pImgExpDir->Base + Ordinal[i];
                PDWORD exportAddress = Address + nameOrdinal - pImgExpDir->Base;

                if (*exportAddress == 0)
                    return false;

                MemoryManipulation::MemoryRights oldRights;

                if (addresses_are_relative_jumpable(moduleHandle, newExportAddress))
                {
                    if (!MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), MemoryManipulation::mem_rw, &oldRights))
                        return false;

                    if (exportCallAddress != nullptr)
                        *exportCallAddress = (void*)((LPBYTE)moduleHandle + *exportAddress);

                    *exportAddress = (uintptr_t)newExportAddress - (uintptr_t)moduleHandle;

                    MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), oldRights, nullptr);
                }
                else
                {
                    auto exportJump = mm.GetFreeJump(moduleHandle);
                    if (exportJump == nullptr)
                        return false;

                    if (!MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), MemoryManipulation::mem_rw, &oldRights))
                    {
                        mm.FreeJump(exportJump);
                        return false;
                    }

                    if (!MemoryManipulation::MemoryProtect(exportJump, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::mem_rwx, nullptr))
                    {
                        mm.FreeJump(exportJump);
                        return false;
                    }

                    MemoryManipulation::WriteAbsoluteJump(exportJump, newExportAddress);

                    if (exportCallAddress != nullptr)
                        *exportCallAddress = (void*)((LPBYTE)moduleHandle + *exportAddress);

                    *exportAddress = (uintptr_t)exportJump - (uintptr_t)moduleHandle;

                    MemoryManipulation::MemoryProtect(exportJump, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::mem_rx, nullptr);
                    MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), oldRights, nullptr);
                }

                return true;
            }
        }

        return false;
    }

    bool RestoreModuleExport(void* moduleHandle, const char* exportName, void* newExportAddress)
    {
        PIMAGE_EXPORT_DIRECTORY pImgExpDir;
        PDWORD Address;
        PDWORD Name;
        PWORD Ordinal;

        if (!LoadModuleExportDetails(moduleHandle, &pImgExpDir, &Address, &Name, &Ordinal))
            return false;

        if (pImgExpDir->NumberOfNames > 0 && pImgExpDir->AddressOfNames != 0 && pImgExpDir->AddressOfNameOrdinals != 0)
        {
            for (DWORD i = 0; i < pImgExpDir->NumberOfNames; ++i)
            {
                if (strcmp((const char*)moduleHandle + Name[i], exportName) != 0)
                    continue;

                uint16_t nameOrdinal = pImgExpDir->Base + Ordinal[i];
                PDWORD exportAddress = Address + nameOrdinal - pImgExpDir->Base;

                if (*exportAddress == 0)
                    return false;

                MemoryManipulation::MemoryRights oldRights;

                if (!MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), MemoryManipulation::mem_rw, &oldRights))
                    return false;

                auto oldJumpAddress = (void*)((uintptr_t)moduleHandle + *exportAddress);
                *exportAddress = (uintptr_t)newExportAddress - (uintptr_t)moduleHandle;

                MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), oldRights, nullptr);

                mm.FreeJump(oldJumpAddress);

                return true;
            }
        }

        return false;
    }
}//namespace MemoryManipulation
}//namespace MiniDetour

#endif//MINI_DETOUR_WINDOWS_H