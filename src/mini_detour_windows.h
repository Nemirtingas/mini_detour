#ifndef MINI_DETOUR_WINDOWS_H
#define MINI_DETOUR_WINDOWS_H

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <intsafe.h>

typedef enum _MY_THREAD_INFORMATION_CLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger
} MY_THREAD_INFORMATION_CLASS, * PMY_THREAD_INFORMATION_CLASS;

typedef struct _PEB PEB, * PPEB;

typedef long NTSTATUS;

typedef LONG KPRIORITY, * PKPRIORITY;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

extern "C" NTSTATUS NTAPI NtQueryInformationThread(
    IN  HANDLE                   ThreadHandle,
    IN  MY_THREAD_INFORMATION_CLASS ThreadInformationClass,
    OUT PVOID                    ThreadInformation,
    IN  ULONG                    ThreadInformationLength,
    OUT PULONG                   ReturnLength OPTIONAL);

namespace MiniDetour {
namespace MemoryManipulation {
namespace Implementation {
#if defined(MINIDETOUR_ARCH_X64) || defined(MINIDETOUR_ARCH_ARM64)
    const void* max_user_address = reinterpret_cast<void*>(0x7ffffffff000);
#elif defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_ARM)
    const void* max_user_address = reinterpret_cast<void*>(0x7ffff000);
#endif

    struct ThreadStackInfos_t
    {
        DWORD threadId;
        void* threadStack;
    };

    DWORD _MemoryProtectRightsToNative(MemoryRights rights)
    {
        switch (rights)
        {
            case MemoryRights::mem_r  : return PAGE_READONLY;
            case MemoryRights::mem_w  : return PAGE_READWRITE;
            case MemoryRights::mem_x  : return PAGE_EXECUTE;
            case MemoryRights::mem_rw : return PAGE_READWRITE;
            case MemoryRights::mem_rx : return PAGE_EXECUTE_READ;
            case MemoryRights::mem_wx : return PAGE_EXECUTE_READWRITE;
            case MemoryRights::mem_rwx: return PAGE_EXECUTE_READWRITE;

            default: return PAGE_NOACCESS;
        }
    }

    MemoryRights _MemoryNativeToProtectRights(DWORD rights)
    {
        switch (rights)
        {
            case PAGE_READONLY         : return MemoryRights::mem_r;
            case PAGE_READWRITE        : return MemoryRights::mem_rw;
            case PAGE_EXECUTE          : return MemoryRights::mem_x;
            case PAGE_EXECUTE_READ     : return MemoryRights::mem_rx;
            case PAGE_EXECUTE_READWRITE: return MemoryRights::mem_rwx;
            default                    : return MemoryRights::mem_none;
        }
    }

    void _GetRegionName(
        std::wstring& wmodule_name,
        void* address,
        char* regionName,
        size_t regionNameSize,
        std::vector<void*> const& heaps,
        std::vector<ThreadStackInfos_t> const& stacks)
    {
        DWORD wmodule_name_size = 1024;
        HMODULE moduleHandle;

        regionName[0] = '\0';
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)address, &moduleHandle) != FALSE && moduleHandle != nullptr)
        {
            while (wmodule_name_size != 0)
            {
                wmodule_name_size = GetModuleFileNameW(moduleHandle, &wmodule_name[0], wmodule_name.size());
                if (wmodule_name_size == wmodule_name.size())
                {
                    if (wmodule_name_size > 0x100000)
                        break;

                    wmodule_name.resize(wmodule_name_size * 2);
                }
                else if (wmodule_name_size != 0)
                {
                    wmodule_name.resize(wmodule_name_size);
                    wmodule_name_size = WideCharToMultiByte(CP_UTF8, 0, wmodule_name.c_str(), wmodule_name.length(), regionName, regionNameSize, nullptr, nullptr);
                    regionName[wmodule_name_size] = '\0';
                    wmodule_name.resize(wmodule_name.capacity());
                    return;
                }
            }
        }

        for (auto const& heap : heaps)
        {
            if (address == heap)
            {
                strncpy(regionName, "[heap]", regionNameSize);
                regionName[regionNameSize - 1] = '\0';
                return;
            }
        }
        for (auto const& stack : stacks)
        {
            if (address == stack.threadStack)
            {
                snprintf(regionName, regionNameSize, "[thread %lu stack]", stack.threadId);
                return;
            }
        }
    }

    std::vector<void*> _GetProcessHeapAddresses()
    {
        std::vector<void*> heaps;
        auto numberOfHeaps = GetProcessHeaps(0, nullptr);
        if (numberOfHeaps > 0)
        {
            heaps.resize(numberOfHeaps * 2);
            numberOfHeaps = GetProcessHeaps(heaps.size(), heaps.data());
            heaps.resize(std::min<size_t>(numberOfHeaps, heaps.size()));
        }
        return heaps;
    }

    std::vector<ThreadStackInfos_t> _GetProcessStackAddresses()
    {
        std::vector<ThreadStackInfos_t> stacks;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != nullptr && snap != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 te;
            te.dwSize = sizeof(te);

            if (Thread32First(snap, &te))
            {
                auto pid = GetProcessId(GetCurrentProcess());
                do
                {
                    if (te.th32OwnerProcessID == pid)
                    {
                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                        if (hThread)
                        {
                            THREAD_BASIC_INFORMATION basicInfo;
                            if (NtQueryInformationThread(hThread, ThreadBasicInformation, &basicInfo, sizeof(THREAD_BASIC_INFORMATION), NULL) >= 0)
                            {
                                auto* tib = (const NT_TIB*)basicInfo.TebBaseAddress;
                                stacks.emplace_back(ThreadStackInfos_t {
                                    te.th32ThreadID,
                                    tib->StackLimit, // Because stack is reversed, our begin is the stack's end
                                });
                            }

                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }

        return stacks;
    }

    size_t _GetRegions(MiniDetourMemoryManipulationRegionInfos_t* regions, size_t regionCount, bool onlyFree)
    {
        HANDLE processHandle = GetCurrentProcess();
        LPVOID searchAddress = nullptr;
        MEMORY_BASIC_INFORMATION memoryBasicInformation{};
        size_t writtenRegionCount = 0;
        size_t currentRegionCount = 0;
        std::wstring regionNameBuffer(1024, L'\0');

        auto heaps = _GetProcessHeapAddresses();
        auto stacks = _GetProcessStackAddresses();

        while (VirtualQueryEx(processHandle, searchAddress, &memoryBasicInformation, sizeof(memoryBasicInformation)) != 0)
        {
            if ((!onlyFree || (onlyFree && memoryBasicInformation.State == MEM_FREE)) && regions != nullptr && writtenRegionCount < regionCount)
            {
                auto& region = *regions;
                if (region.StructSize >= sizeof(region))
                {
                    regions = reinterpret_cast<MiniDetourMemoryManipulationRegionInfos_t*>(reinterpret_cast<uintptr_t>(regions) + regions->StructSize);
                    region.Rights = MemoryRights::mem_unset;
                    region.Start = reinterpret_cast<uintptr_t>(memoryBasicInformation.BaseAddress);
                    region.End = reinterpret_cast<uintptr_t>(memoryBasicInformation.BaseAddress) + memoryBasicInformation.RegionSize;
                    region.ModuleName[0] = '\0';

                    if (memoryBasicInformation.State != MEM_FREE)
                    {
                        region.Rights = _MemoryNativeToProtectRights(memoryBasicInformation.Protect);
                        _GetRegionName(
                            regionNameBuffer,
                            memoryBasicInformation.BaseAddress,
                            region.ModuleName,
                            region.StructSize - (sizeof(region) - sizeof(region.ModuleName)),
                            heaps,
                            stacks);
                    }
                    ++writtenRegionCount;
                }
            }

            if (!onlyFree || (onlyFree && memoryBasicInformation.State == MEM_FREE))
                ++currentRegionCount;

            searchAddress = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(memoryBasicInformation.BaseAddress) + memoryBasicInformation.RegionSize);
        }

        return currentRegionCount;
    }

    size_t PageSize()
    {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return sysInfo.dwPageSize;
    }

    void GetRegionInfos(void* address, MiniDetourMemoryManipulationRegionInfos_t* regionInfos)
    {
        MEMORY_BASIC_INFORMATION infos;
        std::wstring regionNameBuffer(1024, L'\0');

        auto heaps = _GetProcessHeapAddresses();
        auto stacks = _GetProcessStackAddresses();

        regionInfos->Rights = MemoryRights::mem_unset;
        if (VirtualQuery(address, &infos, sizeof(infos)) != 0)
        {
            regionInfos->Start = reinterpret_cast<uintptr_t>(infos.BaseAddress);
            regionInfos->End = regionInfos->Start + infos.RegionSize;
            regionInfos->Rights = _MemoryNativeToProtectRights(infos.Protect & 0xFF);
            _GetRegionName(
                regionNameBuffer,
                infos.BaseAddress,
                regionInfos->ModuleName,
                regionInfos->StructSize - (sizeof(*regionInfos) - sizeof(regionInfos->ModuleName)),
                heaps,
                stacks);
        }
    }

    inline size_t GetAllRegions(MiniDetourMemoryManipulationRegionInfos_t* regions, size_t regionCount)
    {
        return _GetRegions(regions, regionCount, false);
    }

    inline size_t GetFreeRegions(MiniDetourMemoryManipulationRegionInfos_t* regions, size_t regionCount)
    {
        return _GetRegions(regions, regionCount, true);
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

        auto freeRegionCount = GetFreeRegions(nullptr, 0);
        std::vector<RegionInfos_t> freeRegions((size_t)(freeRegionCount * 1.5));
        freeRegionCount = GetFreeRegions(freeRegions.data(), freeRegions.size());
        if (freeRegionCount < freeRegions.size())
            freeRegions.resize(freeRegionCount);

        std::sort(freeRegions.begin(), freeRegions.end(), [addressHint](MemoryManipulation::RegionInfos_t const& l, MemoryManipulation::RegionInfos_t const& r)
        {
            return std::max(addressHint, l.Start) - std::min(addressHint, l.Start) <
                std::max(addressHint, r.Start) - std::min(addressHint, r.Start);
        });

        for (auto const& region : freeRegions)
        {
            auto start = region.Start > addressHint ? region.Start : (region.End - pageSize);
            auto increment = static_cast<int32_t>(region.Start > addressHint ? pageSize : -pageSize);

            for (auto allocAddress = start; allocAddress >= region.Start && (allocAddress + size) < region.End; allocAddress += increment)
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

}//namespace Implementation
}//namespace MemoryManipulation

namespace ModuleManipulation {
namespace Implementation {
    static bool _LoadModuleExportDetails(void* moduleHandle, void** moduleBase, PIMAGE_EXPORT_DIRECTORY* imageExportDirectory, PDWORD* functionAddressesRVA, PDWORD* functionNamesRVA, PWORD* functionOrdinal)
    {
        PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)moduleHandle;

        if (imageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)moduleHandle + imageDosHeader->e_lfanew);

        if (imageNTHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
            return false;

        *imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)moduleHandle + imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        if (*imageExportDirectory == nullptr)
            return false;

        *moduleBase = moduleHandle;
        *functionAddressesRVA = (PDWORD)((LPBYTE)moduleHandle + (*imageExportDirectory)->AddressOfFunctions);
        *functionNamesRVA = (PDWORD)((LPBYTE)moduleHandle + (*imageExportDirectory)->AddressOfNames);
        *functionOrdinal = (PWORD)((LPBYTE)moduleHandle + (*imageExportDirectory)->AddressOfNameOrdinals);

        return true;
    }

    static bool _LoadModuleIATDetails(void* moduleHandle, void** moduleBase, PIMAGE_IMPORT_DESCRIPTOR* imageImportDescriptor)
    {
        PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)moduleHandle;

        if (imageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)moduleHandle + imageDosHeader->e_lfanew);

        if (imageNTHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC && imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
            return false;

        *moduleBase = moduleHandle;
        *imageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)imageDosHeader + imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        return true;
    }

    static bool _ReplaceModuleExportInPlace(void* moduleBase, PDWORD exportAddress, void** exportCallAddress, void* newExportAddress)
    {
        MemoryManipulation::MemoryRights oldRights;

        if (!MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), MemoryManipulation::MemoryRights::mem_rw, &oldRights))
            goto Error;

        *exportCallAddress = (void*)((char*)moduleBase + *exportAddress);
        *exportAddress = (uintptr_t)newExportAddress - (uintptr_t)moduleBase;

        MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), oldRights, nullptr);

        return true;

    Error:
        *exportCallAddress = nullptr;
        return false;
    }

    static bool _ReplaceModuleExportWithTrampoline(void* moduleBase, PDWORD exportAddress, void** exportCallAddress, void* newExportAddress)
    {
        MemoryManipulation::MemoryRights oldRights;

        *exportCallAddress = nullptr;
        auto exportJump = mm.GetFreeJump(moduleBase);
        if (exportJump == nullptr)
            goto Error;

        if (!MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), MemoryManipulation::MemoryRights::mem_rw, &oldRights))
            goto ErrorFree;

        if (!MemoryManipulation::MemoryProtect(exportJump, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::MemoryRights::mem_rwx, nullptr))
            goto ErrorFree;

        MemoryManipulation::WriteAbsoluteJump(exportJump, newExportAddress);

        *exportCallAddress = (void*)((char*)moduleBase + *exportAddress);
        *exportAddress = (uintptr_t)exportJump - (uintptr_t)moduleBase;

        MemoryManipulation::MemoryProtect(exportJump, AbsJump::GetMaxOpcodeSize(), MemoryManipulation::MemoryRights::mem_rx, nullptr);
        MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), oldRights, nullptr);

        return true;

    ErrorFree:
        mm.FreeJump(exportJump);
    Error:
        *exportCallAddress = nullptr;
        return false;
    }

    static inline PDWORD _GetExportAddress(void* moduleBase, PDWORD functionAddressesRVA, PDWORD functionNamesRVA, PWORD functionOrdinals, DWORD functionNameCount, const char* symbolName)
    {
        for (DWORD j = 0; j < functionNameCount; ++j)
        {
            if (strcmp((const char*)moduleBase + functionNamesRVA[j], symbolName) == 0)
                return functionAddressesRVA + functionOrdinals[j];
        }

        return nullptr;
    }

    static inline void** _GetIATAddress(void* moduleBase, PIMAGE_IMPORT_DESCRIPTOR imageImportDescriptor, const char* moduleName, const char* symbolName, DWORD ordinal)
    {
        void** addressTable = nullptr;
        PIMAGE_THUNK_DATA thunkData = nullptr;

        for (auto* importDescriptor = imageImportDescriptor;
            importDescriptor->Characteristics != 0;
            ++importDescriptor)
        {
            auto* libraryName = (const char*)((uintptr_t)moduleBase + importDescriptor->Name);
            if (stricmp(moduleName, libraryName) == 0)
            {
                addressTable = (void**)((uintptr_t)moduleBase + importDescriptor->FirstThunk);
                thunkData = (PIMAGE_THUNK_DATA)((uintptr_t)moduleBase + importDescriptor->OriginalFirstThunk);
                break;
            }
        }

        if (thunkData == nullptr)
            return nullptr;

        for (int i = 0; thunkData[i].u1.AddressOfData != 0; ++i)
        {
            if (thunkData[i].u1.AddressOfData & 0x80000000ul)
            {
                if (symbolName == nullptr && (thunkData[i].u1.Ordinal & (~0x80000000ul)) == ordinal)
                    return addressTable + i;
            }
            else if (symbolName != nullptr && strcmp(((PIMAGE_IMPORT_BY_NAME)((uintptr_t)moduleBase + thunkData[i].u1.AddressOfData))->Name, symbolName) == 0)
            {
                return addressTable + i;
            }
        }

        return nullptr;
    }

    size_t GetAllExportedSymbols(void* moduleHandle, ExportDetails_t* exportDetails, size_t exportDetailsCount)
    {
        void* moduleBase = nullptr;
        PIMAGE_EXPORT_DIRECTORY imageExportDirectory;
        PDWORD functionAddressesRVA;
        PDWORD functionNamesRVA;
        PWORD functionOrdinal;
        size_t result = 0;

        if (!_LoadModuleExportDetails(moduleHandle, &moduleBase, &imageExportDirectory, &functionAddressesRVA, &functionNamesRVA, &functionOrdinal))
            return result;

        if (imageExportDirectory->NumberOfFunctions <= 0)
            return result;

        if (exportDetails == nullptr)
            return imageExportDirectory->NumberOfFunctions;

        for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions && i < exportDetailsCount; ++i)
        {
            if (functionAddressesRVA[i] == 0)
                continue;

            exportDetails[result].ExportName = nullptr;
            for (DWORD j = 0; j < imageExportDirectory->NumberOfNames; ++j)
            {
                if (functionOrdinal[j] == i)
                {
                    exportDetails[result].ExportName = (const char*)moduleBase + functionNamesRVA[j];
                    break;
                }
            }

            exportDetails[result].ExportCallAddress = (void*)((uintptr_t)moduleBase + functionAddressesRVA[i]);
            exportDetails[result++].ExportOrdinal = i + imageExportDirectory->Base;
        }

        return result;
    }

    size_t GetAllIATSymbols(void* moduleHandle, IATDetails_t* iatDetails, size_t iatDetailsCount)
    {
        void* moduleBase = nullptr;
        PIMAGE_IMPORT_DESCRIPTOR imageImportDescriptor;
        void** addressTable;
        PIMAGE_THUNK_DATA thunkData;
        size_t result = 0;

        if (!_LoadModuleIATDetails(moduleHandle, &moduleBase, &imageImportDescriptor))
            return result;

        if (iatDetails == nullptr)
        {
            for (auto* importDescriptor = imageImportDescriptor;
                importDescriptor->Characteristics != 0;
                ++importDescriptor)
            {
                for (thunkData = (PIMAGE_THUNK_DATA)((uintptr_t)moduleBase + importDescriptor->OriginalFirstThunk);
                    thunkData->u1.AddressOfData != 0;
                    ++thunkData)
                {
                    ++result;
                }
            }

            return result;
        }

        for (auto* importDescriptor = imageImportDescriptor;
            importDescriptor->Characteristics != 0 && result < iatDetailsCount;
            ++importDescriptor)
        {
            auto* libraryName = (const char*)((uintptr_t)moduleBase + importDescriptor->Name);

            addressTable = (void**)((uintptr_t)moduleBase + importDescriptor->FirstThunk);
            thunkData = (PIMAGE_THUNK_DATA)((uintptr_t)moduleBase + importDescriptor->OriginalFirstThunk);

            for (int i = 0; thunkData[i].u1.AddressOfData != 0 && result < iatDetailsCount; ++i)
            {
                if (thunkData[i].u1.AddressOfData & 0x80000000)
                {
                    iatDetails[result].ImportOrdinal = thunkData[i].u1.Ordinal & (~0x80000000);
                    iatDetails[result].ImportName = nullptr;
                }
                else
                {
                    iatDetails[result].ImportOrdinal = uint32_t(-1);
                    iatDetails[result].ImportName = ((PIMAGE_IMPORT_BY_NAME)((uintptr_t)moduleBase + thunkData[i].u1.AddressOfData))->Name;
                }

                iatDetails[result].ImportCallAddress = addressTable[i];
                iatDetails[result++].ImportModuleName = libraryName;
            }
        }

        return result;
    }

    size_t ReplaceModuleExports(void* moduleHandle, ExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount)
    {
        void* moduleBase = nullptr;
        PIMAGE_EXPORT_DIRECTORY imageExportDirectory;
        PDWORD functionAddressesRVA;
        PDWORD functionNamesRVA;
        PWORD functionOrdinal;
        size_t result = 0;

        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
            exportReplaceDetails[i].ExportCallAddress = nullptr;

        if (!_LoadModuleExportDetails(moduleHandle, &moduleBase, &imageExportDirectory, &functionAddressesRVA, &functionNamesRVA, &functionOrdinal))
            return result;

        SPDLOG_INFO("Program base address: {:016X}, Dynamic symbol start: {:016X}", (uintptr_t)moduleBase, (uintptr_t)imageExportDirectory);

        if (imageExportDirectory->NumberOfNames <= 0 || functionNamesRVA == 0 || functionOrdinal == 0)
            return result;

        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
        {
            auto exportAddress = _GetExportAddress(moduleBase, functionAddressesRVA, functionNamesRVA, functionOrdinal, imageExportDirectory->NumberOfNames, exportReplaceDetails[i].ExportName);
            if (exportAddress == nullptr)
            {
                exportReplaceDetails[i].ExportCallAddress = nullptr;
                continue;
            }

            if (_AddressesAreRelativeJumpable(moduleBase, exportReplaceDetails[i].NewExportAddress))
            {
                if (_ReplaceModuleExportInPlace(moduleBase, exportAddress, &exportReplaceDetails[i].ExportCallAddress, exportReplaceDetails[i].NewExportAddress))
                    ++result;
            }
            else
            {
                if (_ReplaceModuleExportWithTrampoline(moduleBase, exportAddress, &exportReplaceDetails[i].ExportCallAddress, exportReplaceDetails[i].NewExportAddress))
                    ++result;
            }
        }

        return result;
    }

    size_t RestoreModuleExports(void* moduleHandle, ExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount)
    {
        void* moduleBase = nullptr;
        PIMAGE_EXPORT_DIRECTORY imageExportDirectory;
        PDWORD functionAddressesRVA;
        PDWORD functionNamesRVA;
        PWORD functionOrdinal;
        size_t result = 0;

        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
            exportReplaceDetails[i].NewExportAddress = nullptr;

        if (!_LoadModuleExportDetails(moduleHandle, &moduleBase, &imageExportDirectory, &functionAddressesRVA, &functionNamesRVA, &functionOrdinal))
            return result;

        if (imageExportDirectory->NumberOfNames <= 0 || functionNamesRVA == 0 || functionOrdinal == 0)
            return result;

        for (size_t i = 0; i < exportReplaceDetailsCount; ++i)
        {
            auto exportAddress = _GetExportAddress(moduleBase, functionAddressesRVA, functionNamesRVA, functionOrdinal, imageExportDirectory->NumberOfNames, exportReplaceDetails[i].ExportName);
            if (exportAddress == nullptr)
            {
                exportReplaceDetails[i].NewExportAddress = nullptr;
                continue;
            }

            MemoryManipulation::MemoryRights oldRights;

            if (!MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), MemoryManipulation::MemoryRights::mem_rw, &oldRights))
                break;

            exportReplaceDetails[i].NewExportAddress = (void*)((uintptr_t)*exportAddress + (uintptr_t)moduleBase);
            auto oldJumpAddress = (void*)((uintptr_t)moduleBase + *exportAddress);
            *exportAddress = (uintptr_t)exportReplaceDetails[i].ExportCallAddress - (uintptr_t)moduleBase;

            MemoryManipulation::MemoryProtect(exportAddress, sizeof(*exportAddress), oldRights, nullptr);

            mm.FreeJump(oldJumpAddress);
            ++result;
        }

        return result;
    }

    size_t ReplaceModuleIATs(void* moduleHandle, IATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount)
    {
        void* moduleBase = nullptr;
        PIMAGE_IMPORT_DESCRIPTOR imageImportDescriptor;
        size_t result = 0;

        for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
            iatReplaceDetails[i].IATCallAddress = nullptr;

        if (!_LoadModuleIATDetails(moduleHandle, &moduleBase, &imageImportDescriptor))
            return result;

        for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
        {
            auto iatAddress = _GetIATAddress(moduleBase, imageImportDescriptor, iatReplaceDetails[i].IATModuleName, iatReplaceDetails[i].IATName, iatReplaceDetails[i].IATOrdinal);
            if (iatAddress == nullptr)
            {
                iatReplaceDetails[i].IATCallAddress = nullptr;
                continue;
            }

            MiniDetour::MemoryManipulation::MemoryRights oldRights;
            if (!MiniDetour::MemoryManipulation::MemoryProtect(iatAddress, sizeof(*iatAddress), MiniDetour::MemoryManipulation::MemoryRights::mem_rwx, &oldRights))
            {
                iatReplaceDetails[i].IATCallAddress = nullptr;
                continue;
            }

            iatReplaceDetails[i].IATCallAddress = *iatAddress;
            *iatAddress = iatReplaceDetails[i].NewIATAddress;
            MiniDetour::MemoryManipulation::MemoryProtect(iatAddress, sizeof(*iatAddress), oldRights, nullptr);
            ++result;
        }

        return result;
    }

    size_t RestoreModuleIATs(void* moduleHandle, IATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount)
    {
        void* moduleBase = nullptr;
        PIMAGE_IMPORT_DESCRIPTOR imageImportDescriptor;
        size_t result = 0;

        for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
            iatReplaceDetails[i].NewIATAddress = nullptr;

        if (!_LoadModuleIATDetails(moduleHandle, &moduleBase, &imageImportDescriptor))
            return result;

        for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
        {
            auto iatAddress = _GetIATAddress(moduleBase, imageImportDescriptor, iatReplaceDetails[i].IATModuleName, iatReplaceDetails[i].IATName, iatReplaceDetails[i].IATOrdinal);
            if (iatAddress == nullptr)
            {
                iatReplaceDetails[i].NewIATAddress = nullptr;
                continue;
            }

            MiniDetour::MemoryManipulation::MemoryRights oldRights;
            if (!MiniDetour::MemoryManipulation::MemoryProtect(iatAddress, sizeof(*iatAddress), MiniDetour::MemoryManipulation::MemoryRights::mem_rwx, &oldRights))
            {
                iatReplaceDetails[i].NewIATAddress = nullptr;
                continue;
            }

            iatReplaceDetails[i].NewIATAddress = *iatAddress;
            *iatAddress = iatReplaceDetails[i].IATCallAddress;
            MiniDetour::MemoryManipulation::MemoryProtect(iatAddress, sizeof(*iatAddress), oldRights, nullptr);
            ++result;
        }

        return result;
    }

}//namespace Implementation
}//namespace ModuleManipulation
}//namespace MiniDetour

#endif//MINI_DETOUR_WINDOWS_H