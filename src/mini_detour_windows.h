#ifndef MINI_DETOUR_WINDOWS_H
#define MINI_DETOUR_WINDOWS_H

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <windows.h>
#include <intsafe.h>

typedef enum _MY_THREAD_INFORMATION_CLASS
{
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
} MY_THREAD_INFORMATION_CLASS, *PMY_THREAD_INFORMATION_CLASS;

typedef struct _PEB PEB, *PPEB;

typedef long NTSTATUS;

typedef LONG KPRIORITY, *PKPRIORITY;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

extern "C" NTSTATUS NTAPI NtQueryInformationThread(
    IN HANDLE ThreadHandle, IN MY_THREAD_INFORMATION_CLASS ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS NTAPI
NtGetNextThread(IN HANDLE ProcessHandle, IN HANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN ULONG HandleAttributes, IN ULONG Flags, OUT PHANDLE NewThreadHandle);

// Calls keep(thread) for every thread of the process, opened with access: it returns true to keep the handle open.
// NtGetNextThread only goes through the threads of this process, where a Toolhelp snapshot lists those of the whole
// system (tens of milliseconds, for each hook).
template <typename Keep>
static void _ForEachProcessThread(ACCESS_MASK access, Keep keep)
{
    HANDLE previous   = nullptr;
    bool keepPrevious = false;
    HANDLE thread;
    while (NtGetNextThread(GetCurrentProcess(), previous, access, 0, 0, &thread) >= 0)
    {
        // The previous handle is needed to get the next one.
        if (previous != nullptr && !keepPrevious)
            CloseHandle(previous);

        keepPrevious = keep(thread);
        previous     = thread;
    }

    if (previous != nullptr && !keepPrevious)
        CloseHandle(previous);
}

// Suspends the other threads of the process while hooked code is written: a thread running the bytes being written
// could execute half of the old and half of the new instructions.
class _OtherThreadsFreezer_t
{
    std::vector<HANDLE> _Threads;

    static uintptr_t _InstructionPointer(CONTEXT const &context)
    {
#if defined(MINIDETOUR_ARCH_X86)
        return context.Eip;
#elif defined(MINIDETOUR_ARCH_X64)
        return context.Rip;
#else
        return context.Pc;
#endif
    }

    // Suspends every other thread. Fails if one of them is inside the code (at its first byte is fine, the instruction
    // there is replaced as a whole). No heap allocation is done while threads are suspended: one of them can hold the
    // heap lock. The threads are counted first, a thread created in the meantime makes this attempt fail.
    bool _TryFreeze(uintptr_t code, size_t size)
    {
        const DWORD access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION;
        size_t threadCount = 0;
        _ForEachProcessThread(
            access,
            [&threadCount](HANDLE)
            {
                ++threadCount;
                return false;
            });
        _Threads.reserve(threadCount + 8);

        const DWORD currentThreadId = GetCurrentThreadId();
        bool inside                 = false;
        bool tooMany                = false;
        _ForEachProcessThread(
            access,
            [&](HANDLE thread)
            {
                if (GetThreadId(thread) == currentThreadId)
                    return false;

                if (_Threads.size() == _Threads.capacity())
                {
                    tooMany = true;
                    return false;
                }

                // A thread that is exiting can't be suspended: it doesn't need to be.
                if (SuspendThread(thread) == (DWORD)-1)
                    return false;

                _Threads.push_back(thread);

                // GetThreadContext also waits for the suspension to be effective.
                CONTEXT context;
                context.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(thread, &context))
                {
                    const uintptr_t ip = _InstructionPointer(context);
                    if (ip > code && ip < code + size)
                        inside = true;
                }

                return true;
            });

        return !inside && !tooMany;
    }

  public:
    ~_OtherThreadsFreezer_t() { Unfreeze(); }

    // Retries a few times when a thread is inside the code: it is most likely only passing through.
    bool Freeze(void *code, size_t size)
    {
        for (int attempt = 0; attempt < 5; ++attempt)
        {
            if (_TryFreeze(reinterpret_cast<uintptr_t>(code), size))
                return true;

            Unfreeze();
            Sleep(1);
        }

        return false;
    }

    // Every thread is resumed before the handles are closed: CloseHandle can be hooked, and its detour must not run
    // while threads are still suspended (one of them could hold a lock it needs).
    void Unfreeze()
    {
        for (auto thread : _Threads)
            ResumeThread(thread);

        for (auto thread : _Threads)
            CloseHandle(thread);

        _Threads.clear();
    }
};

namespace MiniDetour
{
namespace MemoryManipulation
{
namespace Implementation
{
struct ThreadStackInfos_t
{
    DWORD threadId;
    void *threadStack;
};

static DWORD _MemoryProtectRightsToNative(MemoryRights rights)
{
    switch (rights)
    {
        case MemoryRights::mem_r: return PAGE_READONLY;
        case MemoryRights::mem_w: return PAGE_READWRITE;
        case MemoryRights::mem_x: return PAGE_EXECUTE;
        case MemoryRights::mem_rw: return PAGE_READWRITE;
        case MemoryRights::mem_rx: return PAGE_EXECUTE_READ;
        case MemoryRights::mem_wx: return PAGE_EXECUTE_READWRITE;
        case MemoryRights::mem_rwx: return PAGE_EXECUTE_READWRITE;

        default: return PAGE_NOACCESS;
    }
}

static MemoryRights _MemoryNativeToProtectRights(DWORD rights)
{
    // Ignore the modifiers (PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE...).
    switch (rights & 0xFF)
    {
        case PAGE_READONLY: return MemoryRights::mem_r;
        case PAGE_READWRITE: return MemoryRights::mem_rw;
        case PAGE_WRITECOPY: return MemoryRights::mem_rw;
        case PAGE_EXECUTE: return MemoryRights::mem_x;
        case PAGE_EXECUTE_READ: return MemoryRights::mem_rx;
        case PAGE_EXECUTE_READWRITE: return MemoryRights::mem_rwx;
        case PAGE_EXECUTE_WRITECOPY: return MemoryRights::mem_rwx;
        default: return MemoryRights::mem_none;
    }
}

static std::vector<void *> _GetProcessHeapAddresses();
static std::vector<ThreadStackInfos_t> _GetProcessStackAddresses();

// The heaps and thread stacks are only listed when a region that isn't a module must be named: listing the stacks
// opens every thread of the process.
struct _HeapsAndStacks_t
{
    bool Loaded = false;
    std::vector<void *> Heaps;
    std::vector<ThreadStackInfos_t> Stacks;

    void Load()
    {
        if (Loaded)
            return;

        Heaps  = _GetProcessHeapAddresses();
        Stacks = _GetProcessStackAddresses();
        Loaded = true;
    }
};

static void _GetRegionName(std::wstring &wmodule_name, void *address, char *regionName, size_t regionNameSize, _HeapsAndStacks_t &heapsAndStacks)
{
    DWORD wmodule_name_size = 1024;
    HMODULE moduleHandle;

    if (regionNameSize == 0)
        return;

    regionName[0] = '\0';
    // No room for a name (the default RegionInfos_t): nothing to look for.
    if (regionNameSize == 1)
        return;

    if (Globals_t::Instance().ModuleFunctions.GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            static_cast<LPCSTR>(address),
            &moduleHandle) != FALSE &&
        moduleHandle != nullptr)
    {
        while (wmodule_name_size != 0)
        {
            wmodule_name_size = Globals_t::Instance().ModuleFunctions.GetModuleFileNameW(moduleHandle, &wmodule_name[0], static_cast<DWORD>(wmodule_name.size()));
            if (wmodule_name_size == wmodule_name.size())
            {
                if (wmodule_name_size > 0x100000)
                    break;

                wmodule_name.resize(wmodule_name_size * 2);
            }
            else if (wmodule_name_size != 0)
            {
                wmodule_name.resize(wmodule_name_size);

                // Convert, then copy what fits in regionName with its terminating '\0'.
                const int wideLength = static_cast<int>(wmodule_name.length());
                std::string utf8ModuleName(WideCharToMultiByte(CP_UTF8, 0, wmodule_name.c_str(), wideLength, nullptr, 0, nullptr, nullptr), '\0');
                WideCharToMultiByte(CP_UTF8, 0, wmodule_name.c_str(), wideLength, &utf8ModuleName[0], static_cast<int>(utf8ModuleName.length()), nullptr, nullptr);

                size_t copySize = std::min(utf8ModuleName.length(), regionNameSize - 1);
                memcpy(regionName, utf8ModuleName.data(), copySize);
                regionName[copySize] = '\0';

                wmodule_name.resize(wmodule_name.capacity());
                return;
            }
        }
    }

    heapsAndStacks.Load();
    for (auto const &heap : heapsAndStacks.Heaps)
    {
        if (address == heap)
        {
            snprintf(regionName, regionNameSize, "[heap]");
            return;
        }
    }
    for (auto const &stack : heapsAndStacks.Stacks)
    {
        if (address == stack.threadStack)
        {
            snprintf(regionName, regionNameSize, "[thread %lu stack]", stack.threadId);
            return;
        }
    }
}

static std::vector<void *> _GetProcessHeapAddresses()
{
    std::vector<void *> heaps;
    auto numberOfHeaps = GetProcessHeaps(0, nullptr);
    if (numberOfHeaps > 0)
    {
        heaps.resize(numberOfHeaps * 2);
        numberOfHeaps = GetProcessHeaps(static_cast<DWORD>(heaps.size()), heaps.data());
        heaps.resize(std::min<size_t>(numberOfHeaps, heaps.size()));
    }
    return heaps;
}

static std::vector<ThreadStackInfos_t> _GetProcessStackAddresses()
{
    std::vector<ThreadStackInfos_t> stacks;
    _ForEachProcessThread(
        THREAD_QUERY_INFORMATION,
        [&stacks](HANDLE thread)
        {
            THREAD_BASIC_INFORMATION basicInfo;
            if (NtQueryInformationThread(thread, ThreadBasicInformation, &basicInfo, sizeof(THREAD_BASIC_INFORMATION), NULL) >= 0)
            {
                // NtQueryInformationThread can succeed without giving a TebBaseAddress.
                auto *tib = (const NT_TIB *)basicInfo.TebBaseAddress;
                if (tib != nullptr)
                    stacks.emplace_back(ThreadStackInfos_t{GetThreadId(thread), tib->StackLimit}); // The stack grows down: its start is its limit.
            }

            return false;
        });

    return stacks;
}

static size_t _GetRegions(MiniDetourMemoryManipulationRegionInfos_t *regions, size_t regionCount, bool onlyFree)
{
    HANDLE processHandle = GetCurrentProcess();
    LPVOID searchAddress = nullptr;
    MEMORY_BASIC_INFORMATION memoryBasicInformation{};
    size_t writtenRegionCount = 0;
    size_t currentRegionCount = 0;
    std::wstring regionNameBuffer(1024, L'\0');
    _HeapsAndStacks_t heapsAndStacks;

    while (VirtualQueryEx(processHandle, searchAddress, &memoryBasicInformation, sizeof(memoryBasicInformation)) != 0)
    {
        if ((!onlyFree || (onlyFree && memoryBasicInformation.State == MEM_FREE)) && regions != nullptr && writtenRegionCount < regionCount)
        {
            auto &region = *regions;
            if (region.StructSize >= sizeof(region))
            {
                regions              = reinterpret_cast<MiniDetourMemoryManipulationRegionInfos_t *>(reinterpret_cast<uintptr_t>(regions) + regions->StructSize);
                region.Rights        = MemoryRights::mem_unset;
                region.Start         = reinterpret_cast<uintptr_t>(memoryBasicInformation.BaseAddress);
                region.End           = reinterpret_cast<uintptr_t>(memoryBasicInformation.BaseAddress) + memoryBasicInformation.RegionSize;
                region.ModuleName[0] = '\0';

                if (memoryBasicInformation.State != MEM_FREE)
                {
                    region.Rights = _MemoryNativeToProtectRights(memoryBasicInformation.Protect);
                    _GetRegionName(
                        regionNameBuffer,
                        memoryBasicInformation.BaseAddress,
                        region.ModuleName,
                        region.StructSize - (sizeof(region) - sizeof(region.ModuleName)),
                        heapsAndStacks);
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

static size_t _QueryPageSize()
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return sysInfo.dwPageSize;
}

static void GetRegionInfos(void *address, MiniDetourMemoryManipulationRegionInfos_t *regionInfos)
{
    MEMORY_BASIC_INFORMATION infos;
    std::wstring regionNameBuffer;
    _HeapsAndStacks_t heapsAndStacks;

    // Values for an address that can't be queried, replaced below.
    regionInfos->Rights        = MemoryRights::mem_unset;
    regionInfos->Start         = 0;
    regionInfos->End           = 0;
    regionInfos->ModuleName[0] = '\0';
    if (VirtualQuery(address, &infos, sizeof(infos)) != 0)
    {
        // VirtualQuery describes the pages from the one holding the address. The region, as GetAllRegions lists it,
        // starts at the first of the pages with the same state and rights: walk the allocation from its base to it.
        if (infos.State != MEM_FREE)
        {
            MEMORY_BASIC_INFORMATION region;
            for (auto search = reinterpret_cast<uintptr_t>(infos.AllocationBase); VirtualQuery(reinterpret_cast<void *>(search), &region, sizeof(region)) != 0;
                 search      = reinterpret_cast<uintptr_t>(region.BaseAddress) + region.RegionSize)
            {
                if (reinterpret_cast<uintptr_t>(address) < reinterpret_cast<uintptr_t>(region.BaseAddress) + region.RegionSize)
                {
                    infos = region;
                    break;
                }
            }
        }

        regionInfos->Start = reinterpret_cast<uintptr_t>(infos.BaseAddress);
        regionInfos->End   = regionInfos->Start + infos.RegionSize;
        // Free memory has no rights, as in GetAllRegions.
        regionInfos->Rights = infos.State == MEM_FREE ? MemoryRights::mem_unset : _MemoryNativeToProtectRights(infos.Protect);

        // Only allocated when there is room for a name.
        const size_t regionNameSize = regionInfos->StructSize - (sizeof(*regionInfos) - sizeof(regionInfos->ModuleName));
        if (regionNameSize > 1)
            regionNameBuffer.resize(1024, L'\0');

        _GetRegionName(regionNameBuffer, infos.BaseAddress, regionInfos->ModuleName, regionNameSize, heapsAndStacks);
    }
}

inline size_t GetAllRegions(MiniDetourMemoryManipulationRegionInfos_t *regions, size_t regionCount)
{
    return _GetRegions(regions, regionCount, false);
}

inline size_t GetFreeRegions(MiniDetourMemoryManipulationRegionInfos_t *regions, size_t regionCount)
{
    return _GetRegions(regions, regionCount, true);
}

static bool MemoryProtect(void *address, size_t size, MemoryRights rights, MemoryRights *old_rights)
{
    DWORD oldProtect;
    bool res = VirtualProtect(address, size, _MemoryProtectRightsToNative(rights), &oldProtect) != FALSE;

    // oldProtect isn't set when VirtualProtect fails.
    if (old_rights != nullptr)
        *old_rights = res ? _MemoryNativeToProtectRights(oldProtect) : MemoryRights::mem_unset;

    return res;
}

static void MemoryFree(void *address, size_t size)
{
    if (address != nullptr)
        VirtualFree(address, 0, MEM_RELEASE);
}

static inline BOOL MemoryAllocWithProtection(HANDLE hProcess, LPVOID *address, SIZE_T size, MemoryRights rights)
{
    *address = VirtualAllocEx(hProcess, *address, size, MEM_RESERVE | MEM_COMMIT, _MemoryProtectRightsToNative(rights));
    return *address != nullptr;
}

// Allocates at this exact address, fails if it isn't free.
static inline void *_MemoryAllocAt(void *address, size_t size, MemoryRights rights)
{
    // VirtualAlloc treats NULL as "anywhere".
    if (address == nullptr)
        return nullptr;

    void *allocated = address;
    MemoryAllocWithProtection(GetCurrentProcess(), &allocated, size, rights);
    if (allocated != nullptr && allocated != address)
    {
        MemoryFree(allocated, size);
        return nullptr;
    }

    return allocated;
}

static inline void *_MemoryAllocAnywhere(size_t size, MemoryRights rights)
{
    LPVOID address = nullptr;
    MemoryAllocWithProtection(GetCurrentProcess(), &address, size, rights);
    return (void *)address;
}

// The user address space bounds depend on the system and on /LARGEADDRESSAWARE for 32 bits processes.
static inline uintptr_t _QueryMinUserAddress()
{
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    return reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
}

// Memory can be mapped writable and executable at the same time.
static inline bool _QueryWritableExecutableMemory()
{
    return true;
}

// End of the user address space (lpMaximumApplicationAddress is its last byte).
static inline uintptr_t _QueryMaxUserAddress()
{
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    return reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress) + 1;
}

// VirtualAlloc rounds the reserved address down to the allocation granularity (64 KB), not to a page.
static inline size_t _QueryAllocationGranularity()
{
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    return systemInfo.dwAllocationGranularity;
}

static bool SafeMemoryRead(void *address, uint8_t *buffer, size_t size)
{
    auto hProcess   = GetCurrentProcess();
    SIZE_T readSize = 0;

    if (ReadProcessMemory(hProcess, address, buffer, size, &readSize) == FALSE || readSize != size)
        return false;

    return true;
}

static bool SafeMemoryWrite(void *address, const uint8_t *buffer, size_t size)
{
    auto hProcess    = GetCurrentProcess();
    SIZE_T writeSize = 0;

    if (WriteProcessMemory(hProcess, address, buffer, size, &writeSize) == FALSE || writeSize != size)
        return false;

    return true;
}

static int FlushInstructionCache(void *pBase, size_t size)
{
    return ::FlushInstructionCache(GetCurrentProcess(), pBase, size);
}

} // namespace Implementation
} // namespace MemoryManipulation

namespace ModuleManipulation
{
namespace Implementation
{
// Their addresses are asked to the loader when the library starts: see ModuleFunctions_t. Not &GetProcAddress: the
// address of an imported function is the thunk of the image (jmp [import slot]) when it isn't declared dllimport.
static ModuleFunctions_t _QueryModuleFunctions()
{
    HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    ModuleFunctions_t functions;
    functions.GetModuleHandleExA = reinterpret_cast<decltype(functions.GetModuleHandleExA)>(::GetProcAddress(kernel32, "GetModuleHandleExA"));
    functions.GetProcAddress     = reinterpret_cast<decltype(functions.GetProcAddress)>(::GetProcAddress(kernel32, "GetProcAddress"));
    functions.GetModuleFileNameW = reinterpret_cast<decltype(functions.GetModuleFileNameW)>(::GetProcAddress(kernel32, "GetModuleFileNameW"));
    return functions;
}

// RVAs are unsigned 32 bits offsets from the module base: the address must be above it and within 4 GB of it.
static bool _AddressIsRepresentableAsRva(void *moduleBase, void *address)
{
    uintptr_t base = reinterpret_cast<uintptr_t>(moduleBase);
    uintptr_t addr = reinterpret_cast<uintptr_t>(address);

    return addr >= base && (addr - base) <= UINT32_MAX;
}

// Address of a data directory of a loaded PE image, nullptr if it isn't a PE image or has no such directory (RVA of 0).
static void *_GetDataDirectory(void *moduleHandle, DWORD index)
{
    auto imageDosHeader = (PIMAGE_DOS_HEADER)moduleHandle;
    if (imageDosHeader == nullptr || imageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    auto imageNTHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)moduleHandle + imageDosHeader->e_lfanew);
    if (imageNTHeaders->Signature != IMAGE_NT_SIGNATURE || imageNTHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ||
        imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes <= index)
        return nullptr;

    auto const &dataDirectory = imageNTHeaders->OptionalHeader.DataDirectory[index];
    if (dataDirectory.VirtualAddress == 0 || dataDirectory.Size == 0)
        return nullptr;

    return (LPBYTE)moduleHandle + dataDirectory.VirtualAddress;
}

static bool _LoadModuleExportDetails(
    void *moduleHandle, void **moduleBase, PIMAGE_EXPORT_DIRECTORY *imageExportDirectory, PDWORD *functionAddressesRVA, PDWORD *functionNamesRVA, PWORD *functionOrdinal)
{
    *imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)_GetDataDirectory(moduleHandle, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (*imageExportDirectory == nullptr)
        return false;

    *moduleBase           = moduleHandle;
    *functionAddressesRVA = (PDWORD)((LPBYTE)moduleHandle + (*imageExportDirectory)->AddressOfFunctions);
    *functionNamesRVA     = (PDWORD)((LPBYTE)moduleHandle + (*imageExportDirectory)->AddressOfNames);
    *functionOrdinal      = (PWORD)((LPBYTE)moduleHandle + (*imageExportDirectory)->AddressOfNameOrdinals);

    return true;
}

static bool _LoadModuleIATDetails(void *moduleHandle, void **moduleBase, PIMAGE_IMPORT_DESCRIPTOR *imageImportDescriptor)
{
    *imageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)_GetDataDirectory(moduleHandle, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (*imageImportDescriptor == nullptr)
        return false;

    *moduleBase = moduleHandle;
    return true;
}

// The export RVA is unsigned: an address below the module base, or more than 4 GB above it, is reached through a jump.
// The jump is searched from the end of the module image, so it lands above it.
static bool _ReplaceModuleExport(void *moduleBase, PDWORD exportAddress, void *newExportAddress, void **exportCallAddress)
{
    void *target = newExportAddress;
    void *jump   = nullptr;
    if (!_AddressIsRepresentableAsRva(moduleBase, newExportAddress))
    {
        auto imageNTHeaders = (PIMAGE_NT_HEADERS)((char *)moduleBase + ((PIMAGE_DOS_HEADER)moduleBase)->e_lfanew);
        auto moduleEnd      = (void *)((char *)moduleBase + imageNTHeaders->OptionalHeader.SizeOfImage);
        jump                = Globals_t::Instance().Memory.GetFreeJump(moduleEnd, moduleBase, _AddressIsRepresentableAsRva);
        if (jump == nullptr)
            return false;

        if (!_WriteJumpSlot(jump, newExportAddress, _GetCodeMode(jump), _GetCodeMode(newExportAddress)))
        {
            Globals_t::Instance().Memory.FreeJump(jump);
            return false;
        }

        target = jump;
    }

    DWORD previous;
    if (!_ExchangeTableEntry(exportAddress, static_cast<DWORD>((uintptr_t)target - (uintptr_t)moduleBase), &previous))
    {
        if (jump != nullptr)
            Globals_t::Instance().Memory.FreeJump(jump);

        return false;
    }

    *exportCallAddress = (void *)((uintptr_t)moduleBase + previous);
    return true;
}

static inline PDWORD
_GetExportAddress(void *moduleBase, PDWORD functionAddressesRVA, PDWORD functionNamesRVA, PWORD functionOrdinals, DWORD functionNameCount, const char *symbolName)
{
    if (symbolName == nullptr)
        return nullptr;

    for (DWORD j = 0; j < functionNameCount; ++j)
    {
        if (strcmp((const char *)moduleBase + functionNamesRVA[j], symbolName) == 0)
            return functionAddressesRVA + functionOrdinals[j];
    }

    return nullptr;
}

// The import descriptors end with a zeroed one. Characteristics can't be used to detect it: it is the
// OriginalFirstThunk, which is 0 for modules built by old linkers.
static inline bool _IsLastImportDescriptor(PIMAGE_IMPORT_DESCRIPTOR importDescriptor)
{
    return importDescriptor->Name == 0 && importDescriptor->FirstThunk == 0;
}

// Without OriginalFirstThunk, the loaded IAT only holds resolved addresses: the import names are gone.
// The slot is found from its value: boundAddress, or the address the loader resolved for the symbol.
static inline void **_FindBoundIATSlot(void **addressTable, const char *libraryName, const char *symbolName, DWORD ordinal, void *boundAddress)
{
    if (boundAddress == nullptr)
    {
        ModuleFunctions_t const &moduleFunctions = Globals_t::Instance().ModuleFunctions;
        HMODULE library                          = nullptr;
        if (moduleFunctions.GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, libraryName, &library) == FALSE || library == nullptr)
            return nullptr;

        boundAddress = reinterpret_cast<void *>(moduleFunctions.GetProcAddress(library, symbolName != nullptr ? symbolName : MAKEINTRESOURCEA(ordinal)));
        if (boundAddress == nullptr)
            return nullptr;
    }

    for (int i = 0; addressTable[i] != nullptr; ++i)
    {
        if (addressTable[i] == boundAddress)
            return addressTable + i;
    }

    return nullptr;
}

// boundAddress: current value of the slot if known (used only for modules without OriginalFirstThunk).
static inline void **
_GetIATAddress(void *moduleBase, PIMAGE_IMPORT_DESCRIPTOR imageImportDescriptor, const char *moduleName, const char *symbolName, DWORD ordinal, void *boundAddress = nullptr)
{
    void **addressTable         = nullptr;
    PIMAGE_THUNK_DATA thunkData = nullptr;

    // symbolName can be null (import by ordinal), but the module name is required.
    if (moduleName == nullptr)
        return nullptr;

    for (auto *importDescriptor = imageImportDescriptor; !_IsLastImportDescriptor(importDescriptor); ++importDescriptor)
    {
        auto *libraryName = (const char *)((uintptr_t)moduleBase + importDescriptor->Name);
        if (_stricmp(moduleName, libraryName) == 0)
        {
            addressTable = (void **)((uintptr_t)moduleBase + importDescriptor->FirstThunk);
            if (importDescriptor->OriginalFirstThunk == 0)
                return _FindBoundIATSlot(addressTable, libraryName, symbolName, ordinal, boundAddress);

            thunkData = (PIMAGE_THUNK_DATA)((uintptr_t)moduleBase + importDescriptor->OriginalFirstThunk);
            break;
        }
    }

    if (thunkData == nullptr)
        return nullptr;

    for (int i = 0; thunkData[i].u1.AddressOfData != 0; ++i)
    {
        if (thunkData[i].u1.AddressOfData & IMAGE_ORDINAL_FLAG)
        {
            if (symbolName == nullptr && (thunkData[i].u1.Ordinal & (~IMAGE_ORDINAL_FLAG)) == ordinal)
                return addressTable + i;
        }
        else if (symbolName != nullptr && strcmp(((PIMAGE_IMPORT_BY_NAME)((uintptr_t)moduleBase + thunkData[i].u1.AddressOfData))->Name, symbolName) == 0)
        {
            return addressTable + i;
        }
    }

    return nullptr;
}

static size_t GetAllExportedSymbols(void *moduleHandle, ExportDetails_t *exportDetails, size_t exportDetailsCount)
{
    void *moduleBase = nullptr;
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
                exportDetails[result].ExportName = (const char *)moduleBase + functionNamesRVA[j];
                break;
            }
        }

        exportDetails[result].ExportCallAddress = (void *)((uintptr_t)moduleBase + functionAddressesRVA[i]);
        exportDetails[result++].ExportOrdinal   = i + imageExportDirectory->Base;
    }

    return result;
}

static size_t GetAllIATSymbols(void *moduleHandle, IATDetails_t *iatDetails, size_t iatDetailsCount)
{
    void *moduleBase = nullptr;
    PIMAGE_IMPORT_DESCRIPTOR imageImportDescriptor;
    void **addressTable;
    PIMAGE_THUNK_DATA thunkData;
    size_t result = 0;

    if (!_LoadModuleIATDetails(moduleHandle, &moduleBase, &imageImportDescriptor))
        return result;

    if (iatDetails == nullptr)
    {
        for (auto *importDescriptor = imageImportDescriptor; !_IsLastImportDescriptor(importDescriptor); ++importDescriptor)
        {
            // Without OriginalFirstThunk, count the IAT slots.
            auto *slot = (void **)((uintptr_t)moduleBase + importDescriptor->FirstThunk);
            if (importDescriptor->OriginalFirstThunk == 0)
            {
                for (; *slot != nullptr; ++slot)
                    ++result;

                continue;
            }

            for (thunkData = (PIMAGE_THUNK_DATA)((uintptr_t)moduleBase + importDescriptor->OriginalFirstThunk); thunkData->u1.AddressOfData != 0; ++thunkData)
            {
                ++result;
            }
        }

        return result;
    }

    for (auto *importDescriptor = imageImportDescriptor; !_IsLastImportDescriptor(importDescriptor) && result < iatDetailsCount; ++importDescriptor)
    {
        auto *libraryName = (const char *)((uintptr_t)moduleBase + importDescriptor->Name);

        addressTable = (void **)((uintptr_t)moduleBase + importDescriptor->FirstThunk);

        // Without OriginalFirstThunk, only the resolved addresses are known.
        if (importDescriptor->OriginalFirstThunk == 0)
        {
            for (int i = 0; addressTable[i] != nullptr && result < iatDetailsCount; ++i)
            {
                iatDetails[result].ImportOrdinal      = uint32_t(-1);
                iatDetails[result].ImportName         = nullptr;
                iatDetails[result].ImportCallAddress  = addressTable[i];
                iatDetails[result++].ImportModuleName = libraryName;
            }

            continue;
        }

        thunkData = (PIMAGE_THUNK_DATA)((uintptr_t)moduleBase + importDescriptor->OriginalFirstThunk);

        for (int i = 0; thunkData[i].u1.AddressOfData != 0 && result < iatDetailsCount; ++i)
        {
            if (thunkData[i].u1.AddressOfData & IMAGE_ORDINAL_FLAG)
            {
                iatDetails[result].ImportOrdinal = static_cast<uint32_t>(thunkData[i].u1.Ordinal & (~IMAGE_ORDINAL_FLAG));
                iatDetails[result].ImportName    = nullptr;
            }
            else
            {
                iatDetails[result].ImportOrdinal = uint32_t(-1);
                iatDetails[result].ImportName    = ((PIMAGE_IMPORT_BY_NAME)((uintptr_t)moduleBase + thunkData[i].u1.AddressOfData))->Name;
            }

            iatDetails[result].ImportCallAddress  = addressTable[i];
            iatDetails[result++].ImportModuleName = libraryName;
        }
    }

    return result;
}

static size_t ReplaceModuleExports(void *moduleHandle, ExportReplaceParameter_t *exportReplaceDetails, size_t exportReplaceDetailsCount)
{
    void *moduleBase = nullptr;
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
        auto exportAddress =
            _GetExportAddress(moduleBase, functionAddressesRVA, functionNamesRVA, functionOrdinal, imageExportDirectory->NumberOfNames, exportReplaceDetails[i].ExportName);
        if (exportAddress != nullptr && _ReplaceModuleExport(moduleBase, exportAddress, exportReplaceDetails[i].NewExportAddress, &exportReplaceDetails[i].ExportCallAddress))
            ++result;
    }

    return result;
}

static size_t RestoreModuleExports(void *moduleHandle, ExportReplaceParameter_t *exportReplaceDetails, size_t exportReplaceDetailsCount)
{
    void *moduleBase = nullptr;
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
        auto exportAddress =
            _GetExportAddress(moduleBase, functionAddressesRVA, functionNamesRVA, functionOrdinal, imageExportDirectory->NumberOfNames, exportReplaceDetails[i].ExportName);

        // Only this entry fails: the next ones can still be restored.
        DWORD previous;
        if (exportAddress == nullptr ||
            !_ExchangeTableEntry(exportAddress, static_cast<DWORD>((uintptr_t)exportReplaceDetails[i].ExportCallAddress - (uintptr_t)moduleBase), &previous))
            continue;

        exportReplaceDetails[i].NewExportAddress = (void *)((uintptr_t)moduleBase + previous);
        // Does nothing when the export didn't go through a jump.
        Globals_t::Instance().Memory.FreeJump(exportReplaceDetails[i].NewExportAddress);
        ++result;
    }

    return result;
}

// ReplaceModuleIATs writes NewIATAddress and gives the previous value in IATCallAddress, RestoreModuleIATs does the
// opposite: value is the field written, previous the field set.
static size_t _ExchangeModuleIATs(
    void *moduleHandle,
    IATReplaceParameter_t *iatReplaceDetails,
    size_t iatReplaceDetailsCount,
    void *IATReplaceParameter_t::*value,
    void *IATReplaceParameter_t::*previous,
    bool restore)
{
    void *moduleBase = nullptr;
    PIMAGE_IMPORT_DESCRIPTOR imageImportDescriptor;
    size_t result = 0;

    // The slots of modules without OriginalFirstThunk are found from their current value: the replacement on restore.
    std::vector<void *> currentValues(iatReplaceDetailsCount);
    for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
    {
        currentValues[i]               = restore ? iatReplaceDetails[i].*previous : nullptr;
        iatReplaceDetails[i].*previous = nullptr;
    }

    if (!_LoadModuleIATDetails(moduleHandle, &moduleBase, &imageImportDescriptor))
        return result;

    for (size_t i = 0; i < iatReplaceDetailsCount; ++i)
    {
        auto iatAddress =
            _GetIATAddress(moduleBase, imageImportDescriptor, iatReplaceDetails[i].IATModuleName, iatReplaceDetails[i].IATName, iatReplaceDetails[i].IATOrdinal, currentValues[i]);
        if (iatAddress != nullptr && _ExchangeTableEntry(iatAddress, iatReplaceDetails[i].*value, &(iatReplaceDetails[i].*previous)))
            ++result;
    }

    return result;
}

static size_t ReplaceModuleIATs(void *moduleHandle, IATReplaceParameter_t *iatReplaceDetails, size_t iatReplaceDetailsCount)
{
    return _ExchangeModuleIATs(moduleHandle, iatReplaceDetails, iatReplaceDetailsCount, &IATReplaceParameter_t::NewIATAddress, &IATReplaceParameter_t::IATCallAddress, false);
}

static size_t RestoreModuleIATs(void *moduleHandle, IATReplaceParameter_t *iatReplaceDetails, size_t iatReplaceDetailsCount)
{
    return _ExchangeModuleIATs(moduleHandle, iatReplaceDetails, iatReplaceDetailsCount, &IATReplaceParameter_t::IATCallAddress, &IATReplaceParameter_t::NewIATAddress, true);
}

} // namespace Implementation
} // namespace ModuleManipulation
} // namespace MiniDetour

#endif // MINI_DETOUR_WINDOWS_H
