#ifndef MINI_DETOUR_H
#define MINI_DETOUR_H

#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <string>

namespace MiniDetour {
namespace MemoryManipulation {
    enum MemoryRights
    {
        mem_none = 0,
        mem_r    = 1,
        mem_w    = 2,
        mem_x    = 4,
        mem_rw   = mem_r | mem_w,
        mem_rx   = mem_r | mem_x,
        mem_wx   = mem_w | mem_x,
        mem_rwx  = mem_r | mem_w | mem_x,
        mem_unset = 8,
    };

    struct RegionInfos_t
    {
        MemoryRights rights;
        uintptr_t start;
        uintptr_t end;
        std::string module_name;

        RegionInfos_t():
            rights(MemoryRights::mem_none), start(0), end(0)
        {}

        RegionInfos_t(MemoryRights rights, uintptr_t start, uintptr_t end, std::string && module_name):
            rights(rights), start(start), end(end), module_name(std::move(module_name))
        {}

        inline size_t RegionSize() const { return end - start; }
    };

    /// <summary>
    /// Round the address to the upper value aligned with page_size.
    /// If page_size = 0x1000:
    ///   _addr = 0x17ff -> 0x2000
    /// </summary>
    /// <param name="_addr"></param>
    /// <param name="page_size"></param>
    /// <returns></returns>
    inline void* PageRoundUp(void* _addr, size_t page_size)
    {
        uintptr_t addr = (uintptr_t)_addr;
        return (void*)((addr + (page_size - 1)) & (((uintptr_t)-1) ^ (page_size - 1)));
    }

    /// <summary>
    /// Round the address to the upper value aligned with page_size.
    /// If page_size = 0x1000:
    ///   _addr = 0x17ff -> 0x1000
    /// </summary>
    /// <param name="_addr"></param>
    /// <param name="page_size"></param>
    /// <returns></returns>
    inline void* PageRound(void* _addr, size_t page_size)
    {
        uintptr_t addr = (uintptr_t)_addr;
        return (void*)(addr & (((uintptr_t)-1) ^ (page_size - 1)));
    }

    /// <summary>
    /// Return the page size of the current system.
    /// </summary>
    /// <returns></returns>
    size_t PageSize();

    RegionInfos_t GetRegionInfos(void* address);
    std::vector<RegionInfos_t> GetAllRegions();
    std::vector<RegionInfos_t> GetFreeRegions();

    /// <summary>
    /// Changes memory protection. (On Linux and MacOS, address and rights will be aligned to page size, it is required or it will fail)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="size"></param>
    /// <param name="rights"></param>
    /// <param name="old_rights"></param>
    /// <returns></returns>
    bool MemoryProtect(void* address, size_t size, MemoryRights rights, MemoryRights* old_rights = nullptr);
    void MemoryFree(void* address, size_t size);
    void* MemoryAlloc(void* address_hint, size_t size, MemoryRights rights);

    /// <summary>
    /// Safely read memory, it doesn't mean it will always succeed, only that on memory not readable or no allocated, it will not crash your application.
    /// </summary>
    /// <param name="address"></param>
    /// <param name="buffer"></param>
    /// <param name="size"></param>
    /// <returns></returns>
    bool SafeMemoryRead(void* address, uint8_t* buffer, size_t size);

    /// <summary>
    /// Safely write memory, it doesn't mean it will always succeed, only that on memory not writable or no allocated, it will not crash your application.
    /// </summary>
    /// <param name="address"></param>
    /// <param name="buffer"></param>
    /// <param name="size"></param>
    /// <returns></returns>
    bool SafeMemoryWrite(void* address, const uint8_t* buffer, size_t size);

    /// <summary>
    /// Convenient function to write an absolute jump at an address. Pass NULL in address to get the required size of the absolute jump in bytes.
    /// </summary>
    /// <param name="address">Where to write the jump</param>
    /// <param name="destination">Where should to jump to</param>
    /// <returns>The needed size</returns>
    size_t WriteAbsoluteJump(void* address, void* destination);

    /// <summary>
    /// Flushed instruction cache. (only implemented on Windows)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="size"></param>
    /// <returns></returns>
    int FlushInstructionCache(void* address, size_t size);
}//namespace MemoryManipulation
    
namespace ModuleManipulation {
    struct ExportDetails_t
    {
        const char* ExportName;
        uint32_t ExportOrdinal;
        void* ExportCallAddress;
    };

    struct IATDetails_t
    {
        const char* ImportModuleName;
        const char* ImportName;
        uint32_t ImportOrdinal;
        void* ImportCallAddress;
    };

    struct ExportReplaceParameter_t
    {
        /// <summary>
        /// IN: The symbol name
        /// </summary>
        const char* ExportName;
        /// <summary>
        /// ReplaceModuleExports: IN: The new address to redirect to
        /// RestoreModuleExports: OUT: The old symbol address (null if this entry failed)
        /// </summary>
        void* NewExportAddress;
        /// <summary>
        /// ReplaceModuleExports: OUT: The old symbol address (can be used to restore) (null if this entry failed)
        /// RestoreModuleExports: IN: The symbol address to restore
        /// Will be set to null if hook failed.
        /// </summary>
        void* ExportCallAddress;
    };

    struct IATReplaceParameter_t
    {
        /// <summary>
        /// IN: The module where IATName resides (the same IATName could be used in multiple modules)
        /// </summary>
        const char* IATModuleName;
        /// <summary>
        /// IN: The symbol name
        /// </summary>
        const char* IATName;
        /// <summary>
        /// IN: The symbol ordinal (on Windows only?)
        /// </summary>
        uint16_t IATOrdinal;
        /// <summary>
        /// ReplaceModuleIATs: IN: The new address to redirect to
        /// RestoreModuleIATs: OUT: The old symbol address (null if this entry failed)
        /// </summary>
        void* NewIATAddress;
        /// <summary>
        /// ReplaceModuleIATs: OUT: The old symbol address (can be used to restore) (null if this entry failed)
        /// RestoreModuleIATs: IN: The symbol address to restore
        /// Will be set to null if hook failed.
        /// </summary>
        void* IATCallAddress;
    };

    size_t GetAllExportedSymbols(void* moduleHandle, ExportDetails_t* exportDetails, size_t exportDetailsCount);

    size_t GetAllIATSymbols(void* moduleHandle, IATDetails_t* iatDetails, size_t iatDetailsCount);

    /// <summary>
    /// Convenient function that will try to replace the export symbol of a module without writing code into the function.
    /// GetProcAddress and dlsym will return a pointer to your function instead.
    /// </summary>
    /// <param name="moduleHandle"></param>
    /// <param name="exportReplaceDetails"></param>
    /// <param name="exportReplaceDetailsCount"></param>
    /// <returns>Export count replaced</returns>
    size_t ReplaceModuleExports(void* moduleHandle, ExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="moduleHandle"></param>
    /// <param name="exportReplaceDetails"></param>
    /// <param name="exportReplaceDetailsCount"></param>
    /// <returns>Export count restored</returns>
    size_t RestoreModuleExports(void* moduleHandle, ExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount);

    /// <summary>
    /// Convenient function that will try to replace the import symbol of a module without writing code into the function.
    /// </summary>
    /// <param name="moduleHandle"></param>
    /// <param name="iatReplaceDetails"></param>
    /// <param name="iatReplaceDetailsCount"></param>
    /// <returns>IAT count replaced</returns>
    size_t ReplaceModuleIATs(void* moduleHandle, IATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="moduleHandle"></param>
    /// <param name="iatReplaceDetails"></param>
    /// <param name="iatReplaceDetailsCount"></param>
    /// <returns></returns>
    size_t RestoreModuleIATs(void* moduleHandle, IATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount);
}

class Hook_t
{
    class HookImpl* _Impl;

public:
    Hook_t();
    Hook_t(Hook_t const&) = delete;
    Hook_t(Hook_t&&) noexcept;
    ~Hook_t();

    Hook_t& operator=(Hook_t const&) = delete;
    Hook_t& operator=(Hook_t&&) noexcept;

    void RestoreOnDestroy(bool restore);

    bool CanHook(void* func);
    static bool ReplaceFunction(void* functionToReplace, void* newFunction);
    void* HookFunction(void* functionToHook, void* newFunction);
    void* RestoreFunction();
    void* GetHookFunction();
    void* GetOriginalFunction();

    // Call the hook func
    template<typename T>
    inline T GetHookFunction()
    {
        return reinterpret_cast<T>(GetHookFunction());
    }

    // Call the original func
    template<typename T>
    inline T GetOriginalFunction()
    {
        return reinterpret_cast<T>(GetOriginalFunction());
    }
};

}//namespace MiniDetour

#endif // MINI_DETOUR_H

