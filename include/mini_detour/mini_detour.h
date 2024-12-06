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
    /// <returns></returns>
    int WriteAbsoluteJump(void* address, void* destination);

    /// <summary>
    /// Flushed instruction cache. (only implemented on Windows)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="size"></param>
    /// <returns></returns>
    int FlushInstructionCache(void* address, size_t size);
}//namespace MemoryManipulation
    
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

