#ifndef MINI_DETOUR_H
#define MINI_DETOUR_H

#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <string>

namespace MemoryManipulation
{
    enum memory_rights
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

    struct region_infos_t
    {
        memory_rights rights;
        uintptr_t start;
        uintptr_t end;
        std::string module_name;

        region_infos_t():
            rights(memory_rights::mem_none), start(0), end(0)
        {}

        region_infos_t(memory_rights rights, uintptr_t start, uintptr_t end, std::string && module_name):
            rights(rights), start(start), end(end), module_name(std::move(module_name))
        {}
    };

    inline void* PageRoundUp(void* _addr, size_t page_size)
    {
        size_t addr = (size_t)_addr;
        return (void*)((addr + (page_size - 1)) & (((size_t)-1) ^ (page_size - 1)));
    }

    inline void* PageRound(void* _addr, size_t page_size)
    {
        size_t addr = (size_t)_addr;
        return (void*)(addr & (((size_t)-1) ^ (page_size - 1)));
    }

    size_t PageSize();
    region_infos_t GetRegionInfos(void* address);
    std::vector<region_infos_t> GetAllRegions();
    std::vector<region_infos_t> GetFreeRegions();
    bool MemoryProtect(void* address, size_t size, memory_rights rights, memory_rights* old_rights = nullptr);
    void MemoryFree(void* address, size_t size);
    void* MemoryAlloc(void* address_hint, size_t size, memory_rights rights);
    bool SafeMemoryRead(void* address, uint8_t* buffer, size_t size);
    bool SafeMemoryWrite(void* address, const uint8_t* buffer, size_t size);
    int FlushInstructionCache(void* address, size_t size);
}
    
namespace mini_detour
{
    class hook
    {
        class HookImpl* _Impl;

    public:
        hook();
        hook(hook const&) = delete;
        hook(hook&&) noexcept;
        ~hook();

        hook& operator=(hook const&) = delete;
        hook& operator=(hook &&) noexcept;

        void RestoreOnDestroy(bool restore);

        bool can_hook(void* func);
        static bool replace_func(void* func, void* hook_func);
        void* hook_func(void* func, void* hook_func);
        void* restore_func();
        void* get_hook_func();
        void* get_original_func();

        // Call the hook func
        template<typename T>
        inline T get_hook_func()
        {
            return reinterpret_cast<T>(get_hook_func());
        }

        // Call the original func
        template<typename T>
        inline T get_original_func()
        {
            return reinterpret_cast<T>(get_original_func());
        }
    };
}

#endif // MINI_DETOUR_H

