#ifndef MINI_DETOUR_H
#define MINI_DETOUR_H

#include <stddef.h>
#include <stdint.h>

namespace memory_manipulation
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
        void* start;
        void* end;
    };

    inline void* page_round_up(void* _addr, size_t page_size)
    {
        size_t addr = (size_t)_addr;
        return (void*)((addr + (page_size - 1)) & (((size_t)-1) ^ (page_size - 1)));
    }

    inline void* page_round(void* _addr, size_t page_size)
    {
        size_t addr = (size_t)_addr;
        return (void*)(addr & (((size_t)-1) ^ (page_size - 1)));
    }

    size_t page_size();
    region_infos_t get_region_infos(void* address);
    bool memory_protect(void* address, size_t size, memory_rights rights, memory_rights* old_rights = nullptr);
    void memory_free(void* address, size_t size);
    void* memory_alloc(void* address_hint, size_t size, memory_rights rights);
    int flush_instruction_cache(void* address, size_t size);
}
    
namespace mini_detour
{
    class hook
    {
        class HookImpl* _Impl;

    public:
        // Set this to true to restore the original function on hook destruction
        bool restore_on_destroy;

        hook();
        hook(hook const&) = delete;
        hook(hook&&) noexcept;
        ~hook();

        hook& operator=(hook const&) = delete;
        hook& operator=(hook &&) noexcept;

        void reset();
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

