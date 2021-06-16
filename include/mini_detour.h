#ifndef MINI_DETOUR_H
#define MINI_DETOUR_H

#include <cstddef>
#include <cstdint>

struct abs_jump_t;
struct rel_jump_t;

namespace mini_detour
{
    namespace memory_manipulation
    {
        enum memory_protect_rights
        {
            mem_r,
            mem_w,
            mem_x,
            mem_rw,
            mem_rx,
            mem_rwx
        };
        
        inline size_t page_align(size_t size, size_t page_size)
        {
            return (size + (page_size - 1)) & (((size_t)-1) ^ (page_size - 1));
        }

        inline void* page_addr(void* addr, size_t page_size)
        {
            return reinterpret_cast<void*>(reinterpret_cast<size_t>(addr)& (((size_t)-1) ^ (page_size - 1)));
        }

        size_t page_size();
        bool memory_protect(void* addr, size_t size, memory_protect_rights rights);
        void memory_free(void* mem_addr, size_t size);
        void* memory_alloc(void* address_hint, size_t size, memory_protect_rights rights);
        int flush_instruction_cache(void* pBase, size_t size);
    }
    
    class hook
    {
        void* orignal_func_address;
        // Where the original bytes were modified for hook
        void* restore_address;
        uint8_t saved_code_size;
        // Saved code to restore
        uint8_t* saved_code;
        // Where the original relocation is, to call the original function
        // The content is the saved code + abs jump to original code
        void* original_trampoline_address;
        // The hook address
        void* detour_func;
        // Optional, if we have space for only a relative jump, we need a trampoline
        abs_jump_t* trampoline_address;

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

        // Call the hook func
        template<typename T>
        inline T get_hook_func()
        {
            return reinterpret_cast<T>(detour_func);
        }

        // Call the original func
        template<typename T>
        inline T get_original_func()
        {
            return reinterpret_cast<T>(original_trampoline_address);
        }
    };
}

#endif // MINI_DETOUR_H

