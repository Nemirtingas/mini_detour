#ifndef MINI_DETOUR_H
#define MINI_DETOUR_H

#include <stddef.h>
#include <stdint.h>

#if defined(WIN64) || defined(_WIN64) || defined(__MINGW64__) || defined(WIN32) || defined(_WIN32) || defined(__MINGW32__)
    #define MINIDETOUR_OS_WINDOWS

    #if defined(_M_IX86)
        #define MINIDETOUR_ARCH_X86
    #elif defined(_M_AMD64)
        #define MINIDETOUR_ARCH_X64
    #elif defined(_M_ARM)
        #define MINIDETOUR_ARCH_ARM
    #elif defined(_M_ARM64)
        #define MINIDETOUR_ARCH_ARM64
    #else
        #error "Unhandled arch"
    #endif
#elif defined(__linux__) || defined(linux)
    #define MINIDETOUR_OS_LINUX

    #if defined(__i386__) || defined(__i386) || defined(i386)
        #define MINIDETOUR_ARCH_X86
    #elif defined(__x86_64__) || defined(__x86_64) || defined(__amd64) || defined(__amd64__)
        #define MINIDETOUR_ARCH_X64
    #elif defined(__arm__)
        #define MINIDETOUR_ARCH_ARM
    #elif defined(__aarch64__)
        #define MINIDETOUR_ARCH_ARM64
    #else
        #error "Unhandled arch"
    #endif
#elif defined(__APPLE__)
    #define MINIDETOUR_OS_APPLE

    #if defined(__i386__) || defined(__i386) || defined(i386)
        #define MINIDETOUR_ARCH_X86
    #elif defined(__x86_64__) || defined(__x86_64) || defined(__amd64) || defined(__amd64__)
        #define MINIDETOUR_ARCH_X64
    #elif defined(__arm__)
        #define MINIDETOUR_ARCH_ARM
    #elif defined(__aarch64__)
        #define MINIDETOUR_ARCH_ARM64
    #else
        #error "Unhandled arch"
    #endif
#else
    #error "Unknown OS"
#endif

#ifdef __cplusplus
    #define MINIDETOUR_EXTERN_NONE
    #define MINIDETOUR_EXTERN_C   extern "C"
    #define MINIDETOUR_EXTERN_CXX extern
    #define MINIDETOUR_NAMESPACE_BEGIN(name) namespace name {
    #define MINIDETOUR_NAMESPACE_END(name) }
#else
    #define MINIDETOUR_EXTERN_NONE
    #define MINIDETOUR_EXTERN_C   extern
    #define MINIDETOUR_EXTERN_CXX #error "No C++ export in C"
    #define MINIDETOUR_NAMESPACE_BEGIN(name)
    #define MINIDETOUR_NAMESPACE_END(name)
#endif

#if defined(MINIDETOUR_OS_WINDOWS)
    #define MINIDETOUR_CALL_DEFAULT 
    #define MINIDETOUR_CALL_STD     __stdcall
    #define MINIDETOUR_CALL_CDECL   __cdecl
    #define MINIDETOUR_CALL_FAST    __fastcall
    #define MINIDETOUR_CALL_THIS    __thiscall

    #define MINIDETOUR_MODE_DEFAULT
    #define MINIDETOUR_MODE_EXPORT  __declspec(dllexport)
    #define MINIDETOUR_MODE_IMPORT  __declspec(dllimport)
    #define MINIDETOUR_MODE_HIDDEN 

    #define MINIDETOUR_HIDE_CLASS(keyword)                                         MINIDETOUR_EXTERN_NONE MINIDETOUR_MODE_HIDDEN keyword
    #define MINIDETOUR_HIDE_API(return_type, call_convention)                      MINIDETOUR_EXTERN_NONE MINIDETOUR_MODE_HIDDEN return_type call_convention
    #define MINIDETOUR_EXPORT_API(extern_type, return_type, mode, call_convention) extern_type        mode               return_type call_convention
#elif defined(MINIDETOUR_OS_LINUX) || defined(MINIDETOUR_OS_APPLE)
    #define MINIDETOUR_CALL_DEFAULT 
    #define MINIDETOUR_CALL_STD     __attribute__((stdcall))
    #define MINIDETOUR_CALL_CDECL   __attribute__((cdecl))
    #define MINIDETOUR_CALL_FAST    __attribute__((fastcall))
    #define MINIDETOUR_CALL_THIS    __attribute__((thiscall))

    #define MINIDETOUR_MODE_DEFAULT
    #define MINIDETOUR_MODE_EXPORT  __attribute__((visibility("default")))
    #define MINIDETOUR_MODE_IMPORT  __attribute__((visibility("default")))
    #define MINIDETOUR_MODE_HIDDEN  __attribute__((visibility("hidden")))

    #define MINIDETOUR_HIDE_CLASS(keyword)                                         MINIDETOUR_EXTERN_NONE keyword     MINIDETOUR_MODE_HIDDEN
    #define MINIDETOUR_HIDE_API(return_type, call_convention)                      MINIDETOUR_EXTERN_NONE MINIDETOUR_MODE_HIDDEN return_type call_convention
    #define MINIDETOUR_EXPORT_API(extern_type, return_type, mode, call_convention) extern_type        mode               return_type call_convention
#endif

#ifdef MINIDETOUR_SHARED
    #ifdef MINIDETOUR_BUILD
        #define MINIDETOUR_EXPORT(return_type) MINIDETOUR_EXPORT_API(MINIDETOUR_EXTERN_C, return_type, MINIDETOUR_MODE_EXPORT, MINIDETOUR_CALL_DEFAULT)
        #define MINIDETOUR_CXX_EXPORT(return_type) MINIDETOUR_EXPORT_API(MINIDETOUR_EXTERN_CXX, return_type, MINIDETOUR_MODE_EXPORT, MINIDETOUR_CALL_DEFAULT)
    #else
        #define MINIDETOUR_EXPORT(return_type) MINIDETOUR_EXPORT_API(MINIDETOUR_EXTERN_C, return_type, MINIDETOUR_MODE_IMPORT, MINIDETOUR_CALL_DEFAULT)
        #define MINIDETOUR_CXX_EXPORT(return_type) MINIDETOUR_EXPORT_API(MINIDETOUR_EXTERN_CXX, return_type, MINIDETOUR_MODE_IMPORT, MINIDETOUR_CALL_DEFAULT)
    #endif
#else
    #define MINIDETOUR_EXPORT(return_type) MINIDETOUR_EXPORT_API(MINIDETOUR_EXTERN_C, return_type, MINIDETOUR_MODE_DEFAULT, MINIDETOUR_CALL_DEFAULT)
    #define MINIDETOUR_CXX_EXPORT(return_type) MINIDETOUR_EXPORT_API(MINIDETOUR_EXTERN_CXX, return_type, MINIDETOUR_MODE_DEFAULT, MINIDETOUR_CALL_DEFAULT)
#endif

enum MiniDetourMemoryManipulationMemoryRights
{
    mem_none = 0,
    mem_r = 1,
    mem_w = 2,
    mem_x = 4,
    mem_rw = mem_r | mem_w,
    mem_rx = mem_r | mem_x,
    mem_wx = mem_w | mem_x,
    mem_rwx = mem_r | mem_w | mem_x,
    mem_unset = 8,
};

struct MiniDetourModuleManipulationExportDetails_t
{
    const char* ExportName;
    uint32_t ExportOrdinal;
    void* ExportCallAddress;
};

struct MiniDetourModuleManipulationIATDetails_t
{
    const char* ImportModuleName;
    const char* ImportName;
    uint32_t ImportOrdinal;
    void* ImportCallAddress;
};

struct MiniDetourModuleManipulationExportReplaceParameter_t
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

struct MiniDetourModuleManipulationIATReplaceParameter_t
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

/// <summary>
/// Round the address to the upper value aligned with page_size.
/// If page_size = 0x1000:
///   _addr = 0x17ff -> 0x2000
/// </summary>
/// <param name="_addr"></param>
/// <param name="page_size"></param>
/// <returns></returns>
MINIDETOUR_EXPORT(void*) MiniDetourUtilsPageRoundUp(void* _addr, size_t page_size);

/// <summary>
/// Round the address to the upper value aligned with page_size.
/// If page_size = 0x1000:
///   _addr = 0x17ff -> 0x1000
/// </summary>
/// <param name="_addr"></param>
/// <param name="page_size"></param>
/// <returns></returns>
MINIDETOUR_EXPORT(void*) MiniDetourUtilsPageRound(void* _addr, size_t page_size);

/// <summary>
/// Return the page size of the current system.
/// </summary>
/// <returns></returns>
MINIDETOUR_EXPORT(size_t) MiniDetourUtilsPageSize();

// MiniDetour MemoryManipulation C functions

/// <summary>
/// Changes memory protection. (On Linux and MacOS, address and rights will be aligned to page size, it is required or it will fail)
/// </summary>
/// <param name="address"></param>
/// <param name="size"></param>
/// <param name="rights"></param>
/// <param name="old_rights"></param>
/// <returns></returns>
MINIDETOUR_EXPORT(bool) MiniDetourMemoryManipulationMemoryProtect(void* address, size_t size, MiniDetourMemoryManipulationMemoryRights rights, MiniDetourMemoryManipulationMemoryRights* old_rights /* = NULL */);
MINIDETOUR_EXPORT(void) MiniDetourMemoryManipulationMemoryFree(void* address, size_t size);
MINIDETOUR_EXPORT(void*) MiniDetourMemoryManipulationMemoryAlloc(void* address_hint, size_t size, MiniDetourMemoryManipulationMemoryRights rights);

/// <summary>
/// Safely read memory, it doesn't mean it will always succeed, only that on memory not readable or no allocated, it will not crash your application.
/// </summary>
/// <param name="address"></param>
/// <param name="buffer"></param>
/// <param name="size"></param>
/// <returns></returns>
MINIDETOUR_EXPORT(bool) MiniDetourMemoryManipulationSafeMemoryRead(void* address, uint8_t* buffer, size_t size);

/// <summary>
/// Safely write memory, it doesn't mean it will always succeed, only that on memory not writable or no allocated, it will not crash your application.
/// </summary>
/// <param name="address"></param>
/// <param name="buffer"></param>
/// <param name="size"></param>
/// <returns></returns>
MINIDETOUR_EXPORT(bool) MiniDetourMemoryManipulationSafeMemoryWrite(void* address, const uint8_t* buffer, size_t size);

/// <summary>
/// Convenient function to write an absolute jump at an address. Pass NULL in address to get the required size of the absolute jump in bytes.
/// </summary>
/// <param name="address">Where to write the jump</param>
/// <param name="destination">Where should to jump to</param>
/// <returns>The needed size</returns>
MINIDETOUR_EXPORT(size_t) MiniDetourMemoryManipulationWriteAbsoluteJump(void* address, void* destination);

/// <summary>
/// Flush the instruction cache. (only implemented on Windows)
/// </summary>
/// <param name="address"></param>
/// <param name="size"></param>
/// <returns></returns>
MINIDETOUR_EXPORT(int) MiniDetourMemoryManipulationFlushInstructionCache(void* address, size_t size);

// MiniDetour ModuleManipulation C functions
MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationGetAllExportedSymbols(void* moduleHandle, MiniDetourModuleManipulationExportDetails_t* exportDetails, size_t exportDetailsCount);

MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationGetAllIATSymbols(void* moduleHandle, MiniDetourModuleManipulationIATDetails_t* iatDetails, size_t iatDetailsCount);

/// <summary>
/// Convenient function that will try to replace the export symbol of a module without writing code into the function.
/// GetProcAddress and dlsym will return a pointer to your function instead.
/// </summary>
/// <param name="moduleHandle"></param>
/// <param name="exportReplaceDetails"></param>
/// <param name="exportReplaceDetailsCount"></param>
/// <returns>Export count replaced</returns>
MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationReplaceModuleExports(void* moduleHandle, MiniDetourModuleManipulationExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount);

/// <summary>
/// 
/// </summary>
/// <param name="moduleHandle"></param>
/// <param name="exportReplaceDetails"></param>
/// <param name="exportReplaceDetailsCount"></param>
/// <returns>Export count restored</returns>
MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationRestoreModuleExports(void* moduleHandle, MiniDetourModuleManipulationExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount);

/// <summary>
/// Convenient function that will try to replace the import symbol of a module without writing code into the function.
/// </summary>
/// <param name="moduleHandle"></param>
/// <param name="iatReplaceDetails"></param>
/// <param name="iatReplaceDetailsCount"></param>
/// <returns>IAT count replaced</returns>
MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationReplaceModuleIATs(void* moduleHandle, MiniDetourModuleManipulationIATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount);

/// <summary>
/// 
/// </summary>
/// <param name="moduleHandle"></param>
/// <param name="iatReplaceDetails"></param>
/// <param name="iatReplaceDetailsCount"></param>
/// <returns></returns>
MINIDETOUR_EXPORT(size_t) MiniDetourModuleManipulationRestoreModuleIATs(void* moduleHandle, MiniDetourModuleManipulationIATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount);

// MiniDetour Hook_t class C functions

typedef struct _minidetour_hook_handle_t* minidetour_hook_handle_t;

MINIDETOUR_EXPORT(minidetour_hook_handle_t) MiniDetourHookTAlloc();
MINIDETOUR_EXPORT(void) MiniDetourHookTFree(minidetour_hook_handle_t handle);

MINIDETOUR_EXPORT(void) MiniDetourHookTRestoreOnDestroy(minidetour_hook_handle_t handle, bool restore);
MINIDETOUR_EXPORT(bool) MiniDetourHookTCanHook(minidetour_hook_handle_t handle, void* function);
MINIDETOUR_EXPORT(void*) MiniDetourHookTHookFunction(minidetour_hook_handle_t handle, void* function_to_hook, void* new_function);
MINIDETOUR_EXPORT(void*) MiniDetourHookTRestoreFunction(minidetour_hook_handle_t handle);
MINIDETOUR_EXPORT(void*) MiniDetourHookTGetHookFunction(minidetour_hook_handle_t handle);
MINIDETOUR_EXPORT(void*) MiniDetourHookTGetOriginalFunction(minidetour_hook_handle_t handle);

MINIDETOUR_EXPORT(bool) MiniDetourHookTReplaceFunction(void* function_to_replace, void* new_function);

#ifdef __cplusplus

#include <vector>
#include <string>

namespace MiniDetour {
namespace MemoryManipulation {
    using MemoryRights = MiniDetourMemoryManipulationMemoryRights;

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

    inline void* PageRoundUp(void* _addr, size_t page_size)
    {
        return MiniDetourUtilsPageRoundUp(_addr, page_size);
    }

    inline void* PageRound(void* _addr, size_t page_size)
    {
        return MiniDetourUtilsPageRound(_addr, page_size);
    }

    inline size_t PageSize()
    {
        return MiniDetourUtilsPageSize();
    }

    // Do not use until refactored!
    MINIDETOUR_CXX_EXPORT(RegionInfos_t) GetRegionInfos(void* address);
    MINIDETOUR_CXX_EXPORT(std::vector<RegionInfos_t>) GetAllRegions();
    MINIDETOUR_CXX_EXPORT(std::vector<RegionInfos_t>) GetFreeRegions();

    inline bool MemoryProtect(void* address, size_t size, MemoryRights rights, MemoryRights* old_rights = nullptr)
    {
        return MiniDetourMemoryManipulationMemoryProtect(address, size, rights, old_rights);
    }

    inline void MemoryFree(void* address, size_t size)
    {
        return MiniDetourMemoryManipulationMemoryFree(address, size);
    }

    inline void* MemoryAlloc(void* address_hint, size_t size, MemoryRights rights)
    {
        return MiniDetourMemoryManipulationMemoryAlloc(address_hint, size, rights);
    }

    inline bool SafeMemoryRead(void* address, uint8_t* buffer, size_t size)
    {
        return MiniDetourMemoryManipulationSafeMemoryRead(address, buffer, size);
    }

    inline bool SafeMemoryWrite(void* address, const uint8_t* buffer, size_t size)
    {
        return MiniDetourMemoryManipulationSafeMemoryWrite(address, buffer, size);
    }

    inline size_t WriteAbsoluteJump(void* address, void* destination)
    {
        return MiniDetourMemoryManipulationWriteAbsoluteJump(address, destination);
    }

    inline int FlushInstructionCache(void* address, size_t size)
    {
        return MiniDetourMemoryManipulationFlushInstructionCache(address, size);
    }
}//namespace MemoryManipulation
    
namespace ModuleManipulation {
    using ExportDetails_t = MiniDetourModuleManipulationExportDetails_t;
    using IATDetails_t = MiniDetourModuleManipulationIATDetails_t;
    using ExportReplaceParameter_t = MiniDetourModuleManipulationExportReplaceParameter_t;
    using IATReplaceParameter_t = MiniDetourModuleManipulationIATReplaceParameter_t;

    inline size_t GetAllExportedSymbols(void* moduleHandle, ExportDetails_t* exportDetails, size_t exportDetailsCount)
    {
        return MiniDetourModuleManipulationGetAllExportedSymbols(moduleHandle, exportDetails, exportDetailsCount);
    }

    inline size_t GetAllIATSymbols(void* moduleHandle, IATDetails_t* iatDetails, size_t iatDetailsCount)
    {
        return MiniDetourModuleManipulationGetAllIATSymbols(moduleHandle, iatDetails, iatDetailsCount);
    }

    inline size_t ReplaceModuleExports(void* moduleHandle, ExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount)
    {
        return MiniDetourModuleManipulationReplaceModuleExports(moduleHandle, exportReplaceDetails, exportReplaceDetailsCount);
    }

    inline size_t RestoreModuleExports(void* moduleHandle, ExportReplaceParameter_t* exportReplaceDetails, size_t exportReplaceDetailsCount)
    {
        return MiniDetourModuleManipulationRestoreModuleExports(moduleHandle, exportReplaceDetails, exportReplaceDetailsCount);
    }

    inline size_t ReplaceModuleIATs(void* moduleHandle, IATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount)
    {
        return MiniDetourModuleManipulationReplaceModuleIATs(moduleHandle, iatReplaceDetails, iatReplaceDetailsCount);
    }

    inline size_t RestoreModuleIATs(void* moduleHandle, IATReplaceParameter_t* iatReplaceDetails, size_t iatReplaceDetailsCount)
    {
        return MiniDetourModuleManipulationRestoreModuleIATs(moduleHandle, iatReplaceDetails, iatReplaceDetailsCount);
    }
}

class Hook_t
{
    minidetour_hook_handle_t _hookHandle;

public:
    inline Hook_t():
        _hookHandle(MiniDetourHookTAlloc())
    {
    }

    Hook_t(Hook_t const&) = delete;

    inline Hook_t(Hook_t&& other) noexcept
    {
        auto hookHandle = other._hookHandle;
        other._hookHandle = nullptr;
        _hookHandle = hookHandle;
    }

    inline ~Hook_t()
    {
        MiniDetourHookTFree(_hookHandle);
        _hookHandle = nullptr;
    }

    Hook_t& operator=(Hook_t const&) = delete;

    inline Hook_t& operator=(Hook_t&& other) noexcept
    {
        auto hookHandle = other._hookHandle;
        other._hookHandle = nullptr;
        _hookHandle = hookHandle;
        return *this;
    }

    inline void RestoreOnDestroy(bool restore)
    {
        MiniDetourHookTRestoreOnDestroy(_hookHandle, restore);
    }

    inline bool CanHook(void* function)
    {
        return MiniDetourHookTCanHook(_hookHandle, function);
    }

    static bool ReplaceFunction(void* functionToReplace, void* newFunction)
    {
        return MiniDetourHookTReplaceFunction(functionToReplace, newFunction);
    }

    inline void* HookFunction(void* functionToHook, void* newFunction)
    {
        return MiniDetourHookTHookFunction(_hookHandle, functionToHook, newFunction);
    }

    inline void* RestoreFunction()
    {
        return MiniDetourHookTRestoreFunction(_hookHandle);
    }

    inline void* GetHookFunction()
    {
        return MiniDetourHookTGetHookFunction(_hookHandle);
    }

    inline void* GetOriginalFunction()
    {
        return MiniDetourHookTGetOriginalFunction(_hookHandle);
    }

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

#endif

#endif // MINI_DETOUR_H