#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#include <mini_detour/mini_detour.h>
#include <spdlog/spdlog-inl.h>
#include <iostream>

#if defined(WIN64) || defined(_WIN64) || defined(__MINGW64__) ||\
    defined(WIN32) || defined(_WIN32) || defined(__MINGW32__)
#define TESTS_OS_WINDOWS

#define LOAD_LIBRARY(filePath) LoadLibraryA(filePath)
#define GET_LIBRAR_PROC(handle, name) GetProcAddress(handle, name)
#define FREE_LIBRARY(handle) FreeLibrary(handle)

#elif defined(__linux__) || defined(linux)
#include <dl.h>

#define TESTS_OS_LINUX

#define LOAD_LIBRARY(filePath) dlopen(filePath, RTLD_LAZY)
#define GET_LIBRAR_PROC(handle, name) dlsym(handle, name)
#define FREE_LIBRARY(handle) dlclose(handle)

#elif defined(__APPLE__)
#include <dl.h>

#define TESTS_OS_APPLE

#define LOAD_LIBRARY(filePath) dlopen(filePath, RTLD_LAZY)
#define GET_LIBRAR_PROC(handle, name) dlsym(handle, name)
#define FREE_LIBRARY(handle) dlclose(handle)

#endif

#if defined(TESTS_OS_WINDOWS)
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
#elif defined(TESTS_OS_LINUX)
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
#elif defined(TESTS_OS_APPLE)
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
#endif

inline void* relative_addr_to_absolute(void* source_addr, int32_t rel_addr)
{
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(source_addr) + rel_addr + 5);
}

static void _EnterRecursiveThunk(void*& _pCode)
{
    uint8_t* pCode = reinterpret_cast<uint8_t*>(_pCode);
    while (1)
    {
        // If its an imported function.      CALL                JUMP
        if (pCode[0] == 0xFF && (/*pCode[1] == 0x15 ||*/ pCode[1] == 0x25))
        {
            // Get the real imported function address
            pCode = **reinterpret_cast<uint8_t***>(pCode + 2); // 2 opcodes + 4 absolute address ptr
        }
        else if (pCode[0] == 0xe8 || pCode[0] == 0xe9)
        {
            pCode = (uint8_t*)relative_addr_to_absolute(pCode, *(int32_t*)(pCode + 1));
        }
        else
        {
            break;
        }
    }

    _pCode = pCode;
}

int main(int argc, char* argv[]) {
    // global setup...

    int result = Catch::Session().run(argc, argv);

    // global clean-up...

    return result;
}

int MyAdd(int a, int b)
{
    return a - b;
}

TEST_CASE("", "[module_export_hook]") {
    SPDLOG_INFO("Test module export hook");
#if defined(TESTS_OS_WINDOWS)
    auto h = LOAD_LIBRARY("./export_hook_test_library.dll");
    if (h != nullptr && h != INVALID_HANDLE_VALUE)
    {
        int(*libraryAdd)(int a, int b) = nullptr;
        CHECK(MiniDetour::MemoryManipulation::ReplaceModuleExport(h, "add", (void**)&libraryAdd, &MyAdd) == true);
        if (libraryAdd != nullptr)
        {
            auto myAdd = ((decltype(libraryAdd))GetProcAddress(h, "add"));

            CHECK(libraryAdd(5, 3) == 8);
            CHECK(myAdd(5, 3) == 2);

            // Test restore
            CHECK(MiniDetour::MemoryManipulation::RestoreModuleExport(h, "add", libraryAdd) == true);

            myAdd = ((decltype(libraryAdd))GetProcAddress(h, "add"));

            CHECK(libraryAdd(5, 3) == 8);
            CHECK(myAdd(5, 3) == 8);
        }

        FREE_LIBRARY(h);
    }
#else
// Linux (ELF) and MacOS (MachO) not implemented.
    SPDLOG_INFO("Not implemented");
#endif
}

int AbsoluteJumpWriteTest(int x)
{
    return x * 5;
}

TEST_CASE("Test absolute jump write", "[absolute_jump_write]") {
    SPDLOG_INFO("Test absolute jump write");
    auto allocSize = MiniDetour::MemoryManipulation::WriteAbsoluteJump(nullptr, nullptr);
    auto jumpAddress = (int(*)(int))MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, allocSize, MiniDetour::MemoryManipulation::mem_rw);
    CHECK(jumpAddress != nullptr);
    if (jumpAddress != nullptr)
    {
        if (MiniDetour::MemoryManipulation::WriteAbsoluteJump((void*)jumpAddress, (void*)&AbsoluteJumpWriteTest) &&
            MiniDetour::MemoryManipulation::MemoryProtect((void*)jumpAddress, allocSize, MiniDetour::MemoryManipulation::mem_rx))
        {
            auto a1 = jumpAddress(2);
            auto a2 = jumpAddress(3);
            CHECK(a1 == 10);
            CHECK(a2 == 15);
            SPDLOG_INFO("Absolute jump write: {}, {}", a1, a2);
        }

        MiniDetour::MemoryManipulation::MemoryFree((void*)jumpAddress, allocSize);
    }
}

TEST_CASE("Memory mappings", "[vmmap]") {
    SPDLOG_INFO("Memory mappings");
    auto maps = MiniDetour::MemoryManipulation::GetAllRegions();

    char rights_str[5] = { '-', '-', '-', '-', '\0' };

    for (auto const& map : maps)
    {
        if (map.rights != MiniDetour::MemoryManipulation::MemoryRights::mem_unset)
        {
            if (map.rights & MiniDetour::MemoryManipulation::MemoryRights::mem_r)
                rights_str[0] = 'r';
            else
                rights_str[0] = '-';

            if (map.rights & MiniDetour::MemoryManipulation::MemoryRights::mem_w)
                rights_str[1] = 'w';
            else
                rights_str[1] = '-';

            if (map.rights & MiniDetour::MemoryManipulation::MemoryRights::mem_x)
                rights_str[2] = 'x';
            else
                rights_str[2] = '-';

            rights_str[3] = '-';
        }
        else
        {
            rights_str[0] = 'f';
            rights_str[1] = 'r';
            rights_str[2] = 'e';
            rights_str[3] = 'e';
        }

        SPDLOG_INFO("[{:016X}-{:016X}]: [{}] {}", map.start, map.end, rights_str, map.module_name);
    }
}

TEST_CASE("Free memory mappings", "[vmmap]") {
    SPDLOG_INFO("Free memory mappings");
    auto maps = MiniDetour::MemoryManipulation::GetFreeRegions();

    char rights_str[5] = { '-', '-', '-', '-', '\0' };

    for (auto const& map : maps)
    {
        CHECK(map.rights == MiniDetour::MemoryManipulation::MemoryRights::mem_unset);

        rights_str[0] = 'f';
        rights_str[1] = 'r';
        rights_str[2] = 'e';
        rights_str[3] = 'e';

        SPDLOG_INFO("[{:016X}-{:016X}]: [{}] {}", map.start, map.end, rights_str, map.module_name);
    }
}

TEST_CASE("Memory allocation", "[mem alloc]") {
    const int alloc_size = 50;
    void* mem = MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);

    CHECK(mem != nullptr);

    MiniDetour::MemoryManipulation::MemoryFree(mem, alloc_size);
}

#ifndef TESTS_OS_APPLE

TEST_CASE("Memory protect", "[memprotect]") {
    MiniDetour::MemoryManipulation::MemoryRights old_rights;

    const int alloc_size = 50;
    void* mem = MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_none);

    CHECK(mem != nullptr);

#if defined(TESTS_OS_WINDOWS)
    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_r, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_none);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_w, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_r);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_x, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rw); // Windows doesn't have a pure w

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_x);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rw);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_wx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rx);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rwx); // Windows doesn't have a pure wx
#elif defined(TESTS_OS_LINUX)
    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_r, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_none);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_w, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_r);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_x, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_w);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_x);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rw);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_wx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rx);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_wx);
#elif defined(TESTS_OS_APPLE)
    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_r, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_none);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_w, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_r);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_x, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_w);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_x);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rw);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_wx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rx);

    CHECK(MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx, &old_rights) == true);
    CHECK(old_rights == MiniDetour::MemoryManipulation::MemoryRights::mem_wx);
#endif

    auto infos = MiniDetour::MemoryManipulation::GetRegionInfos(mem);
    CHECK(infos.start != 0);
    CHECK(infos.end != 0);
    CHECK(infos.rights == MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);

    MiniDetour::MemoryManipulation::MemoryFree(mem, alloc_size);
}

TEST_CASE("Memory read/write", "[memread/memwrite]")
{
    const int alloc_size = 50;
    void* mem = MiniDetour::MemoryManipulation::MemoryAlloc(nullptr, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_r);
    uint8_t buffer[30];

    CHECK(mem != nullptr);

    CHECK(MiniDetour::MemoryManipulation::SafeMemoryWrite(mem, (const uint8_t*)"0123456789ABCDEFabcdef", 22) == false);

    MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_rw);
    CHECK(MiniDetour::MemoryManipulation::SafeMemoryWrite(mem, (const uint8_t*)"0123456789ABCDEFabcdef", 22) == true);

    MiniDetour::MemoryManipulation::MemoryProtect(mem, alloc_size, MiniDetour::MemoryManipulation::MemoryRights::mem_r);
    CHECK(MiniDetour::MemoryManipulation::SafeMemoryRead(mem, buffer, 22) == true);

    CHECK(memcmp(buffer, "0123456789ABCDEFabcdef", 22) == 0);

    MiniDetour::MemoryManipulation::MemoryFree(mem, alloc_size);

    memset(buffer, 0, 30);
    CHECK(MiniDetour::MemoryManipulation::SafeMemoryRead(mem, buffer, 30) == false);
    CHECK(memcmp(buffer, "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0", 30) == 0);
}


bool Myputs_called = false;
MiniDetour::Hook_t puts_hook;

#ifdef TESTS_OS_WINDOWS
int __cdecl Myputs(const char* str)
#else
int Myputs(const char* str)
#endif
{
    Myputs_called = true;
    return puts_hook.GetOriginalFunction<decltype(puts)*>()(str);
};

int do_something(int a, int b)
{
    return a + b;
}

MiniDetour::Hook_t do_something_hook;
int Mydo_something(int a, int b)
{
    return a * b;
}

int do_something2(int a, int b)
{
    return a - b;
}

MiniDetour::Hook_t do_something_hook2;
int Mydo_something2(int a, int b)
{
    return a / b;
}

TEST_CASE("Hook function", "[Hook function]") {

    puts("Unhooked Test");
    CHECK(Myputs_called == false);

    SPDLOG_INFO("Hooking puts...");
    CHECK(puts_hook.HookFunction((void*)&puts, (void*)&Myputs) != nullptr);

    SPDLOG_INFO("Calling original puts...");
	if(puts_hook.GetOriginalFunction<decltype(puts)*>() != nullptr)
	{
		puts_hook.GetOriginalFunction<decltype(puts)*>()("Hooked but call original");
	}
    CHECK(Myputs_called == false);
    
    SPDLOG_INFO("Calling puts...");
    puts("Hook Test");
    CHECK(Myputs_called == true);
    
    SPDLOG_INFO("Restoring puts...");
    CHECK(puts_hook.RestoreFunction() != nullptr);
    Myputs_called = false;
    
    SPDLOG_INFO("Calling puts...");
    puts("Unhooked Test");
    CHECK(Myputs_called == false);
    
    SPDLOG_INFO("Calling do_something...");
    CHECK(do_something(5, 8) == 13);

    SPDLOG_INFO("Hooking do_something...");
    CHECK(do_something_hook.HookFunction((void*)&do_something, (void*)Mydo_something) != nullptr);
    
    if (do_something_hook.GetOriginalFunction<void*>() != nullptr)
    {
        int r;
        SPDLOG_INFO("Calling original do_something...");
        r = do_something_hook.GetOriginalFunction<decltype(do_something)*>()(5, 8);
        CHECK(r == 13);

        SPDLOG_INFO("Calling do_something...");
        r = do_something(5, 8);
        CHECK(r == 40);

        SPDLOG_INFO("Restoring do_something...");
        CHECK(do_something_hook.RestoreFunction() != nullptr);

        SPDLOG_INFO("Calling do_something...");
        r = do_something(5, 8);
        CHECK(r == 13);
    }

    CHECK(do_something2(8, 4) == 4);
    CHECK(do_something_hook2.HookFunction((void*)&do_something2, (void*)Mydo_something2) != nullptr);

    if (do_something_hook2.GetOriginalFunction<void*>() != nullptr)
    {
        int r;

        SPDLOG_INFO("Calling original do_something2...");
        r = do_something_hook2.GetOriginalFunction<decltype(do_something2)*>()(8, 4);
        CHECK(r == 4);

        SPDLOG_INFO("Calling do_something2...");
        r = do_something2(8, 4);
        CHECK(r == 2);

        SPDLOG_INFO("Restoring do_something2...");
        CHECK(do_something_hook2.RestoreFunction() != nullptr);

        SPDLOG_INFO("Calling do_something2...");
        r = do_something2(8, 4);
        CHECK(r == 4);
    }
}

#if defined(MINIDETOUR_ARCH_X86) || defined(MINIDETOUR_ARCH_X64)
auto test_func = (void(*)())((void*)"\x50\xE8\x00\x00\x00\x00\x58\xc3");

void(*bkp)();

void nothing()
{
    SPDLOG_INFO("Called nothing.");
}

void my_test_func()
{
    SPDLOG_INFO("Called my_test_func");
    bkp();
}

TEST_CASE("Hook small function with call", "[Hook function]") {

    MiniDetour::Hook_t test_hook;

    MiniDetour::MemoryManipulation::MemoryProtect((void*)test_func, 8, MiniDetour::MemoryManipulation::MemoryRights::mem_rwx);
    void* nothing_addr = (void*)nothing;

    _EnterRecursiveThunk(nothing_addr);

    int32_t jump_addr = reinterpret_cast<uint8_t*>(nothing_addr) - (reinterpret_cast<uint8_t*>(test_func) + 1 + 5);
    *reinterpret_cast<int32_t*>(reinterpret_cast<uintptr_t>(test_func) + 2) = jump_addr;

    SPDLOG_INFO("Calling test_func");
    test_func();

    (void*&)bkp = test_hook.HookFunction((void*)test_func, (void*)my_test_func);

    SPDLOG_INFO("Calling test_func");
    test_func();
}
#endif

#endif//TESTS_OS_APPLE