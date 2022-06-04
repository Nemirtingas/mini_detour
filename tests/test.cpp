#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#include <mini_detour/mini_detour.h>
#include <iostream>

static void* mem;

const int alloc_size = 50;

#if defined(WIN64) || defined(_WIN64) || defined(__MINGW64__) ||\
    defined(WIN32) || defined(_WIN32) || defined(__MINGW32__)
#define TESTS_OS_WINDOWS
#elif defined(__linux__) || defined(linux)
#define TESTS_OS_LINUX
#elif defined(__APPLE__)
#define TESTS_OS_APPLE
#endif

int main(int argc, char* argv[]) {
    // global setup...

    int result = Catch::Session().run(argc, argv);

    // global clean-up...

    return result;
}

TEST_CASE("Memory allocation", "[mem alloc]") {
    mem = memory_manipulation::memory_alloc((void*)&main, alloc_size, memory_manipulation::memory_rights::mem_none);
    CHECK(mem != nullptr);
}

TEST_CASE("Memory protect", "[memprotect]") {
    memory_manipulation::memory_rights old_rights;

    CHECK(mem != nullptr);

#if defined(TESTS_OS_WINDOWS)
    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_r, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_none);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_w, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_r);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_x, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_rw); // Windows doesn't have a pure w

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_rw, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_x);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_rx, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_rw);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_wx, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_rx);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_rwx, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_rwx); // Windows doesn't have a pure wx

    auto infos = memory_manipulation::get_region_infos(mem);
    CHECK(infos.start != nullptr);
    CHECK(infos.end != nullptr);
    CHECK(infos.rights == memory_manipulation::memory_rights::mem_rwx);
#elif defined(TESTS_OS_LINUX)
    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_r, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_none);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_w, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_r);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_x, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_w);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_rw, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_x);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_rx, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_rw);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_wx, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_rx);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_rwx, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_wx);

    auto infos = memory_manipulation::get_region_infos(mem);
    CHECK(infos.start != nullptr);
    CHECK(infos.end != nullptr);
    CHECK(infos.rights == memory_manipulation::memory_rights::mem_rwx);
#elif defined(TESTS_OS_APPLE)
    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_r, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_none);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_w, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_r);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_x, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_w);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_rw, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_x);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_rx, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_rw);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_wx, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_rx);

    CHECK(memory_manipulation::memory_protect(mem, alloc_size, memory_manipulation::memory_rights::mem_rwx, &old_rights) == true);
    CHECK(old_rights == memory_manipulation::memory_rights::mem_wx);

    auto infos = memory_manipulation::get_region_infos(mem);
    CHECK(infos.start != nullptr);
    CHECK(infos.end != nullptr);
    CHECK(infos.rights == memory_manipulation::memory_rights::mem_rwx);
#endif
}

TEST_CASE("Memory free", "[memfree]") {
    memory_manipulation::memory_free(mem, alloc_size);
}

bool Myputs_called = false;
mini_detour::hook puts_hook;

#ifdef TESTS_OS_WINDOWS
int __cdecl Myputs(const char* str)
#else
int Myputs(const char* str)
#endif
{
    Myputs_called = true;
    return puts_hook.get_original_func<decltype(puts)*>()(str);
};

int do_something(int a, int b)
{
    return a + b;
}

mini_detour::hook do_something_hook;
int Mydo_something(int a, int b)
{
    return a * b;
}

int do_something2(int a, int b)
{
    return a - b;
}

mini_detour::hook do_something_hook2;
int Mydo_something2(int a, int b)
{
    return a / b;
}

TEST_CASE("Hook function", "[Hook function]") {

    puts("Unhooked Test");
    CHECK(Myputs_called == false);

    CHECK(puts_hook.hook_func((void*)&puts, (void*)&Myputs) != nullptr);

    puts_hook.get_original_func<decltype(puts)*>()("Hooked but call original");
    CHECK(Myputs_called == false);
    
    puts("Hook Test");
    CHECK(Myputs_called == true);
    
    CHECK(puts_hook.restore_func() != nullptr);
    Myputs_called = false;
    
    puts("Unhooked Test");
    CHECK(Myputs_called == false);

    CHECK(puts_hook.hook_func((void*)&puts, (void*)&Myputs) != nullptr);
    
    CHECK(do_something(5, 8) == 13);
    CHECK(do_something_hook.hook_func((void*)&do_something, (void*)Mydo_something) != nullptr);
    
    if (do_something_hook.get_original_func<void*>() != nullptr)
    {
        CHECK(do_something_hook.get_original_func<decltype(do_something)*>()(5, 8) == 13);
        CHECK(do_something(5, 8) == 40);
        CHECK(do_something_hook.restore_func() != nullptr);
        CHECK(do_something(5, 8) == 13);
    }

    CHECK(do_something2(8, 4) == 4);
    CHECK(do_something_hook2.hook_func((void*)&do_something2, (void*)Mydo_something2) != nullptr);

    if (do_something_hook2.get_original_func<void*>() != nullptr)
    {
        CHECK(do_something_hook2.get_original_func<decltype(do_something2)*>()(8, 4) == 4);
        CHECK(do_something2(8, 4) == 2);
        CHECK(do_something_hook2.restore_func() != nullptr);
        CHECK(do_something2(8, 4) == 4);
    }
}
