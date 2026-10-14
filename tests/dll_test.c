#if defined(WIN64) || defined(_WIN64) || defined(__MINGW64__) || defined(WIN32) || defined(_WIN32) || defined(__MINGW32__)
#define TESTS_OS_WINDOWS
#define EXPORT_SYMBOL __declspec(dllexport)
#elif defined(__linux__) || defined(linux)
#define TESTS_OS_LINUX
#define EXPORT_SYMBOL __attribute__((visibility("default")))
#elif defined(__APPLE__)
#define TESTS_OS_APPLE
#define EXPORT_SYMBOL __attribute__((visibility("default")))
#endif

#include <stdio.h>

EXPORT_SYMBOL int add(int a, int b)
{
    return a + b;
}

#if defined(TESTS_OS_LINUX)
EXPORT_SYMBOL int add_alias(int a, int b) __attribute__((alias("add")));
#elif defined(_MSC_VER)
#if defined(_M_IX86)
#pragma comment(linker, "/export:add_alias=_add")
#else
#pragma comment(linker, "/export:add_alias=add")
#endif
#endif

EXPORT_SYMBOL int some_integer = 0;

EXPORT_SYMBOL void iat_puts()
{
    puts("Hi");
}
