#if defined(WIN64) || defined(_WIN64) || defined(__MINGW64__) ||\
    defined(WIN32) || defined(_WIN32) || defined(__MINGW32__)
#define TESTS_OS_WINDOWS
#define EXPORT_SYMBOL __declspec(dllexport)
#elif defined(__linux__) || defined(linux)
#define TESTS_OS_LINUX
#define EXPORT_SYMBOL __attribute__((visibility("default")))
#elif defined(__APPLE__)
#define TESTS_OS_APPLE
#define EXPORT_SYMBOL __attribute__((visibility("default")))
#endif

EXPORT_SYMBOL int add(int a, int b)
{
    return a + b;
}

EXPORT_SYMBOL int some_integer = 0;