#include <mini_detour/mini_detour.h>

#if defined(MINIDETOUR_OS_WINDOWS)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

int main()
{
#if defined(MINIDETOUR_OS_WINDOWS)
    // user32 is one of the default libraries of a Windows project: it must still be linked.
    if (GetDesktopWindow() == nullptr)
        return 2;
#endif

    return MiniDetour::MemoryManipulation::PageSize() != 0 ? 0 : 1;
}
