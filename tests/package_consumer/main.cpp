#include <mini_detour/mini_detour.h>

int main()
{
    return MiniDetour::MemoryManipulation::PageSize() != 0 ? 0 : 1;
}
