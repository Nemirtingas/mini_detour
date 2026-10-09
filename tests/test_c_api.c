/* BUGS.md #40: the public header must compile as C. */
#include <mini_detour/mini_detour.h>

int MiniDetourCApiTest(void)
{
    MiniDetourMemoryManipulationRegionInfos_t regionInfos;
    MiniDetourMemoryManipulationMemoryRights rights = mem_rx;
    minidetour_hook_handle_t hook;
    bool canHook;
    void *original;

    if (MiniDetourUtilsPageSize() == 0)
        return 1;

    regionInfos.StructSize = sizeof(regionInfos);
    MiniDetourMemoryManipulationGetRegionInfos((void *)&MiniDetourCApiTest, &regionInfos);
    if (regionInfos.Rights == mem_unset || (regionInfos.Rights & rights) == 0)
        return 2;

    hook = MiniDetourHookTAlloc();
    if (hook == NULL)
        return 3;

    /* Only checks that bool works in C, the result depends on how the compiler built this function. */
    canHook = MiniDetourHookTCanHook(hook, (void *)&MiniDetourCApiTest);
    (void)canHook;

    original = MiniDetourHookTGetOriginalFunction(hook);
    MiniDetourHookTFree(hook);

    return original == NULL ? 0 : 4;
}
