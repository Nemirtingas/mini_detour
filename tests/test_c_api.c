/* BUGS.md #40: the public header must compile as C. */
#include <mini_detour/mini_detour.h>

/* The C API uses int for booleans: the header must not bring bool in (stdbool.h). */
#if defined(__bool_true_false_are_defined) || defined(bool)
#error "mini_detour.h must not include stdbool.h or define bool"
#endif

int MiniDetourCApiTest(void)
{
    MiniDetourMemoryManipulationRegionInfos_t regionInfos;
    MiniDetourMemoryManipulationMemoryRights rights = mem_rx;
    minidetour_hook_handle_t hook;
    int canHook;
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

    /* The result depends on how the compiler built this function: only checks that it is 0 or 1. */
    canHook = MiniDetourHookTCanHook(hook, (void *)&MiniDetourCApiTest);
    if (canHook != 0 && canHook != 1)
        return 5;

    MiniDetourHookTRestoreOnDestroy(hook, 1);

    original = MiniDetourHookTGetOriginalFunction(hook);
    MiniDetourHookTFree(hook);

    return original == NULL ? 0 : 4;
}
