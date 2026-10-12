/* Built twice (see CMakeLists.txt): for an old macOS, getpid is called through a lazy symbol pointer; for macOS 12,
   through a non lazy pointer set by chained fixups. */
#include <unistd.h>

__attribute__((visibility("default"))) int ImportGetPid(void)
{
    return (int)getpid();
}
