#include <stdio.h>

// Built with -fno-plt: puts is called through its GOT entry.
__attribute__((visibility("default"))) int no_plt_puts(const char *str)
{
    return puts(str);
}
