#include <stdio.h>

// Hidden: the library exports nothing, but still imports puts.
void no_export_test_function(void)
{
    puts("no_export_test_function");
}
