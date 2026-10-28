#include <stdio.h>

FILE *test_popen_forbidden(void)
{
    return popen("true", "r");
}
