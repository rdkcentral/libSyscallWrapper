#include <stdlib.h>

int test_system_forbidden(void)
{
    return system("true");
}
