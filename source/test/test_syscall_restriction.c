#include <stdio.h>
#include <stdlib.h>

void test_raw_syscalls(void)
{
    system("ls");
    popen("ls", "r");
}
