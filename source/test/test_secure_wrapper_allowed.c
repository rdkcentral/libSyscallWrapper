#include "secure_wrapper.h"

void test_secure_syscalls(void)
{
    v_secure_system("ls");
    v_secure_popen("r", "ls");
}
