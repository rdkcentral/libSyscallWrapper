#include "secure_wrapper.h"

void test_secure_wrapper_allowed(void)
{
    (void)v_secure_system("true");
    (void)v_secure_popen("r", "true");
}
