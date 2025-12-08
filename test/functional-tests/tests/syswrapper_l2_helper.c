#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "../../../source/secure_wrapper.h"

static int call_secure_system(const char *cmd)
{
    return v_secure_system("/bin/sh -c \"%s\"", cmd);
}

static int call_secure_popen(const char *cmd)
{
    char buf[4096];
    memset(buf, 0, sizeof(buf));

    FILE *fp = v_secure_popen("r", "/bin/sh -c \"%s\"", cmd);
    if (!fp)
        return 255;

    while (fgets(buf, sizeof(buf), fp))
        fputs(buf, stdout);

    fflush(stdout);

    return v_secure_pclose(fp);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <system|popen> <cmd>\n", argv[0]);
        return 255;
    }

    if (strcmp(argv[1], "system") == 0)
        return call_secure_system(argv[2]);

    if (strcmp(argv[1], "popen") == 0)
        return call_secure_popen(argv[2]);

    fprintf(stderr, "Unknown mode\n");
    return 255;
}
