#include <stdio.h>
#include <string.h>
#include "secure_wrapper.h"

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr,
            "Usage:\n"
            "  %s system <command>\n"
            "  %s popen <command>\n"
            "  %s legacy <command>\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "system") == 0) {
        return v_secure_system("%s", argv[2]);
    }

    if (strcmp(argv[1], "popen") == 0) {
        FILE *fp = v_secure_popen("r", "%s", argv[2]);
        if (!fp) return 2;

        char buf[256];
        while (fgets(buf, sizeof(buf), fp)) {
            fputs(buf, stdout);
        }
        return v_secure_pclose(fp);
    }

    if (strcmp(argv[1], "legacy") == 0) {
        return secure_system_call_vp(argv[2], NULL);
    }

    fprintf(stderr, "Unknown mode: %s\n", argv[1]);
    return 1;
}
