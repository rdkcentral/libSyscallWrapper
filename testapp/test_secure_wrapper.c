/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "secure_wrapper.h"

#define TEST_ARP_CACHE_FILE "/tmp/arp_cache_test"
#define DEFAULT_IFACE "brlan0"
#define DEFAULT_ITERATIONS 1000

static void check_zombie_processes(int iter)
{
    int ret = -1;

    printf("\n[DEBUG] Iteration %d: Checking zombie processes\n", iter);
    fflush(stdout);

    ret = v_secure_system("ps -ww | grep %s | grep -v grep", " Z ");
    printf("[DEBUG] zombie process check ret=%d errno=%d (%s)\n",
           ret, errno, strerror(errno));
    fflush(stdout);

    ret = v_secure_system("ps -ww | grep %s | grep -v grep", "[ip]");
    printf("[DEBUG] [ip] process check ret=%d errno=%d (%s)\n",
           ret, errno, strerror(errno));
    fflush(stdout);

    printf("[DEBUG] Zombie check completed\n\n");
    fflush(stdout);
}

static void run_ipv4_cmd(const char *iface, int iter)
{
    int ret = -1;

    errno = 0;
    printf("[DEBUG] Iteration %d: Running IPv4 command for iface=%s\n", iter, iface);
    fflush(stdout);

    ret = v_secure_system(
        "ip -4 nei show | grep %s | grep -v 192.168.10 > " TEST_ARP_CACHE_FILE,
        iface
    );

    printf("[DEBUG] Iteration %d: IPv4 v_secure_system ret=%d errno=%d (%s)\n",
           iter, ret, errno, strerror(errno));
    fflush(stdout);
}

static void run_ipv6_cmd(const char *iface, int iter)
{
    int ret = -1;

    errno = 0;
    printf("[DEBUG] Iteration %d: Running IPv6 command for iface=%s\n", iter, iface);
    fflush(stdout);

    ret = v_secure_system(
        "ip -6 nei show | grep %s | egrep -v '^(fc|fd)' >> " TEST_ARP_CACHE_FILE,
        iface
    );

    printf("[DEBUG] Iteration %d: IPv6 v_secure_system ret=%d errno=%d (%s)\n",
           iter, ret, errno, strerror(errno));
    fflush(stdout);
}

int main(int argc, char *argv[])
{
    const char *iface = DEFAULT_IFACE;
    int iterations = DEFAULT_ITERATIONS;
    int i = 0;

    if (argc > 1) {
        iface = argv[1];
    }

    if (argc > 2) {
        iterations = atoi(argv[2]);
        if (iterations <= 0) {
            iterations = DEFAULT_ITERATIONS;
        }
    }

    printf("=============================================\n");
    printf("libSyscallWrapper ip pipeline zombie test\n");
    printf("Interface  : %s\n", iface);
    printf("Iterations : %d\n", iterations);
    printf("Output file: %s\n", TEST_ARP_CACHE_FILE);
    printf("=============================================\n");
    fflush(stdout);

    unlink(TEST_ARP_CACHE_FILE);

    check_zombie_processes(0);

    for (i = 1; i <= iterations; i++) {
        unlink(TEST_ARP_CACHE_FILE);

        run_ipv4_cmd(iface, i);
        run_ipv6_cmd(iface, i);

        if (i % 10 == 0) {
            check_zombie_processes(i);
        }

        sleep(1);
    }

    check_zombie_processes(iterations);

    printf("Test completed\n");
    fflush(stdout);

    return 0;
}
