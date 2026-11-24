#ifndef SYSCALL_RESTRICTION_H
#define SYSCALL_RESTRICTION_H

#include <stdio.h>
#include <stdlib.h>

#if defined(__GNUC__) || defined(__clang__)

#ifdef __cplusplus
extern "C" {
#endif

extern int system(const char *command)
    __attribute__((error(
        "Direct system() calls are forbidden; use v_secure_system()")));
extern FILE *popen(const char *command, const char *type)
    __attribute__((error(
        "Direct popen() calls are forbidden; use v_secure_popen()")));

#ifdef __cplusplus
}
#endif

#else
#error "system()/popen() enforcement requires GCC or Clang"
#endif

#endif
