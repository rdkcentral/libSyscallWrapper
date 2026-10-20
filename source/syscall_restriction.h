#ifndef SYSCALL_RESTRICTION_H
#define SYSCALL_RESTRICTION_H

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC poison system
#pragma GCC poison popen
#endif

#endif
