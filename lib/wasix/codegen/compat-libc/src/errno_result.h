#ifndef WASIX_COMPAT_LIBC_ERRNO_RESULT_H
#define WASIX_COMPAT_LIBC_ERRNO_RESULT_H

#include <errno.h>

/* Match musl's -4095..-1 syscall error range using only public libc APIs. */
static inline int wasix_compat_result(long result) {
  if ((unsigned long)result > -4096UL) {
    errno = (int)-result;
    return -1;
  }
  return (int)result;
}

#endif
