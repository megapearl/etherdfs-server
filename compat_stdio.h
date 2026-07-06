/*
 * compat_stdio.h - Win9x-safe snprintf for ethersrv.
 *
 * On Windows, mingw routes C99 snprintf() through a wrapper that resolves
 * msvcrt at runtime via GetModuleHandleW(L"msvcrt.dll") - and GetModuleHandleW
 * is a non-functional stub on Win9x, so any snprintf call would drag a wide CRT
 * import into the binary and break it on 9x. Map snprintf() to a thin wrapper
 * over msvcrt's own _vsnprintf() (which pulls in no wide call), adding the NUL
 * termination that _vsnprintf omits on truncation. No effect on Linux or
 * DJGPP/DOS, whose snprintf is fine and pulls in no wide symbol.
 *
 * Include this AFTER the system headers in any Windows-compiled TU that calls
 * snprintf (fs.c, ethersrv.c, fsplat_win.c).
 *
 * ethersrv is distributed under the terms of the MIT License (see ethersrv.c).
 */
#ifndef COMPAT_STDIO_H
#define COMPAT_STDIO_H

#ifdef _WIN32
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

static __inline int edf_snprintf(char *buf, size_t n, const char *fmt, ...) {
  va_list ap;
  int r;
  va_start(ap, fmt);
  r = _vsnprintf(buf, n, fmt, ap);
  va_end(ap);
  if (n > 0)
    buf[n - 1] = 0; /* _vsnprintf leaves the buffer unterminated on truncation */
  return r;
}
#define snprintf edf_snprintf
#endif

#endif
