/*
 * compat_getopt.h - minimal POSIX getopt() for platforms whose libc getopt
 * drags in unwanted dependencies. mingw's getopt reads the environment through
 * GetEnvironmentVariableW - a Win9x stub - so the Windows/DOS builds link this
 * bundled implementation instead (compat_getopt.c). The Linux build keeps the
 * glibc getopt and never compiles this.
 *
 * ethersrv is distributed under the terms of the MIT License (see ethersrv.c).
 */
#ifndef COMPAT_GETOPT_H
#define COMPAT_GETOPT_H

extern int opterr;
extern int optind;
extern int optopt;
extern char *optarg;

int getopt(int argc, char *const argv[], const char *optstring);

#endif
