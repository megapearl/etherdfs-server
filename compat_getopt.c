/*
 * compat_getopt.c - minimal POSIX-style getopt() for the Windows/DOS builds.
 *
 * A self-contained getopt supporting the "abc:d:" convention (a trailing ':'
 * marks an option that takes an argument, given either attached "-mVALUE" or as
 * the next argv "-m VALUE"). It does NOT permute argv - it stops at the first
 * non-option - which is exactly ethersrv's "[options] interface roots..." usage.
 * Providing getopt/optind/optarg/optopt/opterr here makes the linker use these
 * instead of the libc getopt (which on mingw reads the environment via a wide
 * CRT call that is a stub on Win9x).
 *
 * ethersrv is distributed under the terms of the MIT License (see ethersrv.c).
 */
#include <string.h>

#include "compat_getopt.h"

int opterr = 1;
int optind = 1;
int optopt = 0;
char *optarg = NULL;

int getopt(int argc, char *const argv[], const char *optstring) {
  static int optpos = 1; /* position within a bundled "-abc" group */
  const char *spec;

  optarg = NULL;

  if (optind >= argc || argv[optind] == NULL)
    return -1;
  if (argv[optind][0] != '-' || argv[optind][1] == '\0')
    return -1; /* not an option (or a lone "-") */
  if (argv[optind][1] == '-' && argv[optind][2] == '\0') {
    optind++; /* "--" ends option processing */
    return -1;
  }

  optopt = (unsigned char)argv[optind][optpos];
  spec = strchr(optstring, optopt);
  if (optopt == ':' || spec == NULL) {
    /* unknown option character */
    if (argv[optind][++optpos] == '\0') {
      optind++;
      optpos = 1;
    }
    return '?';
  }

  if (spec[1] == ':') {
    /* option requires an argument */
    if (argv[optind][optpos + 1] != '\0') {
      optarg = (char *)&argv[optind][optpos + 1]; /* -mVALUE */
      optind++;
    } else if (optind + 1 < argc) {
      optarg = argv[optind + 1]; /* -m VALUE */
      optind += 2;
    } else {
      optind++;
      optpos = 1;
      return (optstring[0] == ':') ? ':' : '?'; /* missing argument */
    }
    optpos = 1;
    return optopt;
  }

  /* plain flag option */
  if (argv[optind][++optpos] == '\0') {
    optind++;
    optpos = 1;
  }
  return optopt;
}
