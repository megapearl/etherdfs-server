/*
 * fsplat_dos.c - DJGPP (DOS) backend for fsplat.h.
 *
 * DJGPP ships a POSIX-ish libc, so most of this mirrors fsplat_posix.c
 * (opendir/readdir with d_type, stat, mkdir/rmdir/chdir/unlink/rename,
 * truncate, statvfs). The DOS-specific pieces are the real FAT attribute byte
 * (DJGPP's _chmod, which wraps INT 21h AX=4300h/4301h) and path canonicalization
 * (_fixpath, which unlike realpath does not verify existence, so an explicit
 * stat is added). DOS volumes are always FAT, so plat_isfat trivially succeeds.
 *
 * ethersrv is distributed under the terms of the MIT License (see ethersrv.c).
 */

#include <dirent.h>
#include <errno.h>
#include <io.h>     /* _chmod() - DOS attribute get/set */
#include <stdio.h>  /* FILENAME_MAX, snprintf */
#include <stdlib.h> /* _fixpath() */
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h> /* truncate(), chdir(), rmdir(), unlink() */

#include "fsplat.h"

plat_dir *plat_opendir(const char *path) { return (plat_dir *)opendir(path); }

int plat_readdir(plat_dir *d, struct plat_dirent *out) {
  struct dirent *e = readdir((DIR *)d);
  if (e == NULL)
    return 0;
  snprintf(out->lfn, sizeof(out->lfn), "%s", e->d_name);
  out->is_dir = (e->d_type == DT_DIR); /* DJGPP fills d_type from the FAT attr */
  return 1;
}

void plat_closedir(plat_dir *d) {
  if (d != NULL)
    closedir((DIR *)d);
}

int plat_stat(const char *path, int *is_dir, unsigned long long *size,
              time_t *mtime) {
  struct stat st;
  if (stat(path, &st) != 0)
    return -1;
  if (is_dir != NULL)
    *is_dir = S_ISDIR(st.st_mode) ? 1 : 0;
  if (size != NULL)
    *size = (unsigned long long)st.st_size;
  if (mtime != NULL)
    *mtime = st.st_mtime;
  return 0;
}

int plat_getfatattr(const char *path, unsigned char *attr) {
  int a = _chmod(path, 0); /* get: INT 21h AX=4300h */
  if (a < 0)
    return -1;
  /* RO=1 HID=2 SYS=4 DIR=0x10 ARCH=0x20 - the DOS attribute bits directly */
  if (attr != NULL)
    *attr = (unsigned char)(a & 0x37);
  return 0;
}

int plat_setfatattr(const char *path, unsigned char attr) {
  /* set only the file attribute bits (never VOL/DIR): INT 21h AX=4301h */
  return (_chmod(path, 1, attr & 0x27) < 0) ? -1 : 0;
}

int plat_diskspace(const char *path, unsigned long long *total,
                   unsigned long long *freebytes) {
  struct statvfs buf;
  if (statvfs(path, &buf) != 0)
    return -1;
  if (total != NULL)
    *total = (unsigned long long)buf.f_blocks * buf.f_frsize;
  if (freebytes != NULL)
    *freebytes = (unsigned long long)buf.f_bfree * buf.f_bsize;
  return 0;
}

int plat_mkdir(const char *path) { return mkdir(path, 0777); }

int plat_rmdir(const char *path) { return rmdir(path); } /* no symlinks on DOS */

int plat_chdir(const char *path) { return chdir(path); }

int plat_unlink(const char *path) { return unlink(path); }

int plat_rename(const char *from, const char *to) { return rename(from, to); }

int plat_truncate(const char *path, unsigned long size) {
  return truncate(path, (off_t)size);
}

int plat_isfat(const char *path) {
  (void)path;
  return 0; /* every DOS volume is FAT, so DOS attributes are always meaningful */
}

void plat_setnewfileperms(const char *path) {
  (void)path; /* host permission bits are a POSIX concept; no-op on DOS */
}

int plat_fullpath(const char *in, char *out, int outsz) {
  char tmp[FILENAME_MAX];
  struct stat st;
  _fixpath(in, tmp); /* canonicalize; does NOT verify the path exists */
  if ((int)strlen(tmp) >= outsz)
    return -1;
  if (stat(tmp, &st) != 0)
    return -1; /* match realpath(): reject a nonexistent served root */
  strcpy(out, tmp);
  return 0;
}
