/*
 * fsplat_posix.c - POSIX (Linux/BSD) backend for fsplat.h.
 *
 * The Linux/BSD reference implementation: the opendir/readdir/stat/statvfs/
 * FAT_IOCTL/realpath/truncate code lifted out of fs.c behind the plat_*
 * interface, so the Linux build behaves bit-identically to before the
 * multi-platform refactor.
 *
 * ethersrv is distributed under the terms of the MIT License (see ethersrv.c).
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h> /* PATH_MAX */
#ifdef __linux__
#include <linux/msdos_fs.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* realpath() */
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "fsplat.h"

plat_dir *plat_opendir(const char *path) {
  return (plat_dir *)opendir(path);
}

int plat_readdir(plat_dir *d, struct plat_dirent *out) {
  struct dirent *e = readdir((DIR *)d);
  if (e == NULL)
    return 0;
  snprintf(out->lfn, sizeof(out->lfn), "%s", e->d_name);
  out->is_dir = (e->d_type == DT_DIR);
  return 1;
}

void plat_closedir(plat_dir *d) {
  if (d != NULL)
    closedir((DIR *)d);
}

int plat_stat(const char *path, int *is_dir, unsigned long long *size,
              time_t *mtime) {
  struct stat statbuf;
  if (stat(path, &statbuf) != 0)
    return -1;
  if (is_dir != NULL)
    *is_dir = S_ISDIR(statbuf.st_mode) ? 1 : 0;
  if (size != NULL)
    *size = (unsigned long long)statbuf.st_size;
  if (mtime != NULL)
    *mtime = statbuf.st_mtime;
  return 0;
}

int plat_getfatattr(const char *path, unsigned char *attr) {
#ifdef __linux__
  uint32_t a;
  int fd = open(path, O_RDONLY);
  if (fd == -1)
    return -1;
  if (ioctl(fd, (int)FAT_IOCTL_GET_ATTRIBUTES, &a) < 0) {
    close(fd);
    return 1; /* opened, but attributes unreadable */
  }
  close(fd);
  if (attr != NULL)
    *attr = (unsigned char)a;
  return 0;
#else
  /* No FAT-attribute API: fake archive, matching the historical fallback. */
  if (attr != NULL)
    *attr = 0x20;
  return 0;
#endif
}

int plat_setfatattr(const char *path, unsigned char attr) {
#ifdef __linux__
  uint32_t a = attr;
  int fd, res;
  fd = open(path, O_RDONLY);
  if (fd == -1)
    return -1;
  res = ioctl(fd, (int)FAT_IOCTL_SET_ATTRIBUTES, &a);
  close(fd);
  return (res < 0) ? -1 : 0;
#else
  (void)path;
  (void)attr;
  return 0; /* not supported: no-op, as before */
#endif
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

int plat_rmdir(const char *path) {
  struct stat st;
  if (lstat(path, &st) == 0 && S_ISLNK(st.st_mode))
    return unlink(path);
  return rmdir(path);
}

int plat_chdir(const char *path) { return chdir(path); }

int plat_unlink(const char *path) { return unlink(path); }

int plat_rename(const char *from, const char *to) { return rename(from, to); }

int plat_truncate(const char *path, unsigned long size) {
  return truncate(path, (off_t)size);
}

int plat_isfat(const char *path) {
#ifdef __linux__
  int fd;
  uint32_t volid;
  fd = open(path, O_RDONLY);
  if (fd == -1)
    return -1;
  if (ioctl(fd, (int)FAT_IOCTL_GET_VOLUME_ID, (int *)&volid) < 0) {
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
#else
  (void)path;
  return -1; /* no FAT probe: treat as non-FAT so attributes aren't used */
#endif
}

void plat_setnewfileperms(const char *path) {
  /* make the file mutually writable by others on the host system too */
  chmod(path, 0666);
}

int plat_fullpath(const char *in, char *out, int outsz) {
  char tmp[PATH_MAX];
  if (realpath(in, tmp) == NULL)
    return -1;
  if ((int)strlen(tmp) >= outsz)
    return -1;
  strcpy(out, tmp);
  return 0;
}
