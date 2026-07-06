/*
 * fsplat_win.c - Windows 9x backend for fsplat.h (native VFAT long names).
 *
 * Uses only the ANSI (*A) Win32 entry points, which are the ones actually
 * implemented on Windows 95/98/ME (the wide *W functions are unimplemented
 * stubs there). VFAT delivers long names for free via FindFirstFileA, so the
 * server hands DOS the real long name and lets fs.c's own lfn2sfn synthesize
 * the deterministic 8.3 alias (Windows' cAlternateFileName is deliberately
 * discarded - it is not stable across directory churn/reboots and must not
 * disagree with what the reverse SFN->long resolve computes).
 *
 * CODEPAGE NOTE: FindFirstFileA / fopen use the system ANSI codepage (~1252),
 * whereas fs.c's cp_disk2wire treats disk bytes as UTF-8. For 7-bit ASCII
 * names - the whole practical retro-DOS filename set - the two agree byte for
 * byte, so this backend is correct as-is. Non-ASCII names need the disk-side
 * codec in cp_disk2wire/cp_wire2disk to become platform-aware (ANSI-1252 <->
 * OEM via CharToOemBuffA/OemToCharBuffA); that is a focused follow-up in fs.c,
 * tracked separately.
 *
 * ethersrv is distributed under the terms of the MIT License (see ethersrv.c).
 */

#include <windows.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fsplat.h"

/* FILETIME (100 ns since 1601-01-01 UTC) -> time_t (seconds since 1970). The
 * 11644473600 s gap between the two epochs, times 10^7. */
static time_t filetime_to_time_t(const FILETIME *ft) {
  ULARGE_INTEGER u;
  u.LowPart = ft->dwLowDateTime;
  u.HighPart = ft->dwHighDateTime;
  return (time_t)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

/* "C:\dir\..." -> "C:\" ; best-effort passthrough for anything unusual. */
static void volume_root_of(const char *path, char *root, int rootsz) {
  if (path[0] != 0 && path[1] == ':' && rootsz >= 4) {
    root[0] = path[0];
    root[1] = ':';
    root[2] = '\\';
    root[3] = 0;
  } else {
    snprintf(root, (size_t)rootsz, "%s", path);
  }
}

struct plat_dir {
  HANDLE h;
  WIN32_FIND_DATAA fd;
  int pending; /* 1 = fd holds an entry not yet returned (from FindFirstFile) */
};

plat_dir *plat_opendir(const char *path) {
  char pattern[1024];
  plat_dir *d = malloc(sizeof(*d));
  if (d == NULL)
    return NULL;
  snprintf(pattern, sizeof(pattern), "%s\\*", path);
  d->h = FindFirstFileA(pattern, &d->fd);
  if (d->h == INVALID_HANDLE_VALUE) {
    free(d);
    return NULL;
  }
  d->pending = 1;
  return d;
}

int plat_readdir(plat_dir *d, struct plat_dirent *out) {
  if (!d->pending) {
    if (!FindNextFileA(d->h, &d->fd))
      return 0;
  }
  d->pending = 0;
  snprintf(out->lfn, sizeof(out->lfn), "%s", d->fd.cFileName);
  out->is_dir = (d->fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
  return 1;
}

void plat_closedir(plat_dir *d) {
  if (d != NULL) {
    if (d->h != INVALID_HANDLE_VALUE)
      FindClose(d->h);
    free(d);
  }
}

int plat_stat(const char *path, int *is_dir, unsigned long long *size,
              time_t *mtime) {
  /* FindFirstFileA (rather than GetFileAttributesExA, which only exists on
   * Win98+) returns attributes, size and mtime for a single file or directory
   * in one WIN32_FIND_DATA, and is available on Win95 too. It does not work on
   * a bare drive root ("C:\"), but the server only stats files and served
   * subdirectories, never a drive root. */
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(path, &fd);
  if (h == INVALID_HANDLE_VALUE)
    return -1;
  FindClose(h);
  if (is_dir != NULL)
    *is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
  if (size != NULL)
    *size = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
  if (mtime != NULL)
    *mtime = filetime_to_time_t(&fd.ftLastWriteTime);
  return 0;
}

int plat_getfatattr(const char *path, unsigned char *attr) {
  DWORD a = GetFileAttributesA(path);
  if (a == INVALID_FILE_ATTRIBUTES)
    return -1;
  /* Win32 attribute bits ARE the DOS attribute bits: RO=1 HID=2 SYS=4
   * DIR=0x10 ARCH=0x20. Mask off everything Windows adds on top. */
  if (attr != NULL)
    *attr = (unsigned char)(a & 0x37);
  return 0;
}

int plat_setfatattr(const char *path, unsigned char attr) {
  DWORD a = attr & 0x27; /* RO|HID|SYS|ARCH; DIR can't be set via this call */
  if (a == 0)
    a = FILE_ATTRIBUTE_NORMAL;
  return SetFileAttributesA(path, a) ? 0 : -1;
}

int plat_diskspace(const char *path, unsigned long long *total,
                   unsigned long long *freebytes) {
  ULARGE_INTEGER freeToCaller, tot, totFree;
  if (!GetDiskFreeSpaceExA(path, &freeToCaller, &tot, &totFree))
    return -1;
  if (total != NULL)
    *total = (unsigned long long)tot.QuadPart;
  if (freebytes != NULL)
    *freebytes = (unsigned long long)totFree.QuadPart;
  return 0;
}

int plat_mkdir(const char *path) {
  if (CreateDirectoryA(path, NULL))
    return 0;
  errno = (GetLastError() == ERROR_PATH_NOT_FOUND) ? ENOENT : EACCES;
  return -1;
}

int plat_rmdir(const char *path) { return RemoveDirectoryA(path) ? 0 : -1; }

int plat_chdir(const char *path) { return SetCurrentDirectoryA(path) ? 0 : -1; }

int plat_unlink(const char *path) { return DeleteFileA(path) ? 0 : -1; }

int plat_rename(const char *from, const char *to) {
  if (MoveFileA(from, to))
    return 0;
  {
    DWORD e = GetLastError();
    errno = (e == ERROR_PATH_NOT_FOUND || e == ERROR_FILE_NOT_FOUND) ? ENOENT
            : (e == ERROR_NOT_SAME_DEVICE)                           ? EXDEV
                                                                     : EACCES;
  }
  return -1;
}

int plat_truncate(const char *path, unsigned long size) {
  HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return -1;
  if (SetFilePointer(h, (LONG)size, NULL, FILE_BEGIN) ==
          INVALID_SET_FILE_POINTER ||
      !SetEndOfFile(h)) {
    CloseHandle(h);
    return -1;
  }
  CloseHandle(h);
  return 0;
}

int plat_isfat(const char *path) {
  char root[MAX_PATH], fsname[32];
  volume_root_of(path, root, sizeof(root));
  if (!GetVolumeInformationA(root, NULL, 0, NULL, NULL, NULL, fsname,
                             sizeof(fsname)))
    return -1;
  /* "FAT", "FAT32" -> FAT; "NTFS", "CDFS" -> not */
  return (strncmp(fsname, "FAT", 3) == 0) ? 0 : -1;
}

void plat_setnewfileperms(const char *path) {
  (void)path; /* host permission bits are a POSIX concept; no-op on Windows */
}

int plat_fullpath(const char *in, char *out, int outsz) {
  DWORD n = GetFullPathNameA(in, (DWORD)outsz, out, NULL);
  if (n == 0 || n >= (DWORD)outsz)
    return -1;
  /* realpath() fails on a nonexistent path; match that so a bad served root is
   * rejected at startup rather than silently accepted. */
  if (GetFileAttributesA(out) == INVALID_FILE_ATTRIBUTES)
    return -1;
  return 0;
}
