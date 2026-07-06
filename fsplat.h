/*
 * fsplat.h - platform-neutral filesystem access for ethersrv.
 *
 * fs.c is pure EtherDFS logic (8.3 alias generation, the fsdb cache, wire
 * codepage conversion) plus ANSI stdio file I/O (fopen/fread/fwrite/fseek,
 * which recompile everywhere). Everything that differs between operating
 * systems - directory enumeration, stat, FAT attributes, disk-free, the
 * mkdir/rmdir/chdir/unlink/rename/truncate primitives and path canonicalization
 * - goes through this interface. Each platform implements it in its own
 * fsplat_<platform>.c: fsplat_posix.c (Linux/BSD, the reference), fsplat_win.c
 * (Win9x, FindFirstFileA + VFAT long names) and fsplat_dos.c (DJGPP).
 *
 * ethersrv is distributed under the terms of the MIT License (see ethersrv.c).
 */
#ifndef FSPLAT_H
#define FSPLAT_H

#include <time.h> /* time_t */

/* Opaque directory handle (a DIR* on POSIX, a FindFirst handle on Win/DOS). */
typedef struct plat_dir plat_dir;

/* One directory entry. lfn holds the on-disk long name in the platform's
 * on-disk byte encoding (UTF-8 on POSIX, ANSI on Win9x, OEM on DOS); fs.c
 * converts it to the wire codepage via cp_disk2wire. is_dir mirrors the
 * historical `d_type == DT_DIR` test. */
struct plat_dirent {
  char lfn[256];
  int is_dir;
};

plat_dir *plat_opendir(const char *path);
int plat_readdir(plat_dir *d, struct plat_dirent *out); /* 1 = entry, 0 = end */
void plat_closedir(plat_dir *d);

/* Stat one item. Returns 0 on success (fills *is_dir, *size and *mtime), or -1
 * if the item does not exist. */
int plat_stat(const char *path, int *is_dir, unsigned long long *size,
              time_t *mtime);

/* Read the real DOS FAT attribute byte into *attr. Returns 0 on success, -1 if
 * the item could not be opened, or 1 if it was opened but the FAT attributes
 * are unreadable. On a platform without a FAT-attribute API this returns 0 with
 * *attr = 0x20 (archive), matching the historical non-Linux fallback. */
int plat_getfatattr(const char *path, unsigned char *attr);

/* Set the DOS FAT attribute byte. Returns 0 on success, -1 on error. A no-op
 * returning 0 on platforms without a FAT-attribute API. */
int plat_setfatattr(const char *path, unsigned char attr);

/* Total and free bytes of the filesystem holding path. Returns 0 on success,
 * -1 on error. */
int plat_diskspace(const char *path, unsigned long long *total,
                   unsigned long long *freebytes);

int plat_mkdir(const char *path);  /* create a directory; 0 on success */
int plat_rmdir(const char *path);  /* remove a dir (unlink a symlink first) */
int plat_chdir(const char *path);  /* 0 if the directory exists / was entered */
int plat_unlink(const char *path); /* delete a file; 0 on success */
int plat_rename(const char *from, const char *to); /* 0 on success */
int plat_truncate(const char *path, unsigned long size); /* 0 on success */

/* 0 if path is on a FAT filesystem (so DOS attributes are meaningful),
 * non-zero otherwise. */
int plat_isfat(const char *path);

/* Make a freshly created file world-readable/writable on the host. A no-op on
 * platforms where that concept does not apply (DOS/Win9x). */
void plat_setnewfileperms(const char *path);

/* Canonicalize `in` into `out` (>= outsz bytes), resolving . / .. (and symlinks
 * where they exist). Returns 0 on success, -1 on error.
 * realpath() / GetFullPathNameA() / _fixpath(). */
int plat_fullpath(const char *in, char *out, int outsz);

#endif
