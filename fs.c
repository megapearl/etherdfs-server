/*
 * This file is part of the ethersrv-linux project
 * Copyright (C) 2017 Mateusz Viste
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#ifdef __linux__
#include <linux/msdos_fs.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* free() */
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>    /* stat() */
#include <sys/statvfs.h> /* statvfs() for diskfree calls */
#include <sys/types.h>
#include <time.h> /* time_t, struct tm... */
#include <unistd.h>

#include "debug.h"
#include "fs.h" /* include self for control */

/* ===================================================================
 * Codepage conversion (increment 6): the Linux filesystem stores names as
 * UTF-8, but the DOS wire carries single-byte OEM codepage bytes (CP437 by
 * default, CP850 optional via ETHERDFS_CODEPAGE). We convert at the two
 * storage seams: disk->wire when listing/matching (cp_disk2wire) and
 * wire->disk when creating (cp_wire2disk). 0x00..0x7F is ASCII == Unicode
 * 1:1; only the high half needs a table. Tables are generated from the
 * authoritative unicode.org MICSFT/PC/CP{437,850}.TXT. */
static const unsigned short cp437_hi[128] = {
  0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7,
  0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
  0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
  0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
  0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA,
  0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
  0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
  0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
  0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
  0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
  0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B,
  0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
  0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4,
  0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
  0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248,
  0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
};
static const unsigned short cp850_hi[128] = {
  0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7,
  0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
  0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
  0x00FF, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x00D7, 0x0192,
  0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA,
  0x00BF, 0x00AE, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
  0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x00C1, 0x00C2, 0x00C0,
  0x00A9, 0x2563, 0x2551, 0x2557, 0x255D, 0x00A2, 0x00A5, 0x2510,
  0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x00E3, 0x00C3,
  0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x00A4,
  0x00F0, 0x00D0, 0x00CA, 0x00CB, 0x00C8, 0x0131, 0x00CD, 0x00CE,
  0x00CF, 0x2518, 0x250C, 0x2588, 0x2584, 0x00A6, 0x00CC, 0x2580,
  0x00D3, 0x00DF, 0x00D4, 0x00D2, 0x00F5, 0x00D5, 0x00B5, 0x00FE,
  0x00DE, 0x00DA, 0x00DB, 0x00D9, 0x00FD, 0x00DD, 0x00AF, 0x00B4,
  0x00AD, 0x00B1, 0x2017, 0x00BE, 0x00B6, 0x00A7, 0x00F7, 0x00B8,
  0x00B0, 0x00A8, 0x00B7, 0x00B9, 0x00B3, 0x00B2, 0x25A0, 0x00A0,
};

static const unsigned short *g_cp_hi = cp437_hi; /* active high-half table */

/* Select the active codepage from a name/number ("437" default, "850"). NULL
 * or unknown -> CP437. Called once at startup from main(). */
void cp_init(const char *name) {
  if (name != NULL &&
      (strcmp(name, "850") == 0 || strcmp(name, "cp850") == 0 ||
       strcmp(name, "CP850") == 0)) {
    g_cp_hi = cp850_hi;
  } else {
    g_cp_hi = cp437_hi;
  }
}

/* Convert a UTF-8 disk name to OEM-codepage wire bytes. Each Unicode code
 * point becomes exactly one output byte: ASCII passes through, a high-half
 * code point is reverse-looked-up in the active table, and anything not
 * representable becomes '_' (Win95 substitutes '_' for unmappable chars). A
 * malformed UTF-8 lead/continuation byte is passed through raw (best effort,
 * never expands). Output is always shorter-or-equal to the input, so a 255-
 * byte name fits any >=256 buffer. NUL-terminated, bounded by outsz. */
void cp_disk2wire(const char *utf8, char *out, int outsz) {
  const unsigned char *s = (const unsigned char *)utf8;
  int o = 0;
  while (*s != 0 && o < outsz - 1) {
    unsigned long cp;
    int n, k, ok;
    unsigned char b = *s;
    if (b < 0x80) { out[o++] = (char)b; s++; continue; }
    if ((b & 0xE0) == 0xC0) { cp = b & 0x1F; n = 1; }
    else if ((b & 0xF0) == 0xE0) { cp = b & 0x0F; n = 2; }
    else if ((b & 0xF8) == 0xF0) { cp = b & 0x07; n = 3; }
    else { out[o++] = '_'; s++; continue; } /* stray continuation/invalid lead */
    ok = 1;
    for (k = 0; k < n; k++) {
      if ((s[1 + k] & 0xC0) != 0x80) { ok = 0; break; }
      cp = (cp << 6) | (s[1 + k] & 0x3F);
    }
    if (!ok) { out[o++] = '_'; s++; continue; } /* truncated sequence */
    s += n + 1;
    /* reject non-shortest (overlong) forms, UTF-16 surrogates and beyond-
     * Unicode values: never let "different bytes, same code point" alias a
     * name (RFC 3629). readdir() should not produce these, but be strict. */
    if (((n == 1) && (cp < 0x80)) || ((n == 2) && (cp < 0x800)) ||
        ((n == 3) && (cp < 0x10000)) ||
        ((cp >= 0xD800) && (cp <= 0xDFFF)) || (cp > 0x10FFFFul)) {
      out[o++] = '_';
      continue;
    }
    if (cp < 0x80) { out[o++] = (char)cp; continue; }
    { int i, hit = -1;
      for (i = 0; i < 128; i++) if (g_cp_hi[i] == cp) { hit = i; break; }
      out[o++] = (hit >= 0) ? (char)(0x80 + hit) : '_';
    }
  }
  out[o] = 0;
}

/* Convert OEM-codepage wire bytes to a UTF-8 disk name. ASCII passes through;
 * a high byte expands to the 1..3 byte UTF-8 encoding of its code point (all
 * CP437/CP850 points are in the BMP, so <=3 bytes). Output can be up to 3x
 * the input, so the caller must size the buffer accordingly. NUL-terminated,
 * bounded by outsz (a code point that would not fit whole is dropped). */
void cp_wire2disk(const char *cp, char *out, int outsz) {
  const unsigned char *s = (const unsigned char *)cp;
  int o = 0;
  while (*s != 0) {
    unsigned char b = *s++;
    unsigned long u = (b < 0x80) ? b : g_cp_hi[b - 0x80];
    if (u < 0x80) {
      if (o + 1 >= outsz) break;
      out[o++] = (char)u;
    } else if (u < 0x800) {
      if (o + 2 >= outsz) break;
      out[o++] = (char)(0xC0 | (u >> 6));
      out[o++] = (char)(0x80 | (u & 0x3F));
    } else {
      if (o + 3 >= outsz) break;
      out[o++] = (char)(0xE0 | (u >> 12));
      out[o++] = (char)(0x80 | ((u >> 6) & 0x3F));
      out[o++] = (char)(0x80 | (u & 0x3F));
    }
  }
  out[o] = 0;
}
/* =================================================================== */

/* database containing file/dir identifiers and their names - this is used
 * whenever ethersrv-linux needs to provide etherdfs with a 16bit identifier
 * that etherdfs will subsequently use to refer to this file or dir (typically
 * used during FindFirst+FindNext steps and Open/Create+Write/Read.
 * the struct may also contain an entire directory listing computed by FFirst
 * (and used then by FNext) */
static struct sfsdb {
  char *name;
  time_t lastused;
  struct sdirlist { /* pointer to dir listing, if dir and if generated by FFirst
                     */
    char sfn_name[14];  /* Store the 8.3 SFN version of the name */
    char lfn_name[256]; /* the real long name (for LFN ops); empty for VOL node */
    struct fileprops fprops;
    struct sdirlist *next;
  } *dirlist;
} fsdb[65536];

/* frees a sdirlist linked list */
static void freedirlist(struct sdirlist *d) {
  while (d != NULL) {
    struct sdirlist *victim = d;
    d = d->next;
    free(victim);
  }
}

/* returns the "start sector" of a filesystem item (file or directory).
 * it registers the item into the file cache and returns its id or 0xffff on
 * error */
unsigned short getitemss(char *f) {
  unsigned short i, firstfree = 0xffffu, oldest = 0;
  time_t now = time(NULL);
  /* see if not already in cache */
  for (i = 0; i < 0xffffu; i++) {
    /* is it what I am looking after? */
    if ((fsdb[i].name != NULL) && (strcmp(fsdb[i].name, f) == 0)) {
      fsdb[i].lastused = now;
      return (i);
    }
    /* if the entry is not what I was looking for, check its last usage and
     * remove if older than one hour */
    if ((now - fsdb[i].lastused) > 3600) {
      free(fsdb[i].name);
      freedirlist(fsdb[i].dirlist);
      memset(&(fsdb[i]), 0, sizeof(struct sfsdb));
    }
    /* if slot free, remember it, perhaps we'll use it */
    if ((firstfree == 0xffffu) && (fsdb[i].name == NULL)) {
      firstfree = i;
    } else if (fsdb[oldest].lastused >
               fsdb[i].lastused) { /* otherwise see if it's the oldest entry (I
                                      might remove it later if no choice) */
      oldest = i;
    }
  }
  /* not found - if no free slot available, pick the oldest one and replace it
   */
  if (firstfree == 0xffffu) {
    firstfree = oldest;
    free(fsdb[oldest].name);
    freedirlist(fsdb[oldest].dirlist);
    memset(&(fsdb[oldest]), 0, sizeof(struct sfsdb));
  }
  /* register it */
  fsdb[firstfree].name = strdup(f);
  if (fsdb[firstfree].name == NULL) {
    fprintf(stderr, "ERROR: OUT OF MEM!\n");
    return (0xffffu);
  }
  fsdb[firstfree].lastused = now;
  return (firstfree);
}

char *sstoitem(unsigned short ss) { return (fsdb[ss].name); }

/* turns a character c into its upper-case variant */
char upchar(char c) {
  if ((c >= 'a') && (c <= 'z'))
    c -= ('a' - 'A');
  return (c);
}

/* translates a filename string into a fcb-style block ("FILE0001TXT") */
void lfn2sfn(char *sfn, const char *lfn, int collision_idx) {
  int i, j = 0, ext_idx = -1;
  char basen[9] = {0};
  char extn[4] = {0};

  /* explicitly preserve '.' and '..' */
  if (strcmp(lfn, ".") == 0 || strcmp(lfn, "..") == 0) {
    strcpy(sfn, lfn);
    return;
  }

  /* find the last dot for extension */
  for (i = 0; lfn[i] != 0; i++) {
    if (lfn[i] == '.')
      ext_idx = i;
  }

  /* copy valid chars to basen (max 8) */
  for (i = 0; lfn[i] != 0 && i != ext_idx && j < 8; i++) {
    char c = lfn[i];
    if (c == ' ' || c == '.' || c == '+' || c == ',' || c == ';' || c == '=' ||
        c == '[' || c == ']')
      continue; /* DOS invalid chars */
    basen[j++] = upchar(c);
  }

  /* copy valid chars to extn (max 3) */
  if (ext_idx >= 0) {
    j = 0;
    for (i = ext_idx + 1; lfn[i] != 0 && j < 3; i++) {
      char c = lfn[i];
      if (c == ' ' || c == '.' || c == '+' || c == ',' || c == ';' ||
          c == '=' || c == '[' || c == ']')
        continue;
      extn[j++] = upchar(c);
    }
  }

  /* handle ~1 collision if original was truncated or had invalid chars/spaces
   */
  /* simple heuristic: always ~n if lfn != sfn (this is simplified, we apply it
   * when requested) */
  if (collision_idx > 0) {
    char suffix[6];
    int suflen = snprintf(suffix, sizeof(suffix), "~%d", collision_idx);
    int baselen = strlen(basen);
    if (baselen + suflen > 8) {
      baselen = 8 - suflen;
    }
    snprintf(basen + baselen, 9 - baselen, "%s", suffix);
  }

  /* format into 8.3 */
  if (extn[0] != 0) {
    sprintf(sfn, "%s.%s", basen, extn);
  } else {
    sprintf(sfn, "%s", basen);
  }
}

void filename2fcb(char *d, const char *s) {
  int i;
  /* fill the FCB block with spaces */
  for (i = 0; i < 11; i++)
    d[i] = ' ';
  /* cover '.' and '..' entries */
  for (i = 0; i < 8; i++) {
    if (s[i] != '.')
      break;
    d[i] = '.';
  }
  /* fill in the filename, up to 8 chars or first dot, whichever comes first.
   * A '*' is a wildcard for "all remaining positions", expanded to '?' up to
   * the end of the field -- the standard DOS FCB expansion (INT 21h/AH=29h).
   * Search masks can arrive unexpanded (e.g. "*.*") from callers that bypass
   * DOS's normal path processing, such as 4DOS's DIR routed through the "find
   * first without CDS" (INT 2Fh/1119h) path. Real filenames never contain '*',
   * so this stays a no-op for actual names. */
  for (; i < 8; i++) {
    if (s[i] == '*') {
      for (; i < 8; i++)
        d[i] = '?';
      break;
    }
    if ((s[i] == '.') || (s[i] == 0))
      break;
    d[i] = upchar(s[i]);
  }
  /* fast forward to either the first dot or NULL-terminator */
  while ((*s != '.') && (*s != 0))
    s++;
  if (*s == 0)
    return;
  s++; /* skip the dot */
  /* fill in the extension */
  d += 8;
  for (i = 0; i < 3; i++) {
    if (s[i] == '*') { /* wildcard: fill the rest of the extension with '?' */
      for (; i < 3; i++) {
        *d = '?';
        d++;
      }
      break;
    }
    if ((s[i] == '.') || (s[i] == 0))
      break;
    *d = upchar(s[i]);
    d++;
  }
}

/* converts a time_t into a DWORD with DOS (FAT-style) timestamp bits
               24                16                 8                 0
+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
|Y|Y|Y|Y|Y|Y|Y|M| |M|M|M|D|D|D|D|D| |h|h|h|h|h|m|m|m| |m|m|m|s|s|s|s|s|
+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
 \___________/\________/\_________/ \________/\____________/\_________/
    year        month       day        hour       minute      seconds */
static unsigned long time2dos(time_t t) {
  unsigned long res;
  struct tm *ltime;
  ltime = localtime(&t);
  res = ltime->tm_year -
        80; /* tm_year is years from 1900, while FAT needs years from 1980 */
  res <<= 4;
  res |=
      ltime->tm_mon + 1; /* tm_mon is in range 0..11 while FAT expects 1..12 */
  res <<= 5;
  res |= ltime->tm_mday;
  res <<= 5;
  res |= ltime->tm_hour;
  res <<= 6;
  res |= ltime->tm_min;
  res <<= 5;
  res |= (ltime->tm_sec >> 1); /* DOS stores seconds divided by two */
  return (res);
}

/* converts a time_t into a Windows FILETIME (number of 100-nanosecond intervals
 * since 1601-01-01 00:00 UTC). The Unix epoch (1970-01-01) is 11644473600
 * seconds after the FILETIME epoch. Used by the LFN FindFirst/Next replies so
 * the DOS client can hand a WIN32_FIND_DATA back without any date math. */
static unsigned long long time2filetime(time_t t) {
  struct tm *lt = localtime(&t);
  long off = (lt != NULL) ? lt->tm_gmtoff : 0;
  unsigned long long ft;
  /* time2dos() encodes LOCAL wall-clock; to keep the dual-emit contract (the
   * client picks DOS-packed or FILETIME per SI and gets the SAME instant), add
   * the local UTC offset here so the FILETIME's wall-clock matches. */
  ft = (unsigned long long)((long long)t + off) + 11644473600ULL;
  ft *= 10000000ULL;
  return (ft);
}

/* match FCB-style filename to a FCB-style mask ("FILE0001???"), returns 0 if
 * matching, non-zero otherwise - a FCB block is *exactly* 11 bytes long */
static int matchfile2mask(char *msk, const char *fil) {
  int i;
  /* compare filename to mask */
  for (i = 0; i < 11; i++) {
    if ((upchar(fil[i]) != upchar(msk[i])) && (msk[i] != '?'))
      return (-1);
  }
  return (0);
}

/* render an 11-byte FCB name ("MYLONGFITXT") as a display name
 * ("MYLONGFI.TXT", ASCIZ, d must hold 13 bytes) for long-mask matching */
static void fcb2display(char *d, const char *fcb) {
  int i, k = 0;
  for (i = 0; i < 8; i++) {
    if (fcb[i] == ' ')
      break;
    d[k++] = fcb[i];
  }
  if (fcb[8] != ' ') {
    d[k++] = '.';
    for (i = 8; i < 11; i++) {
      if (fcb[i] == ' ')
        break;
      d[k++] = fcb[i];
    }
  }
  d[k] = 0;
}

/* Win95-style wildcard match of an LFN mask against a LONG filename:
 * case-insensitive, '?' matches exactly one character, '*' matches any run of
 * characters INCLUDING dots (RBIL, INT 21h/AX=714Eh). Callers normalize a
 * whole-mask "*.*" to "*" beforehand (Win95: "*.*" == "*" == everything).
 * Returns 0 on match, non-zero otherwise. Iterative two-pointer backtracking
 * (O(n*m)) so adversarial wire masks cannot blow the stack or the clock. */
static int matchlfn2mask(const char *msk, const char *fil) {
  const char *m = msk, *f = fil;
  const char *star_m = NULL, *star_f = NULL;
  for (;;) {
    if (*f == 0) {
      while (*m == '*')
        m++;
      return ((*m == 0) ? 0 : -1);
    }
    if ((*m == '?') || (upchar(*m) == upchar(*f))) {
      m++;
      f++;
    } else if (*m == '*') {
      star_m = m;
      m++;
      star_f = f;
    } else if (star_m != NULL) {
      m = star_m + 1;
      star_f++;
      f = star_f;
    } else {
      return (-1);
    }
  }
}

/* provides DOS-like attributes for item i, as well as size, filling fprops
 * accordingly. returns item's attributes or 0xff on error.
 * DOS attr flags: 1=RO 2=HID 4=SYS 8=VOL 16=DIR 32=ARCH 64=DEVICE */
unsigned char getitemattr(char *i, struct fileprops *fprops,
                          unsigned char fatflag) {
  uint32_t attr;
  int fd;
  struct stat statbuf;
  if (stat(i, &statbuf) != 0)
    return (0xff); /* error (probably doesn't exist) */
  /* zero out fprops and fill it out */
  if (fprops != NULL) {
    char *fname = i;
    char *ptr;
    /* set fname to the file part of i */
    for (ptr = i; *ptr != 0; ptr++) {
      if (((*ptr == '/') || (*ptr == '\\')) && (*(ptr + 1) != 0))
        fname = ptr + 1;
    }
    /* zero out struct and set timestamp & fcbname */
    memset(fprops, 0, sizeof(struct fileprops));
    fprops->ftime = time2dos(statbuf.st_mtime);
    fprops->filetime = time2filetime(statbuf.st_mtime);
    filename2fcb(fprops->fcbname, fname);
  }
  /* is this is a directory? */
  if (S_ISDIR(statbuf.st_mode)) {
    if (fprops != NULL)
      fprops->fattr = 16;
    return (16);
  }
  /* not a directory, set size */
  if (fprops != NULL)
    fprops->fsize = statbuf.st_size;
  /* if not a FAT drive, return a fake attribute of 0x20 (archive) */
  if (fatflag == 0)
    return (0x20);
#ifdef __linux__
  /* try to fetch DOS attributes by calling the FAT IOCTL API */
  fd = open(i, O_RDONLY);
  if (fd == -1)
    return (0xff);
  if (ioctl(fd, (int)FAT_IOCTL_GET_ATTRIBUTES, &attr) < 0) {
    fprintf(stderr, "Failed to fetch attributes of '%s'\n", i);
    close(fd);
    return (0);
  } else {
    close(fd);
    if (fprops != NULL)
      fprops->fattr = attr;
    return (attr);
  }
#else
  /* On non-Linux, simulate archive bit for all FAT formatted files as fallback
   */
  return (0x20);
#endif
}

/* set attributes fattr on file i. returns 0 on success, non-zero otherwise. */
int setitemattr(char *i, unsigned char fattr) {
#ifdef __linux__
  int fd, res;
  fd = open(i, O_RDONLY);
  if (fd == -1)
    return (-1);
  res = ioctl(fd, (int)FAT_IOCTL_SET_ATTRIBUTES, &fattr);
  close(fd);
  if (res < 0)
    return (-1);
  return (0);
#else
  /* On non-Linux systems, we do not support setting DOS FAT attributes natively
   */
  return (0);
#endif
}

/* directory entry used for deterministic SFN (~N) assignment, shared between
 * gendirlist() and resolve_sfn_in_dir() */
struct sfn_entry {
  char lfn[256];   /* real on-disk name, UTF-8 (for out_real / the fs path) */
  char cp437[256]; /* same name in the active OEM codepage (wire + alias in) */
  char sfn[14];
};

/* qsort() comparators. A stable, deterministic name order is REQUIRED so that
 * gendirlist() and resolve_sfn_in_dir() assign identical ~N short-name
 * collision suffixes to the same long name. readdir() does not guarantee the
 * same order across two scans of one directory, so without sorting a short
 * name presented by FindFirst could resolve to a DIFFERENT real file on the
 * follow-up open/create -- a wrong-file / data-corruption hazard. */
static int cmp_names(const void *a, const void *b) {
  return (strcmp(*(const char *const *)a, *(const char *const *)b));
}

static int cmp_sfn_entry(const void *a, const void *b) {
  return (strcmp(((const struct sfn_entry *)a)->lfn,
                 ((const struct sfn_entry *)b)->lfn));
}

/* generates a directory listing for *root and returns the number of file
 * system entries, or a negative value on error */
static long gendirlist(struct sfsdb *root, unsigned char fatflag,
                       const char *vollabel, int is_root) {
  char fullpath[1024];
  int fullpathoffset;
  struct dirent *diridx;
  DIR *dp;
  struct sdirlist *lastnode = NULL, *newnode, *checknode;
  long res = 0;
  freedirlist(root->dirlist);
  root->dirlist = NULL;
  dp = opendir(root->name);
  if (dp == NULL)
    return (-1);
  fullpathoffset = sprintf(fullpath, "%s/", root->name);

  /* Inject the synthetic volume label only in the root directory AND only when
     an explicit label was configured (opt-in). Rationale: under IBM PC DOS the
     synthetic VOL makes DIR's label-phase FindFirst (attr 0x08) succeed, after
     which PC-DOS never issues the file-phase FindFirst and the listing comes
     back empty (MS-DOS/FreeDOS/NC are unaffected). Making the VOL opt-in lets a
     label-less mount behave like a real label-less drive, which PC-DOS DIR
     handles normally. (Previously this also fell back to the directory basename
     when no label was set, so a VOL was always injected.) */
  if (is_root && vollabel != NULL && vollabel[0] != 0) {
    char *basename = root->name;
    char *p;
    for (p = root->name; *p != 0; p++) {
      if (*p == '/' || *p == '\\')
        basename = p + 1;
    }

    /* Only if we found a valid basename or have a custom label */
    if (*basename != 0 || (vollabel != NULL && vollabel[0] != 0)) {
      newnode = calloc(1, sizeof(struct sdirlist));
      if (newnode != NULL) {
        char volname[12];
        char c;
        int i;
        /* format as 11-char volume label, no extension dot */
        for (i = 0; i < 11; i++)
          volname[i] = ' ';

        /* Use custom volume label if provided, else uppercase basename */
        if (vollabel != NULL && vollabel[0] != 0) {
          for (i = 0; i < 11 && vollabel[i] != 0; i++) {
            c = vollabel[i];
            if (c >= 'a' && c <= 'z')
              c -= ('a' - 'A');
            volname[i] = c;
          }
        } else {
          for (i = 0; i < 11 && basename[i] != 0; i++) {
            c = basename[i];
            if (c >= 'a' && c <= 'z')
              c -= ('a' - 'A');
            volname[i] = c;
          }
        }
        volname[11] = 0;

        memset(&(newnode->fprops), 0, sizeof(struct fileprops));
        memcpy(newnode->fprops.fcbname, volname, 11);
        newnode->fprops.fattr = 0x08; /* FAT_VOL */
        newnode->fprops.ftime = 0;    /* Optional for VOL */
        newnode->fprops.fsize = 0;

        newnode->sfn_name[0] =
            0; /* Do not assign basename; prevents artificial DOS collisions
                  with actual subdirectories */

        root->dirlist = newnode;
        lastnode = newnode;
        res++;
      }
    }
  }

  /* Collect all directory entries first, then process them in a deterministic
   * (sorted) order so that ~N short-name collision suffixes are assigned
   * identically here and in resolve_sfn_in_dir() (see cmp_names note above). */
  {
    char **names = NULL;
    long ncount = 0, ncap = 0, ni;

    while ((diridx = readdir(dp)) != NULL) {
      char *dup;
      if (ncount == ncap) {
        char **tmp;
        ncap = (ncap == 0) ? 64 : ncap * 2;
        tmp = realloc(names, ncap * sizeof(char *));
        if (tmp == NULL)
          break; /* out of mem: proceed with what we collected so far */
        names = tmp;
      }
      dup = strdup(diridx->d_name);
      if (dup == NULL)
        break;
      names[ncount++] = dup;
    }
    closedir(dp);

    if (names != NULL)
      qsort(names, (size_t)ncount, sizeof(char *), cmp_names);

    for (ni = 0; ni < ncount; ni++) {
      int collision_idx = 0;
      char tempsfn[14];
      char cp437[256];

      newnode = calloc(1, sizeof(struct sdirlist));
      if (newnode == NULL) {
        fprintf(stderr, "ERROR: out of mem!");
        break;
      }
      sprintf(fullpath + fullpathoffset, "%s", names[ni]);

      /* wire/OEM form of the name -- the 8.3 alias and the long name we hand
       * to DOS must be in the DOS codepage, not UTF-8 (increment 6) */
      cp_disk2wire(names[ni], cp437, sizeof(cp437));

      /* Generate unique SFN */
      do {
        int collision_found = 0;
        lfn2sfn(tempsfn, cp437, collision_idx);
        for (checknode = root->dirlist; checknode != NULL;
             checknode = checknode->next) {
          if (strcmp(checknode->sfn_name, tempsfn) == 0) {
            collision_found = 1;
            break;
          }
        }
        if (!collision_found)
          break;
        collision_idx++;
      } while (collision_idx < 9999);

      strcpy(newnode->sfn_name, tempsfn);
      /* keep the long name too (wire/OEM form), for native LFN ops */
      snprintf(newnode->lfn_name, sizeof(newnode->lfn_name), "%s", cp437);

      /* When getting attributes, use the generated SFN so FCB is based on SFN */
      getitemattr(fullpath, &(newnode->fprops), fatflag);
      /* Override fcbname in fprops with the generated SFN, not the long name */
      filename2fcb(newnode->fprops.fcbname, tempsfn);

      /* add new node to linked list */
      if (lastnode == NULL) {
        root->dirlist = newnode;
      } else {
        lastnode->next = newnode;
      }
      lastnode = newnode;
      res++;
    }

    /* free the temporary name array */
    for (ni = 0; ni < ncount; ni++)
      free(names[ni]);
    free(names);
  }
  return (res);
}

/* searches for file matching the FCB-style template fcbtmpl in directory dss
 * (dss is the starting sector of the directory, as obtained via getitemss) with
 * AT MOST attributes attr, fills 'out' with the nth match. returns 0 on
 * success, non-zero otherwise. *nth is updated with the nth id of the file that
 * matched.
 * lfnmask: optional Win95-style long-name mask (NULL for the legacy 8.3
 * opcodes). When set, an entry matches if EITHER its 8.3 name matches fcbtmpl
 * OR its long name matches lfnmask (Win95 FindFirstFile matches either name);
 * this is what lets an exact long leaf like "Games List.txt" (whose naive
 * FCB-ization differs from its ~N/stripped SFN alias) be found at all. */
int findfile(struct fileprops *f, unsigned short dss, char *fcbtmpl,
             const char *lfnmask, unsigned char attr, unsigned short *nth,
             int flags, const char *vollabel, char *out_lfn) {
  int n = 0;
  struct sdirlist *dirlist;
  if (out_lfn != NULL) /* define it on every return path, incl. early errors */
    out_lfn[0] = 0;
  /* Guard against an evicted/empty directory slot: the fsdb cache can have
   * been reclaimed (getitemss eviction) between FindFirst and FindNext.
   * Without this, gendirlist() below would opendir(NULL) and the
   * isroot()/sstoitem() caller would dereference NULL. Report 'no more
   * files' instead of crashing or scanning the wrong directory. */
  if (fsdb[dss].name == NULL)
    return (-1);
  /* Keep this directory 'hot' so it is not evicted from the cache while we
   * are still walking it across FindFirst/FindNext. FindNext does not pass
   * through getitemss(), so its lastused would otherwise go stale and make
   * the slot a prime eviction target mid-enumeration. */
  fsdb[dss].lastused = time(NULL);
  /* recompute the dir listing if operation is FFirst (nth == 0) or if no
   * cache found */
  if ((*nth == 0) || (fsdb[dss].dirlist == NULL)) {
    long count =
        gendirlist(&(fsdb[dss]), flags & FFILE_ISFAT, vollabel,
                   flags & FFILE_ISROOT);
    if (count < 0) {
      fprintf(stderr, "Error: failed to scan dir '%s'\n", fsdb[dss].name);
      return (-1);
#ifdef DEBUG
    } else {
      DBG("scanned dir '%s' and found %ld items\n", fsdb[dss].name, count);
      for (dirlist = fsdb[dss].dirlist; dirlist != NULL;
           dirlist = dirlist->next) {
        DBG("  '%s' attr %02Xh (%ld bytes)\n", dirlist->fprops.fcbname,
            dirlist->fprops.fattr, dirlist->fprops.fsize);
      }
#endif
    }
  }
  /* */
  for (dirlist = fsdb[dss].dirlist; dirlist != NULL; dirlist = dirlist->next) {
    /* forward to where we need to start listing */
    n++;
    if (n <= *nth)
      continue;
    /* skip '.' and '..' items if directory is root */
    if ((dirlist->fprops.fcbname[0] == '.') && (flags & FFILE_ISROOT))
      continue;
    /* if no match, continue. With an LFN mask present (LFN opcodes from a
     * new client), Win95 semantics apply: the mask glob-matches against
     * EITHER name form (long name or displayed 8.3 alias). The FCB template
     * cannot express mid-name '*' (it expands to all-'?', matching
     * everything), so it is NOT consulted in that mode -- it remains the
     * matcher for the legacy 8.3 opcodes and old-client FindNext requests. */
    if (lfnmask != NULL) {
      char sfndisp[13];
      fcb2display(sfndisp, dirlist->fprops.fcbname);
      if ((matchlfn2mask(lfnmask, sfndisp) != 0) &&
          ((dirlist->lfn_name[0] == 0) ||
           (matchlfn2mask(lfnmask, dirlist->lfn_name) != 0)))
        continue;
    } else {
      if (matchfile2mask(fcbtmpl, dirlist->fprops.fcbname) != 0)
        continue;
    }
    /* do attributes match?
       DOS attribs: 1=RO 2=HID 4=SYS 8=VOL 16=DIR 32=ARCH 64=DEV */
    if (attr == 0x08) { /* I want VOL */
      if ((dirlist->fprops.fattr & 0x08) == 0)
        continue;
    } else { /* else return any file with at most the specified attributes */
      /* If the item is a VOL label, do NOT return it unless explicitly
       * requested above */
      if ((dirlist->fprops.fattr & 0x08) != 0)
        continue;
      if ((attr | (dirlist->fprops.fattr & 0x16)) != attr)
        continue;
    }
    break;
  }
  if (dirlist != NULL) {
    *nth = n;
    /* copy ONLY the fileprops (was sizeof(struct sdirlist), which overran 'f' --
     * now a hard overflow since sdirlist carries a 256-byte lfn_name) */
    memcpy(f, &(dirlist->fprops), sizeof(struct fileprops));
    /* for LFN callers, also hand back the real long name */
    if (out_lfn != NULL) {
      snprintf(out_lfn, 256, "%s", dirlist->lfn_name);
    }
    return (0);
  }
  if (out_lfn != NULL)
    out_lfn[0] = 0;
  return (-1);
}

/* creates or truncates a file f in directory d with attributes attr. returns 0
 * on success (and f filled), non-zero otherwise. */
int createfile(struct fileprops *f, char *d, char *fn, unsigned char attr,
               unsigned char fatflag) {
  char fullpath[1300]; /* dir (<=1023) + '/' + LFN leaf (<=255) + slack */
  FILE *fd;
  snprintf(fullpath, sizeof(fullpath), "%s/%s", d, fn);
  /* try to create/truncate the file */
  fd = fopen(fullpath, "wb");
  if (fd == NULL)
    return (-1);
  fclose(fd);

  /* ensure file is mutually writable by others on the host system too */
  chmod(fullpath, 0666);

  /* set attribs (only if FAT drive) */
  if (fatflag != 0) {
    if (setitemattr(fullpath, attr) != 0)
      fprintf(stderr, "Error: failed to set attribute %02Xh to '%s'\n", attr,
              fullpath);
  }
  /* collect and set attributes */
  getitemattr(fullpath, f, fatflag);
  return (0);
}

/* returns disks total size, in bytes, or 0 on error. also sets dfree to the
 * amount of available bytes */
unsigned long long diskinfo(char *path, unsigned long long *dfree) {
  struct statvfs buf;
  unsigned long long res;
  if (statvfs(path, &buf) != 0)
    return (0);
  res = buf.f_blocks;
  res *= buf.f_frsize;
  *dfree = buf.f_bfree;
  *dfree *= buf.f_bsize;
  return (res);
}

/* try to create directory, return 0 on success, non-zero otherwise */
int makedir(char *d) { return (mkdir(d, 0777)); }

/* try to remove directory, return 0 on success, non-zero otherwise */
int remdir(char *d) {
  struct stat st;
  if (lstat(d, &st) == 0 && S_ISLNK(st.st_mode)) {
    return unlink(d);
  }
  return (rmdir(d));
}

/* change to directory d, return 0 if worked, non-zero otherwise (used
 * essentially to check whether the directory exists or not) */
int changedir(char *d) { return (chdir(d)); }

#define READAHEAD_SIZE 65536
static unsigned char readahead_buff[READAHEAD_SIZE];
static unsigned short readahead_fss = 0xffff;
static unsigned long readahead_offset = 0;
static long readahead_len = 0;

/* reads len bytes from file starting at sector fss, from offset, writes to
 * buff. returns amount of bytes read or a negative value on error. */
long readfile(unsigned char *buff, unsigned short fss, unsigned long offset,
              unsigned short len) {
  long res;
  char *fname;
  FILE *fd;
  fname = fsdb[fss].name;
  if (fname == NULL)
    return (-1);

  /* check read-ahead cache hit */
  if (fss == readahead_fss && offset >= readahead_offset &&
      offset + len <= readahead_offset + readahead_len) {
    memcpy(buff, readahead_buff + (offset - readahead_offset), len);
    return len;
  }

  /* cache miss, fetch 64KB */
  fd = fopen(fname, "rb");
  if (fd == NULL)
    return (-1);
  if (fseek(fd, offset, SEEK_SET) != 0) {
    fclose(fd);
    return (-1);
  }

  readahead_fss = fss;
  readahead_offset = offset;
  readahead_len = fread(readahead_buff, 1, READAHEAD_SIZE, fd);
  fclose(fd);

  res = (readahead_len < len) ? readahead_len : len;

  if (res > 0) {
    memcpy(buff, readahead_buff, res);
  } else {
    readahead_len = 0; /* invalidate cache on read error/EOF */
    readahead_fss = 0xffff;
  }

  return (res);
}

/* writes len bytes from buff to file starting at sect fss, starting at
 * offset. returns amount of bytes written or a negative value on error. */
long writefile(unsigned char *buff, unsigned short fss, unsigned long offset,
               unsigned short len) {
  long res;
  char *fname;
  FILE *fd;
  fname = fsdb[fss].name;
  if (fname == NULL)
    return (-1);
  /* if len is 0, then it means "truncate" or "extend" ! */
  if (len == 0) {
    DBG("truncate '%s' to %lu bytes\n", fname, offset);
    if (truncate(fname, offset) != 0)
      fprintf(stderr, "Error: truncate() failed\n");
    return (0);
  }
  /* otherwise do a regular write */
  DBG("write %u bytes into file '%s' at offset %lu\n", len, fname, offset);
  fd = fopen(fname, "r+b");
  if (fd == NULL)
    return (-1);
  if (fseek(fd, offset, SEEK_SET) != 0) {
    DBG("fseek() to %lu failed!\n", offset);
    fclose(fd);
    return (-1);
  }
  res = fwrite(buff, 1, len, fd);
  fclose(fd);
  return (res);
}

/* remove all files matching the pattern, returns the number of removed files if
 * any found, or -1 on error or if no matching file found */
int delfiles(char *pattern) {
  unsigned int i, fileoffset = 0;
  int ispattern = 0;
  char patterncopy[512];
  char dirnamefcb[12];
  char *dir, *fil;
  char filfcb[12];
  struct dirent *diridx;
  DIR *dp;
  /* scan the pattern for '?' characters, and find where the file part starts,
   * also copy the pattern to patterncopy[] */
  for (i = 0; pattern[i] != 0; i++) {
    if (pattern[i] == '?')
      ispattern = 1;
    if (pattern[i] == '/')
      fileoffset = i;
    patterncopy[i] = pattern[i];
  }
  patterncopy[i] = 0;
  /* if regular file, delete it right away*/
  if (ispattern == 0) {
    if (unlink(pattern) != 0) {
      DBG("Error: failure to delete file '%s' (%s)\n", pattern,
          strerror(errno));
      return (-1);
    }
    return (1);
  }
  /* if pattern, get dir and fil parts and iterate over all directory */
  dir = patterncopy;
  patterncopy[fileoffset] = 0;
  fil = patterncopy + fileoffset + 1;
  filename2fcb(filfcb, fil);
  /* iterate over the directory and delete whatever is matching the pattern */
  dp = opendir(dir);
  if (dp == NULL)
    return (-1);
  for (;;) {
    diridx = readdir(dp);
    if (diridx == NULL)
      break;
    /* skip directories */
    if (diridx->d_type == DT_DIR)
      continue;
    /* if match, delete the file and continue */
    filename2fcb(dirnamefcb, diridx->d_name);
    if (matchfile2mask(filfcb, dirnamefcb) == 0) {
      char fname[512];
      sprintf(fname, "%s/%s", dir, diridx->d_name);
      if (unlink(fname) != 0)
        fprintf(stderr, "failed to delete '%s'\n", fname);
    }
  }
  closedir(dp);

  return (0);
}

/* rename fn1 into fn2 */
int renfile(char *fn1, char *fn2) { return (rename(fn1, fn2)); }

/* checks if a path resides on a FAT filesystem, returns 0 if so, non-zero
 * otherwise */
int isfat(char *d) {
#ifdef __linux__
  int fd;
  uint32_t volid;
  /* test if I can fetch the serial id through calling the FAT IOCTL API */
  fd = open(d, O_RDONLY);
  if (fd == -1)
    return (-1);
  if (ioctl(fd, (int)FAT_IOCTL_GET_VOLUME_ID, (int *)&volid) < 0) {
    close(fd);
    return (-1);
  }
  close(fd);
  return (0);
#else
  /* without Linux ioctls, fallback to treating it as non-FAT so attributes
   * aren't used */
  return (-1);
#endif
}

/* returns the size of an open file (or -1 on error) */
long getfopsize(unsigned short fss) {
  struct fileprops fprops;
  char *fname = fsdb[fss].name;
  if (fname == NULL)
    return (-1);
  if (getitemattr(fname, &fprops, 0) == 0xff)
    return (-1);
  return (fprops.fsize);
}

/* Helper to resolve a single SFN inside a dir to its actual local name.
 * If no match is found, just copy the target string back and assume it's new.
 */
/* Resolve ONE path component inside dir_path, Win95-style: the wire token is
 * matched case-insensitively against EITHER each entry's on-disk long name OR
 * its deterministic 8.3 alias. Aliases are generated in the same sorted order
 * as gendirlist() (same cmp + lfn2sfn + sequential ~N), so the ~N suffixes
 * agree with what FindFirst reports. The long-name match takes precedence.
 * On match: returns 0, fills out_real (exact on-disk bytes, buffer >= 256)
 * and, if out_sfn != NULL, the alias in display form ("LONGDI~1", >= 14).
 * Returns -1 when nothing matches (the caller picks its fallback). */
int resolve_component(const char *dir_path, const char *wire_name,
                      char *out_real, char *out_sfn) {
  struct sfn_entry *local_sfns;
  int capacity = 1024;
  DIR *dp;
  struct dirent *diridx;
  int collision_idx;
  char tempsfn[14];
  int count = 0;
  int i, j;
  int collision_found;
  int match = -1;

  local_sfns = malloc(capacity * sizeof(struct sfn_entry));
  if (local_sfns == NULL)
    return (-1);

  dp = opendir(dir_path);
  if (dp == NULL) {
    free(local_sfns);
    return (-1);
  }

  while ((diridx = readdir(dp)) != NULL) {
    /* Skip . and .. to save processing */
    if (strcmp(diridx->d_name, ".") == 0 || strcmp(diridx->d_name, "..") == 0)
      continue;

    if (count >= capacity) {
      struct sfn_entry *new_sfns;
      capacity *= 2;
      new_sfns = realloc(local_sfns, capacity * sizeof(struct sfn_entry));
      if (new_sfns == NULL) {
        break; /* Out of memory, process what we have so far */
      }
      local_sfns = new_sfns;
    }

    strcpy(local_sfns[count].lfn, diridx->d_name);
    cp_disk2wire(diridx->d_name, local_sfns[count].cp437,
                 sizeof(local_sfns[count].cp437));
    count++;
  }
  closedir(dp);

  /* Sort entries into the SAME deterministic order gendirlist() uses, so the
   * ~N collision suffixes assigned below match the ones FindFirst handed to
   * DOS (otherwise a short name could resolve to a different real file). */
  qsort(local_sfns, (size_t)count, sizeof(struct sfn_entry), cmp_sfn_entry);

  /* Generate every entry's deterministic alias (the collision loop needs all
   * earlier aliases anyway) */
  for (i = 0; i < count; i++) {
    collision_idx = 0;
    do {
      lfn2sfn(tempsfn, local_sfns[i].cp437, collision_idx);
      collision_found = 0;
      for (j = 0; j < i; j++) {
        if (strcmp(local_sfns[j].sfn, tempsfn) == 0) {
          collision_found = 1;
          break;
        }
      }
      if (!collision_found)
        break;
      collision_idx++;
    } while (collision_idx < 9999);
    strcpy(local_sfns[i].sfn, tempsfn);
  }

  /* Pass 1: case-insensitive LONG-name match (Win95 semantics; this is what
   * lets "\Long Dir Name\..." wire components reach the right inode even
   * when the case differs from disk). */
  for (i = 0; i < count; i++) {
    if (strcasecmp(local_sfns[i].cp437, wire_name) == 0) {
      match = i;
      break;
    }
  }
  /* Pass 2: alias match ("LONGDI~1" etc.) */
  if (match < 0) {
    for (i = 0; i < count; i++) {
      if (strcasecmp(local_sfns[i].sfn, wire_name) == 0) {
        match = i;
        break;
      }
    }
  }

  if (match >= 0) {
    strcpy(out_real, local_sfns[match].lfn);
    if (out_sfn != NULL)
      strcpy(out_sfn, local_sfns[match].sfn);
  }
  free(local_sfns);
  return ((match >= 0) ? 0 : -1);
}

static void resolve_sfn_in_dir(char *actual_name, const char *dir_path,
                               const char *target_sfn) {
  if (resolve_component(dir_path, target_sfn, actual_name, NULL) == 0)
    return;

  /* Not found -> return the requested name as the on-disk name (AL_CREATE will
   * create it). The wire carries OEM-codepage bytes, so convert to UTF-8 for
   * the Linux filesystem (increment 6); the result can be up to 3x longer, so
   * actual_name must be >= 768 bytes (resolve_path sizes it so). */
  cp_wire2disk(target_sfn, actual_name, 768);
  if (lowercase_mode) {
    int char_idx = 0;
    while (actual_name[char_idx]) {
      char c = actual_name[char_idx];
      if (c >= 'A' && c <= 'Z')
        actual_name[char_idx] = (char)(c + ('a' - 'A'));
      char_idx++;
    }
  }
}

#define RESOLVE_MAX 512

void resolve_path(char *resolved_path, const char *root, const char *dos_path) {
  char temp_path[1024];
  char current_dir[1024];
  char *token;
  char dos_copy[1024];
  char *p;
  char actual_name[768]; /* wire->disk (cp_wire2disk) can 3x-expand a create leaf */

  snprintf(current_dir, sizeof(current_dir), "%s", root);
  snprintf(dos_copy, sizeof(dos_copy), "%s", dos_path);

  /* Remove leading slashes/backslashes */
  p = dos_copy;
  while (*p == '\\' || *p == '/')
    p++;

  /* Handle root effectively */
  if (*p == 0) {
    snprintf(resolved_path, RESOLVE_MAX, "%s", root);
    return;
  }

  token = strtok(p, "\\/");
  while (token != NULL) {
    resolve_sfn_in_dir(actual_name, current_dir, token);

    /* Append to current_dir, but never overflow it (long LFN components could
     * otherwise push the assembled path past the buffer). If it would, stop
     * extending and use what we have. */
    if (strlen(current_dir) + strlen(actual_name) + 2 >= RESOLVE_MAX)
      break;
    snprintf(temp_path, sizeof(temp_path), "%s/%s", current_dir, actual_name);
    strcpy(current_dir, temp_path);

    token = strtok(NULL, "\\/");
  }

  /* current_dir is now < RESOLVE_MAX; safe for every caller's buffer */
  snprintf(resolved_path, RESOLVE_MAX, "%s", current_dir);
}

/* Translate a wire DOS path (long / alias / mixed components) into the
 * equivalent fully-aliased 8.3 path (e.g. "\LONGDI~1\MYLONGFI.TXT"), for
 * 7160h CL=1 and for the client's classic pass-downs. Walks component-wise
 * with resolve_component(). A nonexistent LEAF is kept (uppercased) if it is
 * its own 8.3 alias -- callers may be about to create it -- otherwise error.
 * Returns 0 on success or a DOS error code: 2 = invalid component (leaf not
 * representable), 3 = path not found (intermediate component missing).
 * out must hold >= 261 bytes. */
int path_to_sfn(char *out, const char *root, const char *dos_path) {
  char current_dir[RESOLVE_MAX];
  char dos_copy[520];
  char real[256], sfn[14], tmp[14];
  char *token, *next;
  int outlen = 0, i;

  snprintf(current_dir, sizeof(current_dir), "%s", root);
  snprintf(dos_copy, sizeof(dos_copy), "%s", dos_path);
  out[0] = 0;

  token = dos_copy;
  while ((*token == '\\') || (*token == '/'))
    token++;
  token = strtok(token, "\\/");
  if (token == NULL) { /* root */
    strcpy(out, "\\");
    return (0);
  }
  while (token != NULL) {
    next = strtok(NULL, "\\/");
    if ((strcmp(token, ".") == 0) || (strcmp(token, "..") == 0)) {
      /* pass dot-dirs through verbatim (DOS usually pre-resolves these) */
      snprintf(real, sizeof(real), "%s", token);
      snprintf(sfn, sizeof(sfn), "%s", token);
    } else if (resolve_component(current_dir, token, real, sfn) != 0) {
      if (next != NULL)
        return (3); /* missing intermediate directory: path not found */
      /* nonexistent leaf: acceptable only if it is its own 8.3 alias */
      lfn2sfn(tmp, token, 0);
      if (strcasecmp(tmp, token) != 0)
        return (2); /* not representable as 8.3: invalid component */
      snprintf(real, sizeof(real), "%s", token);
      snprintf(sfn, sizeof(sfn), "%s", tmp);
    }
    if (outlen + (int)strlen(sfn) + 2 >= 261)
      return (3);
    out[outlen++] = '\\';
    for (i = 0; sfn[i] != 0; i++)
      out[outlen++] = sfn[i];
    out[outlen] = 0;
    if (strlen(current_dir) + strlen(real) + 2 < sizeof(current_dir)) {
      strcat(current_dir, "/");
      strcat(current_dir, real);
    }
    token = next;
  }
  return (0);
}

/* Reverse translation: wire DOS path (aliases / mixed) -> path with the REAL
 * long component names (e.g. "\LONGDI~1\MYLONGFI.TXT" ->
 * "\Long Dir Name\my long file.txt"), for 7160h CL=2 (display: long cwd,
 * prompts). Forgiving: unmatched components pass through verbatim (display
 * use; a stale alias simply shows as itself). out must hold >= 261 bytes. */
int path_to_lfn(char *out, const char *root, const char *dos_path) {
  char current_dir[RESOLVE_MAX];
  char dos_copy[520];
  char real[256];
  char *token;
  int outlen = 0, i;

  snprintf(current_dir, sizeof(current_dir), "%s", root);
  snprintf(dos_copy, sizeof(dos_copy), "%s", dos_path);
  out[0] = 0;

  token = dos_copy;
  while ((*token == '\\') || (*token == '/'))
    token++;
  token = strtok(token, "\\/");
  if (token == NULL) {
    strcpy(out, "\\");
    return (0);
  }
  while (token != NULL) {
    char wire[256];
    int found = 0;
    if ((strcmp(token, ".") != 0) && (strcmp(token, "..") != 0) &&
        (resolve_component(current_dir, token, real, NULL) == 0))
      found = 1;
    if (found) {
      /* `out` (headed for the DOS client) gets the OEM/wire form of the real
       * long name; current_dir keeps the UTF-8 on-disk name for the next
       * lookup (increment 6) */
      cp_disk2wire(real, wire, sizeof(wire));
    } else {
      snprintf(real, sizeof(real), "%s", token); /* verbatim (already OEM) */
      snprintf(wire, sizeof(wire), "%s", token);
    }
    if (outlen + (int)strlen(wire) + 2 >= 261)
      break;
    out[outlen++] = '\\';
    for (i = 0; wire[i] != 0; i++)
      out[outlen++] = wire[i];
    out[outlen] = 0;
    if (strlen(current_dir) + strlen(real) + 2 < sizeof(current_dir)) {
      strcat(current_dir, "/");
      strcat(current_dir, real);
    }
    token = strtok(NULL, "\\/");
  }
  return (0);
}

/* Computes the deterministic 8.3 SFN alias that target_lfn has (or would get)
 * inside dir_path. MUST stay byte-for-byte in sync with gendirlist() and
 * resolve_sfn_in_dir(): identical readdir() collection, identical cmp_sfn_entry
 * sort, identical lfn2sfn() + sequential ~N collision loop. That shared
 * algorithm is what guarantees a freshly created long file reports the same
 * short name a later FindFirst computes for it. */
void sfn_for_name_in_dir(const char *dir_path, const char *target_lfn,
                         char *out_sfn) {
  struct sfn_entry *list;
  int capacity = 1024, count = 0, i, j;
  DIR *dp;
  struct dirent *diridx;
  char tempsfn[14];
  int collision_idx, collision_found;

  /* default fallback (also covers the malloc/opendir failure paths). The
   * target comes from the on-disk (UTF-8) name; the 8.3 alias must be built
   * from its OEM/wire form to stay in sync with gendirlist()/resolve_component()
   * (increment 6). */
  {
    char t_cp[256];
    cp_disk2wire(target_lfn, t_cp, sizeof(t_cp));
    lfn2sfn(out_sfn, t_cp, 0);
  }

  list = malloc(capacity * sizeof(struct sfn_entry));
  if (list == NULL)
    return;
  dp = opendir(dir_path);
  if (dp == NULL) {
    free(list);
    return;
  }
  while ((diridx = readdir(dp)) != NULL) {
    if (strcmp(diridx->d_name, ".") == 0 || strcmp(diridx->d_name, "..") == 0)
      continue;
    if (count >= capacity) {
      struct sfn_entry *grown;
      capacity *= 2;
      grown = realloc(list, capacity * sizeof(struct sfn_entry));
      if (grown == NULL)
        break;
      list = grown;
    }
    snprintf(list[count].lfn, sizeof(list[count].lfn), "%s", diridx->d_name);
    cp_disk2wire(diridx->d_name, list[count].cp437, sizeof(list[count].cp437));
    count++;
  }
  closedir(dp);

  qsort(list, (size_t)count, sizeof(struct sfn_entry), cmp_sfn_entry);

  for (i = 0; i < count; i++) {
    collision_idx = 0;
    do {
      lfn2sfn(tempsfn, list[i].cp437, collision_idx);
      collision_found = 0;
      for (j = 0; j < i; j++) {
        if (strcmp(list[j].sfn, tempsfn) == 0) {
          collision_found = 1;
          break;
        }
      }
      if (!collision_found)
        break;
      collision_idx++;
    } while (collision_idx < 9999);
    strcpy(list[i].sfn, tempsfn);
    if (strcasecmp(list[i].lfn, target_lfn) == 0) {
      strcpy(out_sfn, tempsfn);
      free(list);
      return;
    }
  }
  free(list);
}
