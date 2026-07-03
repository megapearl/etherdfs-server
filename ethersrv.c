/*
 * ethersrv-linux is serving files through the EtherDFS protocol. Runs on
 * Linux.
 *
 * http://etherdfs.sourceforge.net
 *
 * ethersrv-linux is distributed under the terms of the MIT License, as listed
 * below.
 *
 * Copyright (C) 2017, 2018 Mateusz Viste
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <arpa/inet.h> /* htons() */
#include <endian.h>    /* le16toh(), le32toh() */
#include <errno.h>
#include <ifaddrs.h> /* getifaddrs() */
#include <limits.h>  /* PATH_MAX and such */
#include <net/if.h>
#include <signal.h>
#include <stdint.h> /* uint16_t, uint32_t */
#include <stdio.h>
#include <stdlib.h> /* realpath() */
#include <string.h> /* mempcy() */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>   /* time() */
#include <unistd.h> /* close(), getopt(), optind */

#ifdef __linux__
#include <linux/if_packet.h>
#include <netinet/ether.h> /* ETH_ALEN on Linux */

#else
#include <net/ethernet.h> /* ETHER_ADDR_LEN on BSD/macOS */
#include <net/if_dl.h>    /* sockaddr_dl on BSD/macOS */

#ifndef ETH_ALEN
#define ETH_ALEN ETHER_ADDR_LEN
#endif
#endif
#include <pcap.h>

#include "debug.h"
#include "fs.h"
#include "lock.h"

/* program version */
#ifndef PVER
#define PVER "v0.3.11-PRO"
#endif

/* protocol version (single byte, must be in sync with etherdfs) */
#define PROTOVER 2

/* answer cache - last answers sent to clients - used if said client didn't
 * receive my answer, and re-sends his requests so I don't process this
 * request again (which might be dangerous in case of write requests, like
 * write to file, delete file, rename file, etc. For every client that ever
 * sent me a query, there is exactly one entry in the cache. */
#define ANSWCACHESZ 16
static struct struct_answcache {
  unsigned char frame[1520]; /* entire frame that was sent (first 6 bytes is the
                                client's mac) */
  time_t timestamp;   /* time of answer (so if cache full I can drop oldest) */
  unsigned short len; /* frame's length */
} answcache[ANSWCACHESZ];

/* all the calls I support are in the range AL=0..2Eh - the list below serves
 * as a convenience to compare AL (subfunction) values */
enum AL_SUBFUNCTIONS {
  AL_INSTALLCHK = 0x00,
  AL_RMDIR = 0x01,
  AL_MKDIR = 0x03,
  AL_CHDIR = 0x05,
  AL_CLSFIL = 0x06,
  AL_CMMTFIL = 0x07,
  AL_READFIL = 0x08,
  AL_WRITEFIL = 0x09,
  AL_LOCKFIL = 0x0A,
  AL_UNLOCKFIL = 0x0B,
  AL_DISKSPACE = 0x0C,
  AL_SETATTR = 0x0E,
  AL_GETATTR = 0x0F,
  AL_RENAME = 0x11,
  AL_DELETE = 0x13,
  AL_OPEN = 0x16,
  AL_CREATE = 0x17,
  AL_FINDFIRST = 0x1B,
  AL_FINDNEXT = 0x1C,
  AL_SKFMEND = 0x21,
  AL_UNKNOWN_2D = 0x2D,
  AL_SPOPNFIL = 0x2E,
  /* additive LFN (long filename) opcodes - new namespace at 0x40+, kept
   * separate from the legacy 8.3 ops; an old server hits the terminal
   * "else return(-1)" and silently drops them (forward-safe). */
  AL_LFN_CAPS = 0x40,
  AL_LFN_FINDFIRST = 0x41,
  AL_LFN_FINDNEXT = 0x42,
  AL_LFN_OPEN = 0x43,
  AL_LFN_CREATE = 0x44,
  AL_LFN_RENAME = 0x47,
  AL_LFN_MKDIR = 0x49,
  AL_LFN_TRUENAME = 0x4D,
  AL_LFN_VOLINFO = 0x4E,
  AL_UNKNOWN = 0xFF
};

/* an array with flags indicating whether given drive is FAT-based or not */
static unsigned char drivesfat[26]; /* 0 if not, non-zero otherwise */

/* the flag is set when ethersrv is expected to terminate */
static sig_atomic_t volatile terminationflag = 0;
char custom_vol_label[12] = {0}; /* holds an optional custom volume label */

/* runtime debug and delay parameters */
int debug_level = 0;
int readonly_mode = 0;
int lowercase_mode = 0;
unsigned char allowed_mac[6];
int allowed_mac_set = 0;
unsigned int target_delay_ms = 0;

/* live throughput statistics */
unsigned long long stat_bytes_read = 0;
unsigned long long stat_bytes_written = 0;

void sigcatcher(int sig) {
  switch (sig) {
  case SIGTERM:
  case SIGQUIT:
  case SIGINT:
    terminationflag = 1;
    break;
  default:
    break;
  }
}

/* returns a printable version of a FCB block (ie. with added null terminator),
 * this is used only by debug routines */
static char *pfcb(char *s) {
  static char r[12] = "FILENAMEEXT";
  memcpy(r, s, 11);
  return (r);
}

/* turns a character c into its low-case variant */
static char lochar(char c) {
  if ((c >= 'A') && (c <= 'Z'))
    c += ('a' - 'A');
  return (c);
}

/* turns a string into all-lower-case characters, up to n chars max */
static void lostring(char *s, int n) {
  while ((n-- != 0) && (*s != 0)) {
    *s = lochar(*s);
    s++;
  }
}

/* finds the cache entry related to given client */
static struct struct_answcache *findcacheentry(unsigned char *clientmac) {
  int i, oldest = 0;
  /* iterate through cache entries until matching mac is found */
  for (i = 0; i < ANSWCACHESZ; i++) {
    if (memcmp(answcache[i].frame, clientmac, 6) == 0) {
      return (&(answcache[i])); /* found! */
    }
    /* is this the oldest entry? remember it. */
    if (answcache[i].timestamp < answcache[oldest].timestamp)
      oldest = i;
  }
  /* if nothing found, over-write the oldest entry */
  return (&(answcache[oldest]));
}

/* checks wheter dir is belonging to the root directory. returns 0 if so, 1
 * otherwise */
static int isroot(char *root, char *dir) {
  /* dir may be NULL if the directory's cache slot was evicted between
   * FindFirst and FindNext (sstoitem() then returns NULL). Treat that as
   * 'not root' instead of dereferencing NULL; findfile() will subsequently
   * report 'no more files' for the missing slot. */
  if ((root == NULL) || (dir == NULL))
    return (0);
  /* fast-forward past the shared root prefix */
  while ((*root != 0) && (*dir != 0)) {
    root++;
    dir++;
  }
  /* skip any leading / left on the directory tail */
  while (*dir == '/')
    dir++;
  /* If ANYTHING remains after the root prefix (and its slash), this is a
   * subdirectory -- root iff the tail is empty. The previous version only
   * treated a tail CONTAINING a further '/' as non-root, which wrongly
   * classified every first-level subdir ("<root>/uploads" -> tail "uploads",
   * no slash) as root and thus stripped its '.'/'..' entries -- making an
   * empty first-level subdir list as zero items ("File not found"). */
  return ((*dir == 0) ? 1 : 0);
}

/* explode a full X:\DIR\FILE????.??? search path into directory and mask */
static void explodepath(char *dir, char *file, char *source, int sourcelen) {
  int i, lastbackslash, filelen;
  if (sourcelen < 0)
    sourcelen = 0;
  /* if drive present, skip it (guard the source[1] read for short input) */
  if ((sourcelen >= 2) && (source[1] == ':')) {
    source += 2;
    sourcelen -= 2;
  }
  /* find last slash or backslash and copy source into dir up to this last
   * backslash */
  lastbackslash = 0;
  for (i = 0; i < sourcelen; i++) {
    if ((source[i] == '\\') || (source[i] == '/'))
      lastbackslash = i;
  }
  /* empty / slash-less input: produce empty dir+file instead of a negative-
   * length memcpy (an empty LFNSTR from a crafted request would otherwise drive
   * the file copy size to -1 -> SIZE_MAX). */
  if (lastbackslash + 1 > sourcelen) {
    dir[0] = 0;
    file[0] = 0;
    return;
  }
  memcpy(dir, source, lastbackslash + 1);
  dir[lastbackslash + 1] = 0;
  /* copy file/mask into file */
  filelen = sourcelen - (lastbackslash + 1);
  if (filelen < 0)
    filelen = 0;
  memcpy(file, source + lastbackslash + 1, filelen);
  file[filelen] = 0;
}

/* replaces all rep chars in string s by repby */
static void charreplace(char *s, char rep, char repby) {
  while (*s != 0) {
    if (*s == rep)
      *s = repby;
    s++;
  }
}

/* ===== LFN (long filename) helpers ===================================== */

/* Reads an LFNSTR (u16 LE length + <len> raw path bytes, NOT NUL-terminated)
 * from src, which has srclen bytes available. Copies the path into out (NUL-
 * terminated) and converts backslashes to forward slashes. Returns 0 on
 * success, non-zero on a bounds error (declared length runs past the frame, or
 * would overflow out). This is the bounded replacement for the legacy fixed
 * dos_*[256] memcpy's, so a >255-char or truncated LFN can never overflow. */
static int lfnstr_get(unsigned char *src, int srclen, char *out, int outsz) {
  unsigned int len;
  if (srclen < 2)
    return (-1);
  len = (unsigned int)src[0] | ((unsigned int)src[1] << 8);
  if ((int)(2 + len) > srclen)
    return (-1); /* declared length exceeds what's actually in the frame */
  if ((int)len > outsz - 1)
    return (-1); /* would overflow the destination buffer */
  memcpy(out, src + 2, len);
  out[len] = 0;
  charreplace(out, '\\', '/');
  return (0);
}

/* Fills an LFN FindFirst/FindNext/Open/Create response body into answ, per the
 * §9.3 layout: [0]attr [1..11]FCB-SFN [12..15]DOS-packed time [16..19]size
 * [20..21]w20 [22..23]w22 [24]b24 [25..32]FILETIME(LE) [33..34]u16 lfnlen
 * [35..]long name. (find: w20=dirss,w22=fpos,b24=reserved; open: w20=fileid,
 * w22=action,b24=openmode.) Returns the payload length. */
static int lfn_fill_resp(unsigned char *answ, struct fileprops *fp,
                         unsigned short w20, unsigned short w22,
                         unsigned char b24, const char *lfn) {
  int ln = (int)strlen(lfn);
  int i;
  unsigned long long ft = fp->filetime;
  unsigned long t32;
  /* All multi-byte fields are written byte-wise (little-endian) to avoid
   * unaligned typed stores: answ = frame+60, so answ+33 is an odd address. */
  answ[0] = fp->fattr;
  memcpy(answ + 1, fp->fcbname, 11);
  t32 = fp->ftime; /* [12..15] DOS-packed date+time */
  answ[12] = t32 & 0xff;
  answ[13] = (t32 >> 8) & 0xff;
  answ[14] = (t32 >> 16) & 0xff;
  answ[15] = (t32 >> 24) & 0xff;
  t32 = fp->fsize; /* [16..19] size */
  answ[16] = t32 & 0xff;
  answ[17] = (t32 >> 8) & 0xff;
  answ[18] = (t32 >> 16) & 0xff;
  answ[19] = (t32 >> 24) & 0xff;
  answ[20] = w20 & 0xff; /* [20..21] dirss / fileid */
  answ[21] = (w20 >> 8) & 0xff;
  answ[22] = w22 & 0xff; /* [22..23] fpos / action */
  answ[23] = (w22 >> 8) & 0xff;
  answ[24] = b24; /* [24] reserved / open-mode */
  for (i = 0; i < 8; i++) { /* [25..32] FILETIME, little-endian */
    answ[25 + i] = (unsigned char)(ft & 0xff);
    ft >>= 8;
  }
  if (ln > 255)
    ln = 255;
  answ[33] = ln & 0xff; /* [33..34] long-name length */
  answ[34] = (ln >> 8) & 0xff;
  memcpy(answ + 35, lfn, (size_t)ln); /* [35..] long name */
  return (35 + ln);
}

/* FCB-ize an LFN search mask. Like filename2fcb(), but with the Win95 LFN
 * wildcard rule (RBIL, INT 21h/AX=714Eh): a '*' matches ACROSS the dot, and
 * "*" == "*.*" == match any filename. Classic FCB expansion of a dot-less
 * mask like "*" or "FOO*" leaves the extension field BLANK (matches only
 * extension-less names), which made LFN DIR listings drop every file with an
 * extension. So: if the mask contains a '*' but no '.', wildcard the
 * extension field too. Used ONLY by the LFN find opcodes -- the legacy 8.3
 * path keeps the classic filename2fcb() semantics. The CLIENT applies the
 * same rule when it builds the FINDNEXT template (lfn_leaf2fcb); the two MUST
 * stay identical or FindFirst/FindNext would enumerate different sets. */
static void lfn_mask2fcb(char *d, const char *mask) {
  filename2fcb(d, mask);
  if ((strchr(mask, '.') == NULL) && (strchr(mask, '*') != NULL)) {
    int i;
    for (i = 8; i < 11; i++)
      d[i] = '?';
  }
}

/* Given a resolved full Linux path, sets fp->fcbname to the deterministic 8.3
 * SFN alias of its leaf (matching what FindFirst would report) and returns a
 * pointer to the real (long) leaf within fullpath. */
static const char *lfn_alias_from_path(struct fileprops *fp, char *fullpath) {
  char parent[512];
  char sfn[14];
  char *base = fullpath;
  char *p;
  size_t plen;
  for (p = fullpath; *p != 0; p++)
    if (*p == '/')
      base = p + 1;
  plen = (size_t)(base - fullpath);
  if (plen >= sizeof(parent))
    plen = sizeof(parent) - 1;
  memcpy(parent, fullpath, plen);
  if (plen > 1 && parent[plen - 1] == '/') /* drop trailing slash for opendir */
    plen--;
  parent[plen] = 0;
  sfn_for_name_in_dir(parent[0] != 0 ? parent : "/", base, sfn);
  filename2fcb(fp->fcbname, sfn);
  return (base);
}

static int process(struct struct_answcache *answer, unsigned char *reqbuff,
                   int reqbufflen, unsigned char *mymac, char **rootarray) {
  int query, reqdrv, reqflags;
  int reslen = 0;
  unsigned short *ax;  /* pointer to store the value of AX after the query */
  unsigned char *answ; /* convenience pointer to answer->frame */
  unsigned short *wreqbuff; /* same as query, but word-based (16 bits) */
  unsigned short *wansw; /* same as answer->frame, but word-based (16 bits) */
  char *root;
  answ = answer->frame;
  /* must be at least 60 bytes long */
  if (reqbufflen < 60)
    return (-1);
  /* does it match the cache entry (same seq and same mac and len > 0)? if so,
   * just re-send it again */
  if ((answ[57] == reqbuff[57]) && (memcmp(answ, reqbuff + 6, 6) == 0) &&
      (answer->len > 0)) {
#if SIMLOSS > 0
    fprintf(stderr, "Cache HIT (seq %u)\n", answ[57]);
#endif
    return (answer->len);
  }

  /* copy all headers as-is */
  memcpy(answ, reqbuff, 60);

  /* switch src and dst addresses so the reply header is ready */
  memcpy(answ, answ + 6, 6);  /* copy source mac into dst field */
  memcpy(answ + 6, mymac, 6); /* copy my mac into source field */
  /* remember the pointer to the AX result, and fetch reqdrv and AL query */
  ax = (uint16_t *)answ + 29;
  reqdrv = reqbuff[58] & 31;   /* 5 lowest -> drive */
  reqflags = reqbuff[58] >> 5; /* 3 highest bits -> flags */
  reqflags = reqflags; /* just so the compiler won't complain (I don't use flags
                          yet) */
  query = reqbuff[59];
  /* skip eth headers now, as well as padding, seq, reqdrv and AL */
  reqbuff += 60;
  answ += 60;
  reqbufflen -= 60;
  reslen = 0;
  /* set up wansw and wreqbuff */
  wansw = (uint16_t *)answ;
  wreqbuff = (uint16_t *)reqbuff;

  /* is the drive valid? (C: - Z:) */
  if ((reqdrv < 2) || (reqdrv > 25)) { /* 0=A, 1=B, 2=C, etc */
    fprintf(stderr, "invalid drive value: 0x%02Xh\n", reqdrv);
    return (-3);
  }
  /* do I know this drive? */
  root = rootarray[reqdrv];
  if (root == NULL) {
    fprintf(stderr, "unknown drive: %c: (%02Xh)\n", 'A' + reqdrv, reqdrv);
    return (-3);
  }
  /* assume success (hence AX == 0 most of the time) */
  *ax = 0;
  /* let's look at the exact query */
  DBG("Got query: %02Xh [%02X %02X %02X %02X]\n", query, reqbuff[0], reqbuff[1],
      reqbuff[2], reqbuff[3]);
  if (query == AL_DISKSPACE) {
    unsigned long long diskspace, freespace;
    DBG("DISKSPACE for drive '%c:'\n", 'A' + reqdrv);
    diskspace = diskinfo(root, &freespace);
    /* limit results to slightly under 2 GiB (otherwise MS-DOS is confused) */
    if (diskspace >= 2lu * 1024 * 1024 * 1024)
      diskspace = 2lu * 1024 * 1024 * 1024 - 1;
    if (freespace >= 2lu * 1024 * 1024 * 1024)
      freespace = 2lu * 1024 * 1024 * 1024 - 1;
    DBG("TOTAL: %llu KiB ; FREE: %llu KiB\n", diskspace >> 10, freespace >> 10);
    *ax = 1; /* AX: media id (8 bits) | sectors per cluster (8 bits) -- MSDOS
                tolerates only 1 here! */
    wansw[1] = htole16(32768);     /* CX: bytes per sector */
    diskspace >>= 15;              /* space to number of 32K clusters */
    freespace >>= 15;              /* space to number of 32K clusters */
    wansw[0] = htole16(diskspace); /* BX: total clusters */
    wansw[2] = htole16(freespace); /* DX: available clusters */
    reslen += 6;
  } else if ((query == AL_READFIL) && (reqbufflen == 8)) { /* AL=08h */
    uint16_t len, fileid;
    uint32_t offset;
    long readlen;
    offset = le32toh(((uint32_t *)reqbuff)[0]);
    fileid = le16toh(wreqbuff[2]);
    len = le16toh(wreqbuff[3]);
    DBG("Asking for %u bytes of the file #%u, starting offset %u\n", len,
        fileid, offset);
    readlen = readfile(answ, fileid, offset, len);
    if (readlen < 0) {
      fprintf(stderr, "ERROR: invalid handle\n");
      *ax = 5; /* "access denied" */
    } else {
      stat_bytes_read += readlen;
      reslen += readlen;
    }
  } else if ((query == AL_WRITEFIL) && (reqbufflen >= 6)) { /* AL=09h */
    if (readonly_mode) {
      *ax = 5; /* Access Denied */
    } else {
      uint16_t fileid;
      uint32_t offset;
      long writelen;
      offset = le32toh(((uint32_t *)reqbuff)[0]);
      fileid = le16toh(wreqbuff[2]);
      DBG("Writing %u bytes into file #%u, starting offset %u\n",
          reqbufflen - 6, fileid, offset);
      writelen = writefile(reqbuff + 6, fileid, offset, reqbufflen - 6);
      if (writelen < 0) {
        *ax = 5; /* "access denied" */
      } else {
        stat_bytes_written += writelen;
        wansw[0] = htole16(writelen);
        reslen += 2;
      }
    }
  } else if ((query == AL_LOCKFIL) ||
             (query == AL_UNLOCKFIL)) { /* 0x0A / 0x0B */
    /* I do nothing, except lying that lock/unlock succeeded */
  } else if (query == AL_FINDFIRST) { /* 0x1B */
    struct fileprops fprops;
    char directory[256];
    unsigned short dirss;
    char filemask[16], filemaskfcb[12];
    unsigned fattr;
    unsigned short fpos = 0;
    int flags;
    fattr = reqbuff[0];
    fattr = reqbuff[0];
    /* resolve the search path (directory part) */
    {
      char dos_search_path[256];
      char resolved_dir[512];
      memcpy(dos_search_path, (char *)reqbuff + 1, reqbufflen - 1);
      dos_search_path[reqbufflen - 1] = 0;
      lostring(dos_search_path, -1);
      charreplace(dos_search_path, '\\', '/');

      /* explode the full "\DIR\FILE????.???" search path into directory and
       * mask */
      explodepath(directory, filemask, dos_search_path,
                  strlen(dos_search_path));

      /* Map the DOS directory path to actual Linux path */
      resolve_path(resolved_dir, root, directory);
      strcpy(directory, resolved_dir);
    }

    charreplace(directory, '\\', '/');
    /* */
    filename2fcb(filemaskfcb, filemask);
    DBG("FindFirst in '%s'\nfilemask: '%s' (FCB '%s')\nattribs: 0x%2X\n",
        directory, filemask, pfcb(filemaskfcb), fattr);
    flags = 0;
    if (isroot(root, directory) != 0)
      flags |= FFILE_ISROOT;
    if (drivesfat[reqdrv] != 0)
      flags |= FFILE_ISFAT;
    dirss = getitemss(directory);
    if ((dirss == 0xffffu) ||
        (findfile(&fprops, dirss, filemaskfcb, NULL, fattr, &fpos, flags,
                  custom_vol_label, NULL) != 0)) {
      DBG("No matching file found\n");
      *ax = 0x12; /* 0x12 is "no more files" -- one would assume 0x02 "file not
                     found" would be better, but that's not what MS-DOS 5.x
                     does, some applications rely on a failing FFirst to return
                     0x12 (for example LapLink 5) */
    } else {      /* found a file */
      DBG("found file: FCB '%s' (attr %02Xh)\n", pfcb(fprops.fcbname),
          fprops.fattr);
      answ[0] = fprops.fattr; /* fattr (1=RO 2=HID 4=SYS 8=VOL 16=DIR 32=ARCH
                                 64=DEVICE) */
      memcpy(answ + 1, fprops.fcbname, 11);
      answ[12] = fprops.ftime & 0xff;
      answ[13] = (fprops.ftime >> 8) & 0xff;
      answ[14] = (fprops.ftime >> 16) & 0xff;
      answ[15] = (fprops.ftime >> 24) & 0xff;
      answ[16] = fprops.fsize & 0xff;         /* fsize */
      answ[17] = (fprops.fsize >> 8) & 0xff;  /* fsize */
      answ[18] = (fprops.fsize >> 16) & 0xff; /* fsize */
      answ[19] = (fprops.fsize >> 24) & 0xff; /* fsize */
      wansw[10] = htole16(dirss);             /* dir id */
      wansw[11] = htole16(fpos);              /* file position in dir */
      reslen = 24;
    }
  } else if (query == AL_FINDNEXT) { /* 0x1C */
    unsigned short fpos;
    struct fileprops fprops;
    char *fcbmask;
    unsigned char fattr;
    unsigned short dirss;
    int flags;
    dirss = le16toh(wreqbuff[0]);
    fpos = le16toh(wreqbuff[1]);
    fattr = reqbuff[4];
    fcbmask = (char *)reqbuff + 5;
    /* */
    DBG("FindNext looks for nth file %u in dir #%u\nfcbmask: '%s'\nattribs: "
        "0x%2X\n",
        fpos, dirss, pfcb(fcbmask), fattr);
    flags = 0;
    if (isroot(root, sstoitem(dirss)) != 0)
      flags |= FFILE_ISROOT;
    if (drivesfat[reqdrv] != 0)
      flags |= FFILE_ISFAT;
    if (findfile(&fprops, dirss, fcbmask, NULL, fattr, &fpos, flags,
                 custom_vol_label, NULL)) {
      DBG("No more matching files found\n");
      *ax = 0x12; /* "no more files" */
    } else {      /* found a file */
      DBG("found file: FCB '%s' (attr %02Xh)\n", pfcb(fprops.fcbname),
          fprops.fattr);
      answ[0] = fprops.fattr; /* fattr (1=RO 2=HID 4=SYS 8=VOL 16=DIR 32=ARCH
                                 64=DEVICE) */
      memcpy(answ + 1, fprops.fcbname, 11);
      answ[12] = fprops.ftime & 0xff;
      answ[13] = (fprops.ftime >> 8) & 0xff;
      answ[14] = (fprops.ftime >> 16) & 0xff;
      answ[15] = (fprops.ftime >> 24) & 0xff;
      answ[16] = fprops.fsize & 0xff;         /* fsize */
      answ[17] = (fprops.fsize >> 8) & 0xff;  /* fsize */
      answ[18] = (fprops.fsize >> 16) & 0xff; /* fsize */
      answ[19] = (fprops.fsize >> 24) & 0xff; /* fsize */
      wansw[10] = htole16(dirss);             /* dir id */
      wansw[11] = htole16(fpos);              /* file position in dir */
      reslen = 24;
    }
  } else if ((query == AL_MKDIR) || (query == AL_RMDIR)) { /* MKDIR or RMDIR */
    if (readonly_mode) {
      *ax = 5;
    } else {
      char directory[512];
      char dos_dir[256];

      memcpy(dos_dir, (char *)reqbuff, reqbufflen);
      dos_dir[reqbufflen] = 0;
      lostring(dos_dir, -1);
      charreplace(dos_dir, '\\', '/');

      if (query == AL_RMDIR) {
        resolve_path(directory, root, dos_dir);
      } else {
        /* MKDIR: resolve parent, append new name.
           A simple resolve_path might just return the SFN if the dir doesn't
           exist, which is actually correct since MKDIR should create what DOS
           asked for */
        resolve_path(directory, root, dos_dir);
      }
      if (query == AL_MKDIR) {
        DBG("MKDIR '%s'\n", directory);
        if (makedir(directory) != 0) {
          *ax = 29;
          fprintf(stderr, "MKDIR Error: %s\n", strerror(errno));
        }
      } else {
        DBG("RMDIR '%s'\n", directory);
        if (remdir(directory) != 0) {
          *ax = 29;
          fprintf(stderr, "RMDIR Error: %s\n", strerror(errno));
        }
      }
    }
  } else if (query == AL_CHDIR) { /* check if dir exist, return ax=0 if so, ax=3
                                     otherwise */
    char directory[512];
    char dos_dir[256];

    memcpy(dos_dir, (char *)reqbuff, reqbufflen);
    dos_dir[reqbufflen] = 0;
    lostring(dos_dir, -1);
    charreplace(dos_dir, '\\', '/');

    resolve_path(directory, root, dos_dir);
    DBG("CHDIR '%s'\n", directory);
    /* try to chdir to this dir - if works, then we're good */
    if (changedir(directory) != 0) {
      fprintf(stderr, "CHDIR Error (%s): %s\n", directory, strerror(errno));
      *ax = 3;
    }
  } else if (query == AL_CLSFIL) { /* AL_CLSFIL (0x06) */
    /* I do nothing, since I do not keep any open files around anyway.
     * just say 'ok' by sending back AX=0 */
    DBG("CLOSE FILE\n");
    *ax = 0;
  } else if ((query == AL_SETATTR) &&
             (reqbufflen > 1)) { /* AL_SETATTR (0x0E) */
    if (readonly_mode) {
      *ax = 5;
    } else {
      char fname[512];
      char dos_fname[256];
      unsigned char fattr;
      fattr = reqbuff[0];

      /* get full file path */
      memcpy(dos_fname, (char *)reqbuff + 1, reqbufflen - 1);
      dos_fname[reqbufflen - 1] = 0;
      lostring(dos_fname, -1);
      charreplace(dos_fname, '\\', '/');

      resolve_path(fname, root, dos_fname);
      DBG("SETATTR [file: '%s', attr: 0x%02X]\n", fname, fattr);
      /* set attr, but only if drive is FAT */
      if (drivesfat[reqdrv] != 0) {
        if (setitemattr(fname, fattr) != 0)
          *ax = 2;
      }
    }
  } else if ((query == AL_GETATTR) &&
             (reqbufflen > 0)) { /* AL_GETATTR (0x0F) */
    char fname[512];
    char dos_fname[256];
    struct fileprops fprops;

    /* get full file path */
    memcpy(dos_fname, (char *)reqbuff, reqbufflen);
    dos_fname[reqbufflen] = 0;
    lostring(dos_fname, -1);
    charreplace(dos_fname, '\\', '/');

    resolve_path(fname, root, dos_fname);
    DBG("GETATTR on file: '%s' (fatflag=%d)\n", fname, drivesfat[reqdrv]);
    /* */
    if (getitemattr(fname, &fprops, drivesfat[reqdrv]) == 0xFF) {
      DBG("no file found\n");
      *ax = 2;
    } else {
      DBG("found it (%lu bytes, attr 0x%02X)\n", fprops.fsize, fprops.fattr);
      answ[reslen++] = fprops.ftime & 0xff;
      answ[reslen++] = (fprops.ftime >> 8) & 0xff;
      answ[reslen++] = (fprops.ftime >> 16) & 0xff;
      answ[reslen++] = (fprops.ftime >> 24) & 0xff;
      answ[reslen++] = fprops.fsize & 0xff;
      answ[reslen++] = (fprops.fsize >> 8) & 0xff;
      answ[reslen++] = (fprops.fsize >> 16) & 0xff;
      answ[reslen++] = (fprops.fsize >> 24) & 0xff;
      answ[reslen++] = fprops.fattr;
    }
  } else if ((query == AL_RENAME) && (reqbufflen > 2)) { /* AL_RENAME (0x11) */
    if (readonly_mode) {
      *ax = 5;
    } else {
      /* query is LSSS...DDD... */
      char fn1[1024], fn2[1024];
      char dos_fn1[256], dos_fn2[256];
      int fn1len, fn2len;
      fn1len = reqbuff[0];
      fn2len = reqbufflen - (1 + fn1len);
      if (reqbufflen > fn1len) {
        memcpy(dos_fn1, reqbuff + 1, fn1len);
        dos_fn1[fn1len] = 0;
        lostring(dos_fn1, -1);
        charreplace(dos_fn1, '\\', '/');

        memcpy(dos_fn2, reqbuff + 1 + fn1len, fn2len);
        dos_fn2[fn2len] = 0;
        lostring(dos_fn2, -1);
        charreplace(dos_fn2, '\\', '/');

        resolve_path(fn1, root, dos_fn1);
        resolve_path(fn2, root, dos_fn2);

        /* Enhancement: if the dos basename didn't change (a DOS move command),
           we should preserve the original LFN basename from the source. */
        {
          char *dos_base1 = dos_fn1;
          char *dos_base2 = dos_fn2;
          char *p;
          for (p = dos_fn1; *p; p++)
            if (*p == '/')
              dos_base1 = p + 1;
          for (p = dos_fn2; *p; p++)
            if (*p == '/')
              dos_base2 = p + 1;

          if (strcmp(dos_base1, dos_base2) == 0) {
            char *lfn_base = fn1;
            char *fn2_dir = fn2;
            for (p = fn1; *p; p++)
              if (*p == '/')
                lfn_base = p + 1;
            for (p = fn2; *p; p++)
              if (*p == '/')
                fn2_dir = p + 1;

            if (fn2_dir > fn2) {
              strcpy(
                  fn2_dir,
                  lfn_base); /* Replace destination leaf with true LFN leaf */
            }
          }
        }

        DBG("RENAME src='%s' dst='%s'\n", fn1, fn2);
        /* if fn2 destination exists, abort with errcode=5 (as does MS-DOS 5) */
        if (getitemattr(fn2, NULL, 0) != 0xff) {
          DBG("ERROR: '%s' exists already\n", fn2);
          *ax = 5;
        } else {
          DBG("'%s' doesn't exist -> proceed with renaming\n", fn2);
          if (renfile(fn1, fn2) != 0)
            *ax = 5;
        }
      } else {
        *ax = 2;
      }
    }
  } else if (query == AL_DELETE) {
    if (readonly_mode) {
      *ax = 5;
    } else {
      char fullpathname[512];
      char dos_fname[256];

      /* compute full path/file first */
      memcpy(dos_fname, reqbuff, reqbufflen);
      dos_fname[reqbufflen] = 0;
      lostring(dos_fname, -1);
      charreplace(dos_fname, '\\', '/');

      resolve_path(fullpathname, root, dos_fname);
      DBG("DELETE '%s'\n", fullpathname);
      /* is it read-only? */
      if (getitemattr(fullpathname, NULL, drivesfat[reqdrv]) & 1) {
        *ax = 5; /* "access denied" */
      } else if (delfiles(fullpathname) < 0) {
        *ax = 2;
      }
    }
  } else if ((query == AL_OPEN) || (query == AL_CREATE) ||
             (query ==
              AL_SPOPNFIL)) { /* OPEN is only about "does this file exist", and
                                 CREATE "please create or truncate this file",
                                 while SPOPNFIL is a combination of both with
                                 extra flags */
    struct fileprops fprops;
    char directory[256];
    char fname[16], fnamefcb[12];
    char fullpathname[512];
    int fileres;
    unsigned short stackattr, actioncode, spopen_openmode, spopres = 0;
    unsigned char resopenmode;
    char dos_full[256];
    char dos_dir[256];
    /* fetch args */
    stackattr = le16toh(wreqbuff[0]);
    actioncode = le16toh(wreqbuff[1]);
    spopen_openmode = le16toh(wreqbuff[2]);

    /* decode DOS path */
    memcpy(dos_full, reqbuff + 6, reqbufflen - 6);
    dos_full[reqbufflen - 6] = 0;
    lostring(dos_full, -1);
    charreplace(dos_full, '\\', '/');

    /* resolve full path */
    resolve_path(fullpathname, root, dos_full);

    /* compute directory and 'search mask' using DOS path instead of
     * root-prefixed path */
    explodepath(dos_dir, fname, dos_full, strlen(dos_full));

    /* resolve the parent directory specifically */
    resolve_path(directory, root, dos_dir);
    /* does the directory exist? */
    if (changedir(directory) != 0) {
      DBG("open/create/spop failed because directory does not exist\n");
      *ax = 3; /* "path not found" */
    } else {
      /* compute a FCB-style version of the filename */
      filename2fcb(fnamefcb, fname);
      /* */
      DBG("stack word: %04X\n", stackattr);
      DBG("looking for file '%s' (FCB '%s') in '%s'\n", fname, pfcb(fnamefcb),
          directory);
      /* open or create file, depending on exact subfunction */
      if (query == AL_CREATE) {
        DBG("CREATEFIL / stackattr (attribs)=%04Xh / fn='%s'\n", stackattr,
            fullpathname);
        if (readonly_mode) {
          fileres = -1; /* simulate failure */
        } else {
          fileres = createfile(&fprops, directory, fname, stackattr & 0xff,
                               drivesfat[reqdrv]);
        }
        resopenmode = 2; /* read/write */
      } else if (query == AL_SPOPNFIL) {
        /* actioncode contains instructions about how to behave...
         *   high nibble = action if file does NOT exist:
         *     0000 fail
         *     0001 create
         *   low nibble = action if file DOES exist
         *     0000 fail
         *     0001 open
         *     0010 replace/open */
        int attr;
        DBG("SPOPNFIL / stackattr=%04Xh / action=%04Xh / openmode=%04Xh / "
            "fn='%s'\n",
            stackattr, actioncode, spopen_openmode, fullpathname);
        /* see if file exists (and is a file) */
        attr = getitemattr(fullpathname, &fprops, drivesfat[reqdrv]);
        resopenmode = spopen_openmode & 0x7f; /* that's what PHANTOM.C does */
        if (attr ==
            0xff) { /* file not found - look at high nibble of action code */
          DBG("file doesn't exist -> ");
          if ((actioncode & 0xf0) == 16) { /* create */
            DBG("create file\n");
            fileres = createfile(&fprops, directory, fname, stackattr & 0xff,
                                 drivesfat[reqdrv]);
            if (fileres == 0)
              spopres = 2; /* spopres == 2 means 'file created' */
          } else {         /* fail */
            DBG("fail\n");
            fileres = 1;
          }
        } else if ((attr & (FAT_VOL | FAT_DIR)) !=
                   0) { /* item is a DIR or a VOL */
          DBG("fail: item '%s' is either a DIR or a VOL\n", fullpathname);
          fileres = 1;
        } else { /* file found (not a VOL, not a dir) - look at low nibble of
                    action code */
          DBG("file exists already (attr %02Xh) -> ", attr);
          if ((actioncode & 0x0f) == 1) { /* open */
            DBG("open file\n");
            fileres = 0;
            spopres = 1; /* spopres == 1 means 'file opened' */
          } else if ((actioncode & 0x0f) == 2) { /* truncate */
            DBG("truncate file\n");
            if (readonly_mode) {
              fileres = 1;
            } else {
              fileres = createfile(&fprops, directory, fname, stackattr & 0xff,
                                   drivesfat[reqdrv]);
              if (fileres == 0)
                spopres = 3; /* spopres == 3 means 'file truncated' */
            }
          } else { /* fail */
            DBG("fail\n");
            fileres = 1;
          }
        }
      } else { /* simple 'OPEN' */
        int attr;
        DBG("OPENFIL / stackattr (open modes)=%04Xh / fn='%s'\n", stackattr,
            fullpathname);
        resopenmode = stackattr & 0xff;
        attr = getitemattr(fullpathname, &fprops, drivesfat[reqdrv]);
        /* check that item exists, and is neither a volume nor a directory */
        if ((attr != 0xff) && ((attr & (FAT_VOL | FAT_DIR)) == 0)) {
          fileres = 0;
        } else {
          fileres = 1;
        }
      }
      if (fileres != 0) {
        DBG("open/create/spop failed with fileres = %d\n", fileres);
        *ax = 2;
      } else { /* success (found a file, created it or truncated it) */
        unsigned short fileid;
        fileid = getitemss(fullpathname);
        DBG("found file: FCB '%s' (id %04X)\n", pfcb(fprops.fcbname), fileid);
        DBG("     fsize: %lu\n", fprops.fsize);
        DBG("     fattr: %02Xh\n", fprops.fattr);
        DBG("     ftime: %04lX\n", fprops.ftime);
        if (fileid == 0xffffu) {
          fprintf(stderr, "ERROR: failed to get a proper fileid!\n");
          return (-1);
        }
        answ[reslen++] = fprops.fattr; /* fattr (1=RO 2=HID 4=SYS 8=VOL 16=DIR
                                          32=ARCH 64=DEVICE) */
        memcpy(answ + reslen, fprops.fcbname, 11);
        reslen += 11;
        answ[reslen++] =
            fprops.ftime & 0xff; /* time: YYYYYYYM MMMDDDDD hhhhhmmm mmmsssss */
        answ[reslen++] = (fprops.ftime >> 8) & 0xff;
        answ[reslen++] = (fprops.ftime >> 16) & 0xff;
        answ[reslen++] = (fprops.ftime >> 24) & 0xff;
        answ[reslen++] = fprops.fsize & 0xff;         /* fsize */
        answ[reslen++] = (fprops.fsize >> 8) & 0xff;  /* fsize */
        answ[reslen++] = (fprops.fsize >> 16) & 0xff; /* fsize */
        answ[reslen++] = (fprops.fsize >> 24) & 0xff; /* fsize */
        answ[reslen++] = fileid & 0xff;
        answ[reslen++] = fileid >> 8;
        /* CX result (only relevant for SPOPNFIL) */
        answ[reslen++] = spopres & 0xff;
        answ[reslen++] = spopres >> 8;
        answ[reslen++] = resopenmode;
      }
    }
  } else if ((query == AL_SKFMEND) && (reqbufflen == 6)) { /* SKFMEND (0x21) */
    /* translate a 'seek from end' offset into an 'seek from start' offset */
    int32_t offs = le32toh(((uint32_t *)reqbuff)[0]);
    long fsize;
    unsigned short fss = le16toh(((unsigned short *)reqbuff)[2]);
    DBG("SKFMEND on file #%u at offset %d\n", fss, offs);
    /* if arg is positive, zero it out */
    if (offs > 0)
      offs = 0;
    /* */
    fsize = getfopsize(fss);
    if (fsize < 0) {
      DBG("ERROR: file not found or other error\n");
      *ax = 2;
    } else { /* compute new offset and send it back */
      DBG("file #%u is %lu bytes long\n", fss, fsize);
      offs += fsize;
      if (offs < 0)
        offs = 0;
      DBG("new offset: %d\n", offs);
      ((uint32_t *)answ)[0] = htole32(offs);
      reslen = 4;
    }
  } else if (query == AL_LFN_CAPS) { /* 0x40 - LFN capability probe */
    DBG("LFN_CAPS\n");
    answ[0] = 1;    /* LFN sub-version (start at 1) */
    answ[1] = 0;    /* reserved */
    answ[2] = 0x07; /* feature bitmap LE: bit0 find, bit1 open/create, bit2 volinfo */
    answ[3] = 0x00;
    reslen = 4;
  } else if ((query == AL_LFN_TRUENAME) && (reqbufflen >= 4)) { /* 0x4D */
    /* req: [0] = subfunction (1 = long path -> full 8.3-alias path, matching
     * 7160h CL=1 ; 2 = alias/mixed path -> real long path, CL=2), then LFNSTR
     * path. resp: u16 LE length + path bytes. Powers the client's 7160h and
     * every truename+classic-pass-down operation (del/rd/cd/attrib and the
     * 716Ch open path with long parents). */
    unsigned char subfn = reqbuff[0];
    char dlfn[260], outp[300];
    DBG("LFN_TRUENAME subfn %u\n", subfn);
    if (lfnstr_get(reqbuff + 1, reqbufflen - 1, dlfn, sizeof(dlfn)) != 0) {
      *ax = 3;
    } else if ((subfn != 1) && (subfn != 2)) {
      *ax = 1;
    } else {
      int rc = (subfn == 1) ? path_to_sfn(outp, root, dlfn)
                            : path_to_lfn(outp, root, dlfn);
      if (rc != 0) {
        *ax = rc;
      } else {
        int n = (int)strlen(outp);
        if (n > 260) n = 260;
        answ[0] = (unsigned char)(n & 0xff);
        answ[1] = (unsigned char)((n >> 8) & 0xff);
        memcpy(answ + 2, outp, (size_t)n);
        reslen = 2 + n;
        DBG("LFN_TRUENAME -> '%s'\n", outp);
      }
    }
  } else if ((query == AL_LFN_MKDIR) && (reqbufflen >= 3)) { /* 0x49 */
    /* req: LFNSTR full dir path. Creates the directory under its REAL long
     * name (a classic 39h pass-down would 8.3-mangle it). resp: AX only. */
    char dlfn[260], dirpart[512], leaf[260], resolved[512], full[900];
    struct stat st;
    if (readonly_mode) {
      *ax = 5;
    } else if (lfnstr_get(reqbuff, reqbufflen, dlfn, sizeof(dlfn)) != 0) {
      *ax = 3;
    } else {
      explodepath(dirpart, leaf, dlfn, (int)strlen(dlfn));
      resolve_path(resolved, root, dirpart);
      DBG("LFN_MKDIR '%s' in '%s'\n", leaf, resolved);
      if ((leaf[0] == 0) || (stat(resolved, &st) != 0) || (!S_ISDIR(st.st_mode))) {
        *ax = 3; /* parent path not found */
      } else {
        snprintf(full, sizeof(full), "%s/%s", resolved, leaf);
        if (stat(full, &st) == 0) {
          *ax = 5; /* already exists */
        } else if (mkdir(full, 0777) != 0) {
          *ax = (errno == ENOENT) ? 3 : 5;
        }
      }
    }
  } else if ((query == AL_LFN_RENAME) && (reqbufflen >= 4)) { /* 0x47 */
    /* req: LFNSTR old path + LFNSTR new path (concatenated). Renames/moves to
     * the REAL long target name (a classic 56h pass-down would 8.3-mangle the
     * target). Same-drive only by construction. resp: AX only. */
    char oldw[260], neww[260], oldfull[512];
    char dirpart[512], leaf[260], resolved[512], newfull[900];
    struct stat st;
    unsigned short o1len;
    o1len = (unsigned short)(reqbuff[0] | (reqbuff[1] << 8));
    if (readonly_mode) {
      *ax = 5;
    } else if ((lfnstr_get(reqbuff, reqbufflen, oldw, sizeof(oldw)) != 0) ||
               ((int)(2 + o1len) >= reqbufflen) ||
               (lfnstr_get(reqbuff + 2 + o1len, reqbufflen - 2 - o1len, neww,
                           sizeof(neww)) != 0)) {
      *ax = 3;
    } else {
      resolve_path(oldfull, root, oldw);
      explodepath(dirpart, leaf, neww, (int)strlen(neww));
      resolve_path(resolved, root, dirpart);
      DBG("LFN_RENAME '%s' -> '%s'/'%s'\n", oldfull, resolved, leaf);
      if ((stat(oldfull, &st) != 0) || (leaf[0] == 0)) {
        *ax = 2; /* source not found */
      } else {
        snprintf(newfull, sizeof(newfull), "%s/%s", resolved, leaf);
        if (stat(newfull, &st) == 0) {
          *ax = 5; /* target exists: DOS rename must fail, not overwrite */
        } else if (rename(oldfull, newfull) != 0) {
          *ax = (errno == ENOENT) ? 3 : ((errno == EXDEV) ? 0x11 : 5);
        }
      }
    }
  } else if (query == AL_LFN_VOLINFO) { /* 0x4E - GET VOLUME INFO (fallback) */
    DBG("LFN_VOLINFO\n");
    /* byte-wise, all 11 bytes set explicitly (no stale frame data in gaps):
     * [0..1] BX flags LE, [2..3] CX LE, [4..5] DX LE, [6..10] FS-name */
    answ[0] = 0x02; /* BX = 0x4002 LE: bit1 case-preserved | bit14 supports LFN */
    answ[1] = 0x40;
    answ[2] = 0xFF; /* CX = 255 (max filename-component length) */
    answ[3] = 0x00;
    answ[4] = 0x04; /* DX = 260 (max path length) */
    answ[5] = 0x01;
    memcpy(answ + 6, "EDF5", 5); /* [6..10] filesystem name string */
    reslen = 11;
  } else if ((query == AL_LFN_FINDFIRST) && (reqbufflen >= 3)) { /* 0x41 */
    unsigned char fattr = reqbuff[0];
    char dlfn[260], dirpart[512], leafmask[260], filemaskfcb[12], resolved[512];
    char foundlfn[256];
    struct fileprops fprops;
    unsigned short dirss, fpos = 0;
    int flags;
    if (lfnstr_get(reqbuff + 1, reqbufflen - 1, dlfn, sizeof(dlfn)) != 0) {
      *ax = 2;
    } else {
      explodepath(dirpart, leafmask, dlfn, (int)strlen(dlfn));
      resolve_path(resolved, root, dirpart);
      /* Win95: a whole-mask "*.*" means "everything", same as "*" -- normalize
       * so the long-name matcher (which treats '.' literally) agrees */
      if (strcmp(leafmask, "*.*") == 0)
        strcpy(leafmask, "*");
      lfn_mask2fcb(filemaskfcb, leafmask);
      DBG("LFN_FINDFIRST in '%s' mask '%s'\n", resolved, leafmask);
      flags = 0;
      if (isroot(root, resolved) != 0)
        flags |= FFILE_ISROOT;
      if (drivesfat[reqdrv] != 0)
        flags |= FFILE_ISFAT;
      dirss = getitemss(resolved);
      if ((dirss == 0xffffu) ||
          (findfile(&fprops, dirss, filemaskfcb, leafmask, fattr, &fpos,
                    flags, custom_vol_label, foundlfn) != 0)) {
        *ax = 0x12; /* no more files */
      } else {
        reslen = lfn_fill_resp(answ, &fprops, dirss, fpos, 0, foundlfn);
      }
    }
  } else if ((query == AL_LFN_FINDNEXT) && (reqbufflen >= 16)) { /* 0x42 */
    unsigned char fattr = reqbuff[4];
    char *fcbmask = (char *)reqbuff + 5;
    char foundlfn[256];
    char lfnmaskbuf[260];
    const char *lfnmask = NULL;
    struct fileprops fprops;
    unsigned short dirss, fpos;
    int flags;
    dirss = le16toh(wreqbuff[0]);
    fpos = le16toh(wreqbuff[1]);
    /* OPTIONAL additive tail (new clients): LFNSTR long-name mask at [16..],
     * so FindNext matches long names exactly like FindFirst. Old clients send
     * exactly 16 bytes -> lfnmask stays NULL -> SFN-template-only (previous
     * behavior). lfnstr_get bounds-checks the declared length. */
    if ((reqbufflen >= 19) &&
        (lfnstr_get(reqbuff + 16, reqbufflen - 16, lfnmaskbuf,
                    sizeof(lfnmaskbuf)) == 0) &&
        (lfnmaskbuf[0] != 0)) {
      if (strcmp(lfnmaskbuf, "*.*") == 0)
        strcpy(lfnmaskbuf, "*");
      lfnmask = lfnmaskbuf;
    }
    DBG("LFN_FINDNEXT nth %u in dir #%u\n", fpos, dirss);
    flags = 0;
    if (isroot(root, sstoitem(dirss)) != 0)
      flags |= FFILE_ISROOT;
    if (drivesfat[reqdrv] != 0)
      flags |= FFILE_ISFAT;
    if (findfile(&fprops, dirss, fcbmask, lfnmask, fattr, &fpos, flags,
                 custom_vol_label, foundlfn) != 0) {
      *ax = 0x12;
    } else {
      reslen = lfn_fill_resp(answ, &fprops, dirss, fpos, 0, foundlfn);
    }
  } else if ((query == AL_LFN_CREATE) && (reqbufflen >= 4)) { /* 0x44 */
    if (readonly_mode) {
      *ax = 5;
    } else {
      unsigned char cattr = reqbuff[0]; /* creation attributes (low byte) */
      char dlfn[260], dirpart[512], leaf[260], resolved[512], fullpath[1024];
      struct fileprops fprops;
      if (lfnstr_get(reqbuff + 2, reqbufflen - 2, dlfn, sizeof(dlfn)) != 0) {
        *ax = 2;
      } else if (dlfn[0] == 0) {
        *ax = 3; /* empty path -> nothing to create */
      } else {
        explodepath(dirpart, leaf, dlfn, (int)strlen(dlfn));
        resolve_path(resolved, root, dirpart);
        DBG("LFN_CREATE '%s' in '%s'\n", leaf, resolved);
        if (changedir(resolved) != 0) {
          *ax = 3; /* path not found */
        } else if (createfile(&fprops, resolved, leaf, cattr,
                              drivesfat[reqdrv]) != 0) {
          *ax = 2;
        } else {
          unsigned short fileid;
          const char *realleaf;
          snprintf(fullpath, sizeof(fullpath), "%s/%s", resolved, leaf);
          realleaf = lfn_alias_from_path(&fprops, fullpath);
          fileid = getitemss(fullpath);
          if (fileid == 0xffffu) {
            *ax = 2;
          } else {
            reslen = lfn_fill_resp(answ, &fprops, fileid, 2 /*created*/,
                                   2 /*rw*/, realleaf);
          }
        }
      }
    }
  } else if ((query == AL_LFN_OPEN) && (reqbufflen >= 3)) { /* 0x43 */
    char dlfn[260], resolved[512];
    struct fileprops fprops;
    int attr;
    if (lfnstr_get(reqbuff + 1, reqbufflen - 1, dlfn, sizeof(dlfn)) != 0) {
      *ax = 2;
    } else {
      resolve_path(resolved, root, dlfn);
      DBG("LFN_OPEN '%s'\n", resolved);
      attr = getitemattr(resolved, &fprops, drivesfat[reqdrv]);
      if ((attr == 0xff) || ((attr & (FAT_VOL | FAT_DIR)) != 0)) {
        *ax = 2;
      } else {
        unsigned short fileid = getitemss(resolved);
        const char *realleaf = lfn_alias_from_path(&fprops, resolved);
        if (fileid == 0xffffu) {
          *ax = 2;
        } else {
          reslen = lfn_fill_resp(answ, &fprops, fileid, 1 /*opened*/, 2 /*rw*/,
                                 realleaf);
        }
      }
    }
  } else { /* unknown query - ignore */
    return (-1);
  }
  return (reslen + 60);
}

static pcap_t *raw_sock(const int protocol, const char *const interface,
                        void *const hwaddr) {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[32];
  struct ifaddrs *ifap, *ifa;
  int mac_found = 0;

  if ((interface == NULL) || (*interface == 0)) {
    errno = EINVAL;
    return (NULL);
  }

  /* Extract MAC address cross-platform */
  if (getifaddrs(&ifap) == 0) {
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
      if (ifa->ifa_name && strcmp(ifa->ifa_name, interface) == 0) {
#ifdef __linux__
        /* Linux: usually requires ioctl for MAC if not using AF_PACKET
         * sockaddr_ll directly */
        struct ifreq ifr;
        int sockfd;
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd >= 0) {
          strcpy(ifr.ifr_name, interface);
          if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {
            if (hwaddr != NULL)
              memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
            mac_found = 1;
          }
          close(sockfd);
        }
        if (mac_found)
          break;
#else
        /* BSD/macOS: sockaddr_dl */
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK) {
          struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
          if (sdl->sdl_type == IFT_ETHER) {
            if (hwaddr != NULL)
              memcpy(hwaddr, LLADDR(sdl), ETH_ALEN);
            mac_found = 1;
            break;
          }
        }
#endif
      }
    }
    freeifaddrs(ifap);
  }

  if (!mac_found) {
    fprintf(stderr, "Error: Could not determine MAC address for interface %s\n",
            interface);
    return NULL;
  }

  /* Create pcap handle */
  handle = pcap_create(interface, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "pcap_create() failed: %s\n", errbuf);
    return NULL;
  }

  /* Set promiscuous mode to capture raw ethernet frames targeting us and
   * broadcast */
  pcap_set_promisc(handle, 1);
  /* Set a short timeout (e.g. 1ms) so pcap_next_ex can return relatively
   * quickly if no packet */
  pcap_set_timeout(handle, 1);
  /* Disable immediate mode if available to potentially optimize, but for
   * low-latency usually immediate=1 */
  pcap_set_immediate_mode(handle, 1);

  if (pcap_activate(handle) != 0) {
    fprintf(stderr, "pcap_activate() failed: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return NULL;
  }

  /* Compile and apply BPF filter natively within libpcap to drop unwanted
   * traffic */
  sprintf(filter_exp, "ether proto 0x%04X", protocol);
  if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return NULL;
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "pcap_setfilter() failed: %s\n", pcap_geterr(handle));
    pcap_freecode(&fp);
    pcap_close(handle);
    return NULL;
  }
  pcap_freecode(&fp);

  /* Keep the pcap handle in BLOCKING mode so select() on its selectable fd
   * waits correctly. Non-blocking mode makes select()/poll() on the pcap fd
   * unreliable and contributed to the idle busy-spin. The pcap read timeout set
   * above bounds pcap_next_ex() so it still returns promptly when idle. */

  errno = 0;
  return handle;
}

/* used for debug output of frames on screen */
static void dumpframe(unsigned char *frame, int len) {
  int i, b;
  int lines;
  const int LINEWIDTH = 16;
  lines = (len + LINEWIDTH - 1) / LINEWIDTH; /* compute the number of lines */
  /* display line by line */
  for (i = 0; i < lines; i++) {
    /* read the line and output hex data */
    for (b = 0; b < LINEWIDTH; b++) {
      int offset = (i * LINEWIDTH) + b;
      if (b == LINEWIDTH / 2)
        printf(" ");
      if (offset < len) {
        printf(" %02X", frame[offset]);
      } else {
        printf("   ");
      }
    }
    printf(" | "); /* delimiter between hex and ascii */
    /* now output ascii data */
    for (b = 0; b < LINEWIDTH; b++) {
      int offset = (i * LINEWIDTH) + b;
      if (b == LINEWIDTH / 2)
        printf(" ");
      if (offset >= len) {
        printf(" ");
        continue;
      }
      if ((frame[offset] >= ' ') && (frame[offset] <= '~')) {
        printf("%c", frame[offset]);
      } else {
        printf(".");
      }
    }
    /* newline and loop */
    printf("\n");
  }
}

/* compare two chunks of data, returns 0 if data is the same, non-zero otherwise
 */
static int cmpdata(unsigned char *d1, unsigned char *d2, int len) {
  while (len-- > 0) {
    if (*d1 != *d2)
      return (1);
    d1++;
    d2++;
  }
  return (0);
}

/* compute the BSD checksum of l bytes starting at ptr */
static unsigned short bsdsum(unsigned char *ptr, unsigned short l) {
  unsigned short res = 0;
  for (; l > 0; l--) {
    res = (res << 15) | (res >> 1);
    res += *ptr;
    ptr++;
  }
  return (res);
}

static void help(void) {
  printf(
      "ethersrv-linux version " PVER
      " | Copyright (C) 2017, 2018 Mateusz Viste\n"
      "http://etherdfs.sourceforge.net\n"
      "\n"
      "usage: ethersrv-linux [options] interface rootpath1 [rootpath2] ... "
      "[rootpathN]\n"
      "\n"
      "Options:\n"
      "  -d        Enable runtime debug logging (use -dd for raw ethernet "
      "frames)\n"
      "  -f        Keep in foreground (do not daemonize)\n"
      "  -l        Auto-lowercase new DOS files\n"
      "  -m <MAC>  Whitelist a specific MAC address (e.g. 00:11:22:33:44:55)\n"
      "  -r        Enable Read-Only museum mode (reject modifications)\n"
      "  -s <ms>   Artificial delay in milliseconds to slow down packet "
      "processing\n"
      "  -v <label> Specify a custom volume label (max 11 chars)\n"
      "  -h        Display this information\n");
}

/* daemonize the process, return 0 on success, non-zero otherwise */
static int daemonize(void) {
  pid_t mypid;

  /* I don't want to get notified about SIGHUP */
  signal(SIGHUP, SIG_IGN);

  /* fork off */
  mypid = fork();
  if (mypid == 0) { /* I'm the child, do nothing */
    /* nothing to do - just continue */
  } else if (mypid > 0) { /* I'm the parent - quit now */
    exit(0);
  } else { /* error condition */
    return (-2);
  }
  return (0);
}

/* generates a formatted MAC address printout and returns a static buffer */
static char *printmac(unsigned char *b) {
  static char macbuf[18];
  sprintf(macbuf, "%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4],
          b[5]);
  return (macbuf);
}

int main(int argc, char **argv) {
  int len, i;
  pcap_t *handle;
  int pcap_fd;
  const unsigned char *pcap_buff;
  struct pcap_pkthdr *pcap_header;
  unsigned char buff[2048];
  unsigned char cksumflag;
  unsigned short edf5framelen;
  unsigned char mymac[6];
  char *intname, *root[26];
  struct struct_answcache *cacheptr;
  int opt;
  int daemon = 1; /* daemonize self by default */
#define lockfile "/var/run/ethersrv.lock"

  while ((opt = getopt(argc, argv, "dflhm:rs:v:")) != -1) {
    switch (opt) {
    case 'd': /* -d: enable debug mode */
      debug_level++;
      break;
    case 'f': /* -f: no daemon */
      daemon = 0;
      break;
    case 'l': /* -l: auto-lowercase mode */
      lowercase_mode = 1;
      break;
    case 'm': { /* -m: allow specific MAC */
      unsigned int mac_tmp[6];
      if (sscanf(optarg, "%x:%x:%x:%x:%x:%x", &mac_tmp[0], &mac_tmp[1],
                 &mac_tmp[2], &mac_tmp[3], &mac_tmp[4], &mac_tmp[5]) == 6) {
        int mi;
        for (mi = 0; mi < 6; mi++)
          allowed_mac[mi] = (unsigned char)(mac_tmp[mi] & 0xFF);
        allowed_mac_set = 1;
      } else {
        fprintf(stderr, "ERROR: Invalid MAC format. Use XX:XX:XX:XX:XX:XX\n");
        return (1);
      }
      break;
    }
    case 'r': /* -r: read only mode */
      readonly_mode = 1;
      break;
    case 's': /* -s: delay in milliseconds */
      target_delay_ms = strtoul(optarg, NULL, 10);
      break;
    case 'v': /* -v: custom volume label */
      strncpy(custom_vol_label, optarg, 11);
      custom_vol_label[11] = 0; /* Ensure null termination */
      break;
    case 'h': /* -h: help */
      help();
      return (0);
    case '?': /* error */
      help();
      return (1);
    }
  }
  /* I expect at least two positional arguments, and not more than 26 */
  if (argc - optind < 2 || argc - optind > 26) {
    help();
    return (1);
  }
  intname = argv[optind++];
  /* load all "virtual drive" paths */
  for (i = 0; i < 26; i++)
    root[i] = NULL;
  for (i = 0; i < (argc - optind); i++) {
    char tmppath[PATH_MAX];
    if (realpath(argv[i + optind], tmppath) == NULL) {
      fprintf(stderr, "ERROR: failed to resolve path '%s'\n", argv[i + optind]);
      return (1);
    }
    root[i + 2] = strdup(tmppath);
    if (isfat(root[i + 2]) == 0) {
      drivesfat[i + 2] = 1;
    } else {
      drivesfat[i + 2] = 0;
      fprintf(stderr,
              "WARNING: the path '%s' doesn't seem to be stored on a FAT "
              "filesystem! DOS attributes won't be supported.\n\n",
              root[i + 2]);
    }
  }

  handle = raw_sock(0xEDF5, intname, mymac);
  if (handle == NULL) {
    fprintf(stderr,
            "Error: failed to open pcap handle (%s)\n"
            "\n"
            "Usually ethersrv requires to be launched as root to\n"
            "be able to handle raw ethernet devices. Are you root?\n",
            strerror(errno));
    return (1);
  }
  pcap_fd = pcap_get_selectable_fd(handle);

  /* setup signals catcher */
  signal(SIGTERM, sigcatcher);
  signal(SIGQUIT, sigcatcher);
  signal(SIGINT, sigcatcher);

  /* acquire the lock file (fail if already exists - likely ethersrv runs
   * already) */
  if (lockme(lockfile) != 0) {
    fprintf(
        stderr,
        "Error: failed to acquire a lock. Is ethersrv running already? If not, "
        "and you're really sure of that, then delete the lock file at '%s'.\n",
        lockfile);
    return (1);
  }
  printf("Version: %s\n", PVER);
  printf("Listening on '%s' [%s]\n", intname, printmac(mymac));
  for (i = 2; i < 26; i++) {
    if (root[i] == NULL)
      break;
    printf("Drive %c: mapped to %s\n", 'A' + i, root[i]);
  }

  /* forcefully flush the startup banner to the console so Docker logs it
   * immediately */
  fflush(stdout);

  if (daemon != 0) {
    if (daemonize() != 0) {
      fprintf(stderr, "Error: failed to daemonize!\n");
      return (1);
    }
  }

  /* Set umask to 0 so we can explicitly configure 0777 for dirs and 0666 for
     files without the host system stripping away group/other write permissions
   */
  umask(0);

  /* throughput timer */
  /* throughput timer using gettimeofday instead of whole seconds */
  struct timeval stat_tv;
  double last_stat_time;
  int pcap_res;

  gettimeofday(&stat_tv, NULL);
  last_stat_time = stat_tv.tv_sec + (stat_tv.tv_usec / 1000000.0);

  /* main loop */
  while (terminationflag == 0) {
    struct timeval stimeout = {
        1, 0}; /* set timeout to 1s for accurate throughput timer */
    /* prepare the set of descriptors to be monitored later through select() */
    fd_set fdset;
    FD_ZERO(&fdset);
    if (pcap_fd >= 0) {
      /* Wait until the capture fd is READABLE (a frame arrived) or the 1s
       * timeout. Monitor read only: a packet-capture fd is effectively always
       * "writable", so also passing it as the write/except set made select()
       * return immediately on every iteration -> the loop busy-spun a CPU core
       * at 100% even when the link was idle (0 pps). */
      FD_SET(pcap_fd, &fdset);
      select(pcap_fd + 1, &fdset, NULL, NULL, &stimeout);
    } else {
      /* Polling fallback if selectable FD is not supported on this platform */
      struct timeval tv;
      tv.tv_sec = 0;
      tv.tv_usec = 1000;
      select(0, NULL, NULL, NULL, &tv);
    }

    /* Check throughput statistics */
    {
      struct timeval current_tv;
      double current_time;
      gettimeofday(&current_tv, NULL);
      current_time = current_tv.tv_sec + (current_tv.tv_usec / 1000000.0);

      if (current_time - last_stat_time >= 1.0) {
        unsigned long long total_bytes = stat_bytes_read + stat_bytes_written;
        /* Print only if > 10 KB/s combined throughput to accommodate slower
         * MS-DOS packet drivers */
        if (total_bytes > (10ULL * 1024ULL)) {
          printf("[Throughput] Read: %llu KB/s | Write: %llu KB/s\n",
                 stat_bytes_read / 1024ULL, stat_bytes_written / 1024ULL);
          fflush(stdout);
        }
        stat_bytes_read = 0;
        stat_bytes_written = 0;
        last_stat_time = current_time;
      }
    }

    /* fetch packet via libpcap */
    pcap_res = pcap_next_ex(handle, &pcap_header, &pcap_buff);
    if (pcap_res <= 0) {
      continue; /* Timeout, EOF, or error - loop again */
    }
    len = pcap_header->caplen;
    if ((long unsigned int)len > sizeof(buff))
      len = sizeof(buff);
    memcpy(buff, pcap_buff, len);

    /* If we received at least an Ethernet MAC header, track MACs for connection
     * logging */
    if (len >= 14) {
      static unsigned char known_macs[16][6];
      static int known_macs_cnt = 0;
      int m_idx, found = 0;
      for (m_idx = 0; m_idx < known_macs_cnt; m_idx++) {
        if (memcmp(known_macs[m_idx], buff + 6, 6) == 0) {
          found = 1;
          break;
        }
      }
      if (!found) {
        printf("Client connected from MAC %s\n", printmac(buff + 6));
        fflush(stdout); /* flush immediately to TrueNAS console */
        if (known_macs_cnt < 16) {
          memcpy(known_macs[known_macs_cnt], buff + 6, 6);
          known_macs_cnt++;
        }
      }
    }

    if (len < 60)
      continue; /* restart if less than 60 bytes (invalid EtherDFS frame) or
                   negative */

    /* enforce MAC ACL if set */
    if (allowed_mac_set && memcmp(allowed_mac, buff + 6, 6) != 0) {
      continue; /* ignore frame from unauthorized MAC */
    }

    /* validate this is for me (or broadcast) */
    if ((cmpdata(mymac, buff, 6) != 0) &&
        (cmpdata((unsigned char *)"\xff\xff\xff\xff\xff\xff", buff, 6) != 0))
      continue; /* skip anything that is not for me */
    /* is this EDF5 ?*/
    if (((unsigned short *)buff)[6] != htons(0xEDF5)) {
      fprintf(stderr, "Error: Received non-EDF5 frame\n");
      continue;
    }
    /* validate protocol version matches what I expect */
    if ((buff[56] & 127) != PROTOVER) {
      fprintf(stderr, "Error: unsupported protocol version from %s\n",
              buff + 6);
      continue;
    }
    cksumflag = buff[56] >> 7;
    /* trim of padding, if any, or reject frame if it came truncated */
    edf5framelen = le16toh(((unsigned short *)buff)[26]);
    if (edf5framelen == 0) {
      /* nothing to do, edf5framelen is not provided */
    } else if (edf5framelen > len) { /* frame seems truncated */
      fprintf(stderr, "Error: received a truncated frame from %s\n",
              printmac(buff + 6));
      continue;
    } else if (edf5framelen < 60) { /* obvious error */
      fprintf(stderr, "Error: received a malformed frame from %s\n",
              printmac(buff + 6));
      continue;
    } else { /* edf5framelen seems sane, use it instead of the Ethernet lenght
              */
      if (debug_level > 0 && len != edf5framelen) {
        DBG("Note: Received frame with padding from %s (edf5len = %u, ethernet "
            "len = %u)\n",
            printmac(buff + 6), edf5framelen, len);
      }
      len = edf5framelen;
    }
    /* */
    if (debug_level > 0) {
      DBG("Received frame of %d bytes (cksum = %s)\n", len,
          (cksumflag != 0) ? "ENABLED" : "DISABLED");
    }
    if (debug_level >= 2) {
      printf("--- RAW RX ---\n");
      dumpframe(buff, len);
    }
#if SIMLOSS > 0
    /* simulated frame LOSS (input) */
    if ((rand() & 31) == 0) {
      fprintf(stderr, "INPUT LOSS!\n");
      continue;
    }
#endif
    /* validate the CKSUM, if any */
    if (cksumflag != 0) {
      unsigned short cksum_remote, cksum_mine;
      cksum_mine = bsdsum(buff + 56, len - 56);
      cksum_remote = le16toh(((unsigned short *)buff)[27]);
      if (cksum_mine != cksum_remote) {
        fprintf(stderr,
                "CHECKSUM MISMATCH! Computed: 0x%02Xh Received: 0x%02Xh\n",
                cksum_mine, cksum_remote);
        continue;
      }
    }
    /* */
    cacheptr = findcacheentry(buff + 6);
    /* process frame */
    len = process(cacheptr, buff, len, mymac, root);
    /* update cache entry */
    if (len >= 0) {
      cacheptr->len = len;
      cacheptr->timestamp = time(NULL);
    } else {
      cacheptr->len = 0;
    }
/* */
#if SIMLOSS > 0
    /* simulated frame LOSS (output) */
    if ((rand() & 31) == 0) {
      fprintf(stderr, "OUTPUT LOSS!\n");
      continue;
    }
#endif
    DBG("---------------------------------\n");
    if (len > 0) {
      /* fill in frame's length */
      cacheptr->frame[52] = len & 0xff;
      cacheptr->frame[53] = (len >> 8) & 0xff;
      /* fill in checksum into the answer */
      if (cksumflag != 0) {
        unsigned short newcksum = bsdsum(cacheptr->frame + 56, len - 56);
        cacheptr->frame[54] = newcksum & 0xff;
        cacheptr->frame[55] = (newcksum >> 8) & 0xff;
        cacheptr->frame[56] |= 128; /* make sure to set the CKS bit */
      } else {
        cacheptr->frame[54] = 0;
        cacheptr->frame[55] = 0;
        cacheptr->frame[56] &= 127; /* make sure to reset the CKS bit */
      }
      if (debug_level > 0) {
        DBG("Sending back an answer of %d bytes\n", len);
      }
      if (debug_level >= 2) {
        printf("--- RAW TX ---\n");
        dumpframe(cacheptr->frame, len);
      }
      i = pcap_inject(handle, cacheptr->frame, len);
      if (i < 0) {
        fprintf(stderr, "ERROR: pcap_inject() returned %s\n",
                pcap_geterr(handle));
      } else if (i != len) {
        fprintf(stderr,
                "ERROR: pcap_inject() sent less than expected (%d != %d)\n", i,
                len);
      }
    } else {
      fprintf(stderr, "Query ignored (result: %d)\n", len);
    }
    DBG("---------------------------------\n");
  }
  /* remove the lock file and quit */
  unlockme(lockfile);
  return (0);
}
