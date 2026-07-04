/* End-to-end protocol test for the Phase-1 LFN wire handlers.
 * Includes ethersrv.c (main renamed) so we can call the real static process()
 * with crafted EtherDFS request frames and inspect the reply bytes against the
 * §9.3 layout. No networking: deterministic, reproducible. */
#define main ethersrv_main_DISABLED
#include "ethersrv.c"
#undef main

#include <stdio.h>
#include <string.h>

static unsigned char frame[2048];

static int build_req(unsigned char *buf, unsigned char opcode,
                     const unsigned char *payload, int plen) {
  memset(buf, 0, 2048);
  memset(buf, 0xAA, 6);     /* dst = server mac */
  memset(buf + 6, 0xBB, 6); /* src = client mac */
  buf[12] = 0xED;
  buf[13] = 0xF5;
  buf[56] = PROTOVER;
  buf[57] = 1;      /* seq */
  buf[58] = 2;      /* drive C (low 5 bits) */
  buf[59] = opcode; /* AL query */
  if (plen > 0)
    memcpy(buf + 60, payload, plen);
  return 60 + plen;
}

/* append an LFNSTR (u16 LE len + bytes) to p, return bytes written */
static int put_lfnstr(unsigned char *p, const char *s) {
  int n = (int)strlen(s);
  p[0] = n & 0xff;
  p[1] = (n >> 8) & 0xff;
  memcpy(p + 2, s, n);
  return 2 + n;
}

/* decode a §9.3 find/open response payload */
static void show_resp(const char *tag, unsigned char *fr, int rc) {
  unsigned short ax = fr[58] | (fr[59] << 8);
  unsigned char *pl = fr + 60;
  if (rc < 0) {
    printf("  %s: process() rc=%d (error)\n", tag, rc);
    return;
  }
  if (ax != 0) {
    printf("  %s: AX=0x%02X (%s)\n", tag, ax,
           ax == 0x12 ? "no-more-files" : "fail");
    return;
  }
  {
    int ln = pl[33] | (pl[34] << 8);
    unsigned short w20 = pl[20] | (pl[21] << 8);
    unsigned short w22 = pl[22] | (pl[23] << 8);
    unsigned long long ft = 0;
    char lfn[260];
    int i;
    for (i = 7; i >= 0; i--)
      ft = (ft << 8) | pl[25 + i];
    if (ln > 255)
      ln = 255;
    memcpy(lfn, pl + 35, ln);
    lfn[ln] = 0;
    printf("  %s: AX=0 attr=0x%02X SFN='%.11s' w20=%u w22=%u ft=%llu lfn='%s'\n",
           tag, pl[0], pl + 1, w20, w22, ft, lfn);
  }
}

int main(int argc, char **argv) {
  struct struct_answcache ans;
  unsigned char mymac[6];
  char *rootarray[26];
  unsigned char pl[600];
  int reqlen, rc, n, round;
  unsigned short dirss, fpos;

  if (argc < 2) {
    fprintf(stderr, "usage: %s <fixture-dir>\n", argv[0]);
    return (1);
  }
  memset(rootarray, 0, sizeof(rootarray));
  rootarray[2] = argv[1]; /* drive C -> fixture dir */
  memset(mymac, 0xAA, 6);

  printf("=== AL_LFN_CAPS (0x40) ===\n");
  memset(&ans, 0, sizeof(ans));
  reqlen = build_req(frame, 0x40, NULL, 0);
  rc = process(&ans, frame, reqlen, mymac, rootarray);
  printf("  rc=%d AX=%u subver=%u featbm=0x%02X%02X (expect subver=1 bm=0x0007)\n",
         rc, ans.frame[58] | (ans.frame[59] << 8), ans.frame[60],
         ans.frame[63], ans.frame[62]);

  printf("=== AL_LFN_VOLINFO (0x4E) ===\n");
  memset(&ans, 0, sizeof(ans));
  reqlen = build_req(frame, 0x4E, NULL, 0);
  rc = process(&ans, frame, reqlen, mymac, rootarray);
  printf("  rc=%d BX=0x%02X%02X CX=%u DX=%u name='%.4s' (expect BX=0x4002 CX=255 DX=260)\n",
         rc, ans.frame[61], ans.frame[60],
         ans.frame[62] | (ans.frame[63] << 8),
         ans.frame[64] | (ans.frame[65] << 8), ans.frame + 66);

  printf("=== AL_LFN_FINDFIRST/FINDNEXT (0x41/0x42) over drive C ===\n");
  /* FINDFIRST: [0]=attr 0x37, then LFNSTR "\\????????.???" (DOS *.* expanded) */
  pl[0] = 0x37;
  n = 1 + put_lfnstr(pl + 1, "\\????????.???");
  memset(&ans, 0, sizeof(ans));
  reqlen = build_req(frame, 0x41, pl, n);
  rc = process(&ans, frame, reqlen, mymac, rootarray);
  show_resp("FINDFIRST", ans.frame, rc);
  dirss = ans.frame[60 + 20] | (ans.frame[60 + 21] << 8);
  fpos = ans.frame[60 + 22] | (ans.frame[60 + 23] << 8);
  for (round = 0; round < 40; round++) {
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0)
      break; /* previous was no-more or error */
    pl[0] = dirss & 0xff;
    pl[1] = (dirss >> 8) & 0xff;
    pl[2] = fpos & 0xff;
    pl[3] = (fpos >> 8) & 0xff;
    pl[4] = 0x37;                /* attr */
    memset(pl + 5, '?', 11);     /* fcbmask = all wildcards */
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x42, pl, 16);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FINDNEXT: no-more-files (done)\n");
      break;
    }
    show_resp("FINDNEXT", ans.frame, rc);
    fpos = ans.frame[60 + 22] | (ans.frame[60 + 23] << 8);
  }

  printf("=== AL_LFN_FINDFIRST with Win95 mask \"\\*\" (must match files WITH extensions) ===\n");
  /* Regression for the empty-extension FCB template: 4DOS (any Win95-style
   * caller) sends mask "*", which classic FCB expansion turned into
   * "????????   " (blank ext) so every file with an extension was skipped and
   * DIR showed only directories. lfn_mask2fcb must expand "*" to 11x'?'.
   * Enumerate with attr 0x10 (what 4DOS's DIR passes) and REQUIRE that at
   * least one entry with a non-blank SFN extension is returned. */
  {
    int got_ext_file = 0;
    pl[0] = 0x10; /* attr: dirs allowed, normal files must still match */
    n = 1 + put_lfnstr(pl + 1, "\\*");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x41, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    show_resp("FINDFIRST*", ans.frame, rc);
    dirss = ans.frame[60 + 20] | (ans.frame[60 + 21] << 8);
    fpos = ans.frame[60 + 22] | (ans.frame[60 + 23] << 8);
    for (round = 0; round < 40; round++) {
      unsigned char *sfn;
      if ((ans.frame[58] | (ans.frame[59] << 8)) != 0)
        break;
      sfn = ans.frame + 60 + 1;
      if ((ans.frame[60] & 0x18) == 0 && memcmp(sfn + 8, "   ", 3) != 0)
        got_ext_file = 1;
      pl[0] = dirss & 0xff;
      pl[1] = (dirss >> 8) & 0xff;
      pl[2] = fpos & 0xff;
      pl[3] = (fpos >> 8) & 0xff;
      pl[4] = 0x10;
      memset(pl + 5, '?', 11); /* the (fixed) client template for mask "*" */
      memset(&ans, 0, sizeof(ans));
      reqlen = build_req(frame, 0x42, pl, 16);
      rc = process(&ans, frame, reqlen, mymac, rootarray);
      if ((ans.frame[58] | (ans.frame[59] << 8)) != 0)
        break;
      show_resp("FINDNEXT*", ans.frame, rc);
      fpos = ans.frame[60 + 22] | (ans.frame[60 + 23] << 8);
    }
    if (!got_ext_file) {
      printf("  FAIL: mask \"*\" returned no file with an extension\n");
      return (1);
    }
    printf("  OK: mask \"*\" matched file(s) with extensions\n");
  }

  printf("=== exact long-name matching (Win95: names with spaces/~N aliases) ===\n");
  /* Regression: an exact long leaf whose FCB-ization differs from its SFN
   * alias ("my long file.txt" FCB-izes to "MY LONG TXT" but its alias strips
   * the spaces) was UNFINDABLE before the long-name-OR-SFN predicate. The
   * 716Ch open path resolves aliases through exactly this query. */
  {
    int hit = 0;
    pl[0] = 0x37;
    n = 1 + put_lfnstr(pl + 1, "\\my long file.txt");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x41, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    show_resp("FF-exact-spaces", ans.frame, rc);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: exact long name with spaces not found\n");
      return (1);
    }
    /* wildcard over the long name: "*file*" must find it too (old code
     * FCB-ized this to all-'?' and could false-match anything; now it must
     * match the long name properly) */
    pl[0] = 0x37;
    n = 1 + put_lfnstr(pl + 1, "\\*long f*");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x41, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    show_resp("FF-wild-long", ans.frame, rc);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: wildcard '*long f*' did not match the long name\n");
      return (1);
    }
    /* FINDNEXT with the OPTIONAL LFNSTR mask tail: enumerate "*file*" and
     * count matches -- must include both my-long-file and the .diz set's
     * file_id files (long-name matching), then terminate cleanly */
    pl[0] = 0x37;
    n = 1 + put_lfnstr(pl + 1, "\\*file*");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x41, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    dirss = ans.frame[60 + 20] | (ans.frame[60 + 21] << 8);
    fpos = ans.frame[60 + 22] | (ans.frame[60 + 23] << 8);
    while ((ans.frame[58] | (ans.frame[59] << 8)) == 0) {
      hit++;
      pl[0] = dirss & 0xff;
      pl[1] = (dirss >> 8) & 0xff;
      pl[2] = fpos & 0xff;
      pl[3] = (fpos >> 8) & 0xff;
      pl[4] = 0x37;
      memset(pl + 5, '?', 11);
      n = 16 + put_lfnstr(pl + 16, "*file*"); /* the additive mask tail */
      memset(&ans, 0, sizeof(ans));
      reqlen = build_req(frame, 0x42, pl, n);
      rc = process(&ans, frame, reqlen, mymac, rootarray);
      if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) break;
      show_resp("FN-wild-long", ans.frame, rc);
      fpos = ans.frame[60 + 22] | (ans.frame[60 + 23] << 8);
      if (hit > 30) { printf("  FAIL: runaway enumeration\n"); return (1); }
    }
    if (hit != 4) { /* file_id{,_long,_other}.diz + "my long file.txt";
                     * NOT readme.txt/mixedcase.txt (Win95 glob, no FCB leg) */
      printf("  FAIL: '*file*' matched %d entries (expect exactly 4)\n", hit);
      return (1);
    }
    printf("  OK: exact + wildcard long-name matching (%d '*file*' hits)\n", hit);
  }

  printf("=== increment 4: long parents + TRUENAME/MKDIR/RENAME ===\n");
  {
    unsigned char sub[300]; int sn, hits = 0;
    char shortpath[280];
    /* (a) FINDFIRST through a CASE-MISMATCHED long parent: resolve_path must
     * now match "LONG DIR NAME" against on-disk "Long Dir Name" */
    pl[0] = 0x37;
    n = 1 + put_lfnstr(pl + 1, "\\LONG DIR NAME\\*");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x41, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    show_resp("FF-longparent", ans.frame, rc);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: case-mismatched long parent not resolved\n");
      return (1);
    }
    /* (b) TRUENAME CL=1: long path -> full 8.3-alias path */
    pl[0] = 1;
    n = 1 + put_lfnstr(pl + 1, "\\Long Dir Name\\nested long file.txt");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x4D, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: truename CL=1 errored\n");
      return (1);
    }
    sn = ans.frame[60] | (ans.frame[61] << 8);
    if (sn > 279) sn = 279;
    memcpy(shortpath, ans.frame + 62, sn);
    shortpath[sn] = 0;
    printf("  TRUENAME CL=1: '%s'\n", shortpath);
    if (strchr(shortpath, ' ') != NULL) {
      printf("  FAIL: alias path still contains a space\n");
      return (1);
    }
    /* (c) the alias path must round-trip: FINDFIRST on it finds the file */
    pl[0] = 0x37;
    n = 1 + put_lfnstr(pl + 1, shortpath);
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x41, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    show_resp("FF-aliaspath", ans.frame, rc);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: alias path from CL=1 does not resolve\n");
      return (1);
    }
    /* (d) TRUENAME CL=2 on the alias path -> real long names back */
    pl[0] = 2;
    n = 1 + put_lfnstr(pl + 1, shortpath);
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x4D, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    sn = ans.frame[60] | (ans.frame[61] << 8);
    if (sn > 279) sn = 279;
    memcpy(shortpath, ans.frame + 62, sn);
    shortpath[sn] = 0;
    printf("  TRUENAME CL=2: '%s'\n", shortpath);
    if (strcmp(shortpath, "\\Long Dir Name\\nested long file.txt") != 0) {
      printf("  FAIL: CL=2 did not restore the long names\n");
      return (1);
    }
    /* (e) MKDIR with a long name, then find it */
    sn = put_lfnstr(sub, "\\Long Dir Name\\Nieuwe Lange Map");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x49, sub, sn);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: LFN_MKDIR errored\n");
      return (1);
    }
    pl[0] = 0x37;
    n = 1 + put_lfnstr(pl + 1, "\\Long Dir Name\\Nieuwe Lange*");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x41, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    show_resp("FF-newdir", ans.frame, rc);
    if (((ans.frame[58] | (ans.frame[59] << 8)) != 0) ||
        ((ans.frame[60] & 0x10) == 0)) {
      printf("  FAIL: created long dir not found (or not a DIR)\n");
      return (1);
    }
    /* (f) RENAME to a long target, then find it under the new name */
    sn = put_lfnstr(sub, "\\my long file.txt");
    sn += put_lfnstr(sub + sn, "\\Long Dir Name\\renamed even longer.txt");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x47, sub, sn);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: LFN_RENAME errored (AX=0x%02X)\n",
             ans.frame[58] | (ans.frame[59] << 8));
      return (1);
    }
    pl[0] = 0x37;
    n = 1 + put_lfnstr(pl + 1, "\\Long Dir Name\\renamed even longer.txt");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x41, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    show_resp("FF-renamed", ans.frame, rc);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: renamed long target not found\n");
      return (1);
    }
    /* (g) rename source must be gone; rename onto existing must fail (AX=5) */
    pl[0] = 0x37;
    n = 1 + put_lfnstr(pl + 1, "\\my long file.txt");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x41, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) == 0) {
      printf("  FAIL: rename source still exists\n");
      return (1);
    }
    sn = put_lfnstr(sub, "\\readme.txt");
    sn += put_lfnstr(sub + sn, "\\Long Dir Name\\renamed even longer.txt");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x47, sub, sn);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 5) {
      printf("  FAIL: rename onto existing target did not return AX=5\n");
      return (1);
    }
    /* (h) isroot regression: an EMPTY first-level subdirectory must still
     * list its synthetic '.' and '..' entries (both DIR). Before the isroot
     * fix a first-level subdir was misclassified as root, stripping '.'/'..',
     * so an empty one returned "no more files" (DOS "File not found"). */
    {
      unsigned short dss, fp2;
      int dircnt = 0;
      pl[0] = 0x37;
      n = 1 + put_lfnstr(pl + 1, "\\emptydir\\*");
      memset(&ans, 0, sizeof(ans));
      reqlen = build_req(frame, 0x41, pl, n);
      rc = process(&ans, frame, reqlen, mymac, rootarray);
      show_resp("FF-emptydir", ans.frame, rc);
      if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
        printf("  FAIL: empty first-level subdir listed nothing (isroot bug)\n");
        return (1);
      }
      if ((ans.frame[60] & 0x10) != 0) dircnt++;
      dss = ans.frame[60 + 20] | (ans.frame[60 + 21] << 8);
      fp2 = ans.frame[60 + 22] | (ans.frame[60 + 23] << 8);
      /* FINDNEXT to collect the second dot-entry */
      pl[0] = dss & 0xff; pl[1] = (dss >> 8) & 0xff;
      pl[2] = fp2 & 0xff; pl[3] = (fp2 >> 8) & 0xff;
      pl[4] = 0x37;
      memset(pl + 5, '?', 11);
      memset(&ans, 0, sizeof(ans));
      reqlen = build_req(frame, 0x42, pl, 16);
      rc = process(&ans, frame, reqlen, mymac, rootarray);
      if (((ans.frame[58] | (ans.frame[59] << 8)) == 0) &&
          ((ans.frame[60] & 0x10) != 0))
        dircnt++;
      if (dircnt < 2) {
        printf("  FAIL: empty subdir did not return '.' and '..' (got %d)\n",
               dircnt);
        return (1);
      }
    }
    /* (i) empty-path TRUENAME (bare "X:" -> caller strips to len 0). Must NOT
     * be dropped (-1); must return the canonical root "\\". This is the exact
     * frame Norton Commander sends when opening a drive; the old >=4 guard let
     * it fall through to return(-1) -> no reply -> INT 24h "cannot read drive". */
    {
      unsigned char ep[4];
      int r2;
      ep[0] = 2;      /* subfn 2 (alias -> long) */
      ep[1] = 0;      /* LFNSTR length = 0 (empty path) */
      ep[2] = 0;
      memset(&ans, 0, sizeof(ans));
      reqlen = build_req(frame, 0x4D, ep, 3);
      r2 = process(&ans, frame, reqlen, mymac, rootarray);
      if (r2 <= 0) {
        printf("  FAIL: empty-path TRUENAME dropped (rc=%d) -- NC 'cannot read drive'\n", r2);
        return (1);
      }
      if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
        printf("  FAIL: empty-path TRUENAME returned AX=%d\n",
               ans.frame[58] | (ans.frame[59] << 8));
        return (1);
      }
      if (((ans.frame[60] | (ans.frame[61] << 8)) != 1) || (ans.frame[62] != '\\')) {
        printf("  FAIL: empty-path TRUENAME did not return root '\\'\n");
        return (1);
      }
    }
    (void)hits;
    printf("  OK: long parents, truename round-trip, mkdir/rename-long, dotdirs, empty-truename\n");
  }

  printf("=== increment 6: OEM codepage (CP437) wire<->disk ===\n");
  {
    int ln6, j6, has82, hasC3;
    /* (a) 'caf\xc3\xa9.txt' exists on disk as UTF-8; the client asks for it by
     * its CP437 name "caf\x82.txt" (0x82 == e-acute in CP437). Must resolve, and
     * the long name handed back must be CP437 (0x82), never UTF-8 (0xC3 0xA9). */
    pl[0] = 0x37;
    n = 1 + put_lfnstr(pl + 1, "\\caf\x82.txt");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x41, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: CP437 name did not resolve the UTF-8 disk file\n");
      return (1);
    }
    ln6 = ans.frame[93] | (ans.frame[94] << 8);
    has82 = 0; hasC3 = 0;
    for (j6 = 0; j6 < ln6; j6++) {
      unsigned char c = (unsigned char)ans.frame[95 + j6];
      if (c == 0x82) has82 = 1;
      if (c == 0xC3) hasC3 = 1;
    }
    if (!has82 || hasC3) {
      printf("  FAIL: long name not CP437 (has82=%d hasC3=%d)\n", has82, hasC3);
      return (1);
    }
    /* (b) create via a CP437 name (ni<0xA4>o6.txt, 0xA4 == n-tilde), then find it
     * back -- proves wire->disk on create + disk->wire on the subsequent list. */
    pl[0] = 0x20; pl[1] = 0x00;
    n = 2 + put_lfnstr(pl + 2, "\\ni\xa4o6.txt");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x44, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: CP437 create errored (AX=%d)\n",
             ans.frame[58] | (ans.frame[59] << 8));
      return (1);
    }
    pl[0] = 0x37;
    n = 1 + put_lfnstr(pl + 1, "\\ni\xa4o6.txt");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x41, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: CP437-created file not found back\n");
      return (1);
    }
    /* (c) the 8.3 alias of an accented name must be 7-BIT: DOS normalizes
     * high bytes in 8.3 names on the classic path (wire-observed: 0x82->'E',
     * 0x81->0x9A), so an alias containing them cannot round-trip through a
     * classic open. truename CL=1 must return a pure-ASCII alias path, and
     * that path must resolve back to the file. */
    pl[0] = 1;
    n = 1 + put_lfnstr(pl + 1, "\\caf\x82.txt");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x4D, pl, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: truename CL=1 on accented name errored\n");
      return (1);
    }
    ln6 = ans.frame[60] | (ans.frame[61] << 8);
    for (j6 = 0; j6 < ln6; j6++) {
      if ((unsigned char)ans.frame[62 + j6] >= 0x80) {
        printf("  FAIL: alias path contains a high byte (won't survive DOS "
               "filename normalization)\n");
        return (1);
      }
    }
    {
      char apath[280];
      if (ln6 > 270) ln6 = 270;
      memcpy(apath, ans.frame + 62, ln6);
      apath[ln6] = 0;
      pl[0] = 0x37;
      n = 1 + put_lfnstr(pl + 1, apath);
      memset(&ans, 0, sizeof(ans));
      reqlen = build_req(frame, 0x41, pl, n);
      rc = process(&ans, frame, reqlen, mymac, rootarray);
      if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
        printf("  FAIL: 7-bit alias path did not resolve back (%s)\n", apath);
        return (1);
      }
    }
    printf("  OK: CP437 list + resolve + create round-trip + 7-bit alias\n");
  }

  printf("=== hardening: short payloads, case-duplicates, oversized legacy ===\n");
  {
    unsigned char hp[520];
    int r7;
    /* (a) known LFN opcode with a short payload must ANSWER with an error --
     * never silent-drop (the empty-path TRUENAME / NC bug class) */
    hp[0] = 0x00;
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x49, hp, 1); /* mkdir with 1-byte payload */
    r7 = process(&ans, frame, reqlen, mymac, rootarray);
    if (r7 <= 0) {
      printf("  FAIL: short-payload 0x49 was silently dropped (rc=%d)\n", r7);
      return (1);
    }
    if ((ans.frame[58] | (ans.frame[59] << 8)) == 0) {
      printf("  FAIL: short-payload 0x49 returned success\n");
      return (1);
    }
    /* (b) MKDIR case-duplicate: "long dir name" next to "Long Dir Name" */
    n = put_lfnstr(hp, "\\long dir name");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x49, hp, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 5) {
      printf("  FAIL: case-duplicate mkdir did not return AX=5 (got %d)\n",
             ans.frame[58] | (ans.frame[59] << 8));
      return (1);
    }
    /* (c) RENAME onto a case-variant of an EXISTING other file -> AX=5 */
    n = put_lfnstr(hp, "\\readme.txt");
    n += put_lfnstr(hp + n, "\\FILE_ID.DIZ"); /* exists as file_id.diz */
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x47, hp, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 5) {
      printf("  FAIL: rename onto case-variant of other file != AX=5 (%d)\n",
             ans.frame[58] | (ans.frame[59] << 8));
      return (1);
    }
    /* (d) pure case-rename of the SAME file must be allowed */
    n = put_lfnstr(hp, "\\mixedcase.txt");
    n += put_lfnstr(hp + n, "\\MixedCase.txt");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x47, hp, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: pure case-rename refused (AX=%d)\n",
             ans.frame[58] | (ans.frame[59] << 8));
      return (1);
    }
    /* (e) oversized legacy CHDIR path (480 bytes) must not smash the stack;
     * the clamped path simply fails to resolve -> error, and the server keeps
     * answering afterwards */
    memset(hp, 'A', 480);
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x05, hp, 480);
    r7 = process(&ans, frame, reqlen, mymac, rootarray);
    if (r7 <= 0) {
      printf("  FAIL: oversized legacy CHDIR dropped (rc=%d)\n", r7);
      return (1);
    }
    if ((ans.frame[58] | (ans.frame[59] << 8)) == 0) {
      printf("  FAIL: oversized legacy CHDIR claimed success\n");
      return (1);
    }
    /* server still alive? */
    hp[0] = 0x37;
    n = 1 + put_lfnstr(hp + 1, "\\readme.txt");
    memset(&ans, 0, sizeof(ans));
    reqlen = build_req(frame, 0x41, hp, n);
    rc = process(&ans, frame, reqlen, mymac, rootarray);
    if ((ans.frame[58] | (ans.frame[59] << 8)) != 0) {
      printf("  FAIL: server wedged after oversized frame\n");
      return (1);
    }
    printf("  OK: short-payload answer, case-dup mkdir/rename=5, case-rename ok, oversize clamped\n");
  }

  printf("=== AL_LFN_CREATE (0x44) a 9-char-base long file ===\n");
  pl[0] = 0x20; /* cattr archive */
  pl[1] = 0x00;
  n = 2 + put_lfnstr(pl + 2, "\\file_id_wire_created.diz");
  memset(&ans, 0, sizeof(ans));
  reqlen = build_req(frame, 0x44, pl, n);
  rc = process(&ans, frame, reqlen, mymac, rootarray);
  show_resp("CREATE", ans.frame, rc);

  printf("=== AL_LFN_OPEN (0x43) the just-created file ===\n");
  pl[0] = 0x00; /* mode read */
  n = 1 + put_lfnstr(pl + 1, "\\file_id_wire_created.diz");
  memset(&ans, 0, sizeof(ans));
  reqlen = build_req(frame, 0x43, pl, n);
  rc = process(&ans, frame, reqlen, mymac, rootarray);
  show_resp("OPEN", ans.frame, rc);

  printf("=== AL_LFN_FINDFIRST malformed: empty LFNSTR (must not crash) ===\n");
  pl[0] = 0x37;
  pl[1] = 0x00;
  pl[2] = 0x00; /* LFNSTR length 0 */
  memset(&ans, 0, sizeof(ans));
  reqlen = build_req(frame, 0x41, pl, 3);
  rc = process(&ans, frame, reqlen, mymac, rootarray);
  printf("  empty-FINDFIRST rc=%d AX=0x%02X (survived, no crash)\n", rc,
         ans.frame[58] | (ans.frame[59] << 8));

  return (0);
}
