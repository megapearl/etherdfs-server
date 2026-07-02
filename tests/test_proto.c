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
