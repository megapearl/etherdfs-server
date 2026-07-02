/* Golden-vector regression test for the client's FILETIME <-> DOS date/time
 * conversion (client/src/FTCONV.H, the INT 21h/AX=71A7h responder core).
 * Compiles the SAME algorithm the 16-bit TSR runs (FTCONV_HOSTTEST swaps the
 * two native MUL/DIV asm primitives for plain-C equivalents with identical
 * semantics). Vectors were generated independently with Python's datetime
 * (proleptic Gregorian, seconds since 1601-01-01, x10^7 for 100ns units). */
#define FTCONV_HOSTTEST 1
#include <stdio.h>
#include <string.h>
#include "FTCONV.H"

struct vec {
  unsigned long ft_lo, ft_hi;   /* input FILETIME */
  unsigned short dosdate, dostime;
  unsigned char bh;
  unsigned long ftrev_lo, ftrev_hi; /* expected reverse (2-sec granularity) */
  const char *label;
};

static struct vec vecs[] = {
  {0xe1d58000ul, 0x01a8e79ful, 0x0021, 0x0000,   0, 0xe1d58000ul, 0x01a8e79ful, "1980-01-01 00:00:00.00"},
  {0xe306ad00ul, 0x01a8e79ful, 0x0021, 0x0001,   0, 0xe306ad00ul, 0x01a8e79ful, "1980-01-01 00:00:02.00"},
  {0x60c249c0ul, 0x01dd0a2bul, 0x5ce2, 0x7045, 142, 0x5fe99d00ul, 0x01dd0a2bul, "2026-07-02 14:02:11.42"},
  {0xc3c53700ul, 0x01bf82b0ul, 0x285d, 0x63cf,   0, 0xc3c53700ul, 0x01bf82b0ul, "2000-02-29 12:30:30.00"},
  {0x66b8a2e0ul, 0x01da6b6bul, 0x585d, 0xbf7d,  99, 0x66219300ul, 0x01da6b6bul, "2024-02-29 23:59:58.99"},
  {0x24d4a980ul, 0x01bf53ebul, 0x279f, 0xbf7d, 100, 0x243c1300ul, 0x01bf53ebul, "1999-12-31 23:59:59.00"},
  {0x7632d300ul, 0x022f7163ul, 0xef9f, 0xbf7d,   0, 0x7632d300ul, 0x022f7163ul, "2099-12-31 23:59:58.00"},
  {0x66d29300ul, 0x023868b8ul, 0xff9f, 0xbf7d,   0, 0x66d29300ul, 0x023868b8ul, "2107-12-31 23:59:58.00"},
  {0x89775f00ul, 0x01af0535ul, 0x0acf, 0x4083,   0, 0x89775f00ul, 0x01af0535ul, "1985-06-15 08:04:06.00"},
};

static void load_ft(unsigned long lo, unsigned long hi) {
  ftc_w[0] = (unsigned short)(lo & 0xffffu);
  ftc_w[1] = (unsigned short)(lo >> 16);
  ftc_w[2] = (unsigned short)(hi & 0xffffu);
  ftc_w[3] = (unsigned short)(hi >> 16);
}

int main(void) {
  int i, fails = 0;
  printf("=== FTCONV golden vectors (ft2dos + dos2ft) ===\n");
  for (i = 0; i < (int)(sizeof(vecs) / sizeof(vecs[0])); i++) {
    struct vec *v = &vecs[i];
    unsigned long rlo, rhi;
    load_ft(v->ft_lo, v->ft_hi);
    if (ftc_ft2dos() != 0) {
      printf("  FAIL %s: ft2dos returned invalid\n", v->label);
      fails++;
      continue;
    }
    if ((ftc_dosdate != v->dosdate) || (ftc_dostime != v->dostime) || (ftc_bh != v->bh)) {
      printf("  FAIL %s: got date=%04x time=%04x bh=%u want %04x/%04x/%u\n",
             v->label, ftc_dosdate, ftc_dostime, ftc_bh,
             v->dosdate, v->dostime, v->bh);
      fails++;
      continue;
    }
    ftc_dosdate = v->dosdate;
    ftc_dostime = v->dostime;
    if (ftc_dos2ft() != 0) {
      printf("  FAIL %s: dos2ft returned invalid\n", v->label);
      fails++;
      continue;
    }
    rlo = ((unsigned long)ftc_w[1] << 16) | ftc_w[0];
    rhi = ((unsigned long)ftc_w[3] << 16) | ftc_w[2];
    if ((rlo != v->ftrev_lo) || (rhi != v->ftrev_hi)) {
      printf("  FAIL %s: dos2ft got %08lx:%08lx want %08lx:%08lx\n",
             v->label, rhi, rlo, v->ftrev_hi, v->ftrev_lo);
      fails++;
      continue;
    }
    printf("  OK  %s\n", v->label);
  }
  /* invalid inputs must be rejected */
  load_ft(0, 0);
  if (ftc_ft2dos() == 0) { printf("  FAIL: zero FILETIME accepted\n"); fails++; }
  load_ft(0xb76bc000ul, 0x01a8e6d6ul); /* 1979-12-31: before DOS epoch */
  if (ftc_ft2dos() == 0) { printf("  FAIL: pre-1980 accepted\n"); fails++; }
  load_ft(0x6803c000ul, 0x023868b8ul); /* 2108-01-01: past DOS date range */
  if (ftc_ft2dos() == 0) { printf("  FAIL: post-2107 accepted\n"); fails++; }
  if (fails == 0) printf("  OK: invalid inputs rejected\n");

  /* exhaustive round-trip: every valid DOS date 1980..2107 (fixed 13:24:36)
   * must survive dos2ft -> ft2dos unchanged */
  {
    unsigned short y, m, d, md, dd, tt = (13 << 11) | (24 << 5) | (36 >> 1);
    long n = 0, bad = 0;
    for (y = 1980; y <= 2107; y++) {
      for (m = 1; m <= 12; m++) {
        md = ftc_mdays[m - 1];
        if ((m == 2) && ftc_isleap(y)) md++;
        for (d = 1; d <= md; d++) {
          dd = (unsigned short)(((y - 1980) << 9) | (m << 5) | d);
          ftc_dosdate = dd;
          ftc_dostime = tt;
          if (ftc_dos2ft() != 0) { bad++; continue; }
          if (ftc_ft2dos() != 0) { bad++; continue; }
          if ((ftc_dosdate != dd) || (ftc_dostime != tt)) bad++;
          n++;
        }
      }
    }
    printf("  round-trip sweep: %ld dates, %ld bad\n", n, bad);
    if (bad) fails++;
  }

  printf(fails ? "FTCONV: %d FAILURES\n" : "FTCONV: all green\n", fails);
  return(fails ? 1 : 0);
}
