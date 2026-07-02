/*
 * FTCONV.H - FILETIME <-> DOS date/time conversion for INT 21h/AX=71A7h
 * (FileTimeToDosDateTime BL=0 / DosDateTimeToFileTime BL=1).
 *
 * Part of the EtherDFS LFN client. LFN-aware shells (4DOS) request find
 * results as 64-bit FILETIMEs (SI=0) and then call 71A7h to convert them for
 * display; without this responder the call chains to a non-LFN DOS kernel,
 * fails, and DIR shows blank date/time columns.
 *
 * RESIDENT-SAFETY RULES (this file is included in the BEGTEXT resident part):
 *  - NO 32-bit multiply/divide/modulo in C: OpenWatcom emits calls to runtime
 *    helpers (__U4M/__U4D/...) that live in the transient _TEXT segment,
 *    which is FREED after the TSR call - calling them from resident code
 *    would jump into freed memory. All mul/div go through the two native
 *    16-bit primitives below. u32 add/sub/shift/compare are inlined by wcc
 *    and safe.
 *  - The interrupt handler runs with DS = resident segment but SS = caller
 *    stack, and small-model near pointers are DS-relative: passing pointers
 *    to STACK locals between functions would dereference the wrong segment.
 *    So all multi-word working state lives in resident statics (ftc_*).
 *  - Reentrancy: the ftc_* statics are shared, and a nested conversion could
 *    clobber ftc_r between a remainder store and its use as the next DIV's
 *    high word -- violating the hi<d precondition and raising #DE, not just a
 *    wrong date. The 71A7h dispatcher therefore brackets each conversion with
 *    the ftc_busy flag and fails a nested call with CF/ERROR_INVALID_DATA
 *    (the caller shows one blank date; nothing faults or corrupts).
 *
 * The FILETIMEs on the EtherDFS wire are LOCAL wall-clock (the server
 * pre-shifts by its timezone, see fs.c time2filetime), so NO timezone math
 * belongs here - this is a pure calendar conversion.
 *
 * Define FTCONV_HOSTTEST to compile on a modern host (plain C primitives
 * instead of inline asm) for the golden-vector regression test
 * (tests/test_ftconv.c).
 */

#ifndef FTCONV_SENTINEL
#define FTCONV_SENTINEL

/* seconds from 1601-01-01 to 1980-01-01 = 138426 days * 86400
 * = 11960006400 = words {0x3700, 0xc8df, 0x0002, 0x0000} little-endian */
#define FTC_EPOCH_W0 0x3700u
#define FTC_EPOCH_W1 0xc8dfu
#define FTC_EPOCH_W2 0x0002u

/* working state + primitive results (resident statics, see header comment) */
static unsigned char ftc_busy = 0; /* reentrancy guard, set by the dispatcher */
static unsigned short ftc_w[4];    /* 64-bit value, little-endian words */
static unsigned short ftc_mlo, ftc_mhi; /* ftc_mul16 result */
static unsigned short ftc_q, ftc_r;     /* ftc_div3216 result */
static unsigned short ftc_dosdate, ftc_dostime;
static unsigned char ftc_bh;       /* hundredths (0..199, incl. odd second) */

static unsigned char ftc_mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};

#ifdef FTCONV_HOSTTEST
static void ftc_mul16(unsigned short a, unsigned short b) {
  unsigned long t = (unsigned long)a * (unsigned long)b;
  ftc_mlo = (unsigned short)(t & 0xffffu);
  ftc_mhi = (unsigned short)(t >> 16);
}
static void ftc_div3216(unsigned short hi, unsigned short lo, unsigned short d) {
  unsigned long t = ((unsigned long)hi << 16) | lo;
  ftc_q = (unsigned short)(t / d);
  ftc_r = (unsigned short)(t % d);
}
#else
static void ftc_mul16(unsigned short a, unsigned short b) {
  _asm {
    mov ax, a
    mul word ptr b
    mov ftc_mlo, ax
    mov ftc_mhi, dx
  }
}
/* 32/16 -> 16 divide via native DIV. PRECONDITION: hi < d (else #DE); every
 * call site below guarantees it (word-wise long division invariant). */
static void ftc_div3216(unsigned short hi, unsigned short lo, unsigned short d) {
  _asm {
    mov dx, hi
    mov ax, lo
    div word ptr d
    mov ftc_q, ax
    mov ftc_r, dx
  }
}
#endif

/* divide ftc_w (64-bit) in place by d; returns the remainder (< d) */
static unsigned short ftc_div64(unsigned short d) {
  unsigned short rem = 0;
  int i;
  for (i = 3; i >= 0; i--) {
    ftc_div3216(rem, ftc_w[i], d); /* rem < d, so quotient fits 16 bits */
    ftc_w[i] = ftc_q;
    rem = ftc_r;
  }
  return rem;
}

/* multiply ftc_w (64-bit) in place by m, then add a (both 16-bit) */
static void ftc_mul64(unsigned short m, unsigned short a) {
  unsigned short carry = a;
  unsigned long t;
  int i;
  for (i = 0; i < 4; i++) {
    ftc_mul16(ftc_w[i], m);
    /* max 0xFFFF*0xFFFF + 0xFFFF = 0xFFFF0000: no u32 overflow */
    t = (((unsigned long)ftc_mhi << 16) | ftc_mlo) + carry;
    ftc_w[i] = (unsigned short)(t & 0xffffu);
    carry = (unsigned short)(t >> 16);
  }
}

/* shift ftc_w (64-bit) left by n bits (n must be 1..15: the (16-n) inner
 * shift makes n=0 undefined-ish on 286+ CL-masking; only ever called with 7) */
static void ftc_shl64(unsigned short n) {
  int i;
  for (i = 3; i > 0; i--)
    ftc_w[i] = (unsigned short)((ftc_w[i] << n) | (ftc_w[i - 1] >> (16 - n)));
  ftc_w[0] = (unsigned short)(ftc_w[0] << n);
}

static int ftc_isleap(unsigned short y) {
  if ((y & 3) != 0) return(0);
  if ((y % 100) != 0) return(1);
  return((y % 400) == 0);
}

/* FILETIME (in ftc_w) -> DOS date/time (ftc_dosdate/ftc_dostime/ftc_bh).
 * Returns 0 on success, -1 if zero or out of the DOS range (1980..2107). */
static int ftc_ft2dos(void) {
  unsigned short r2, days, y, m, md, hh, mi, ss;
  unsigned long secs, t, tod;
  unsigned short borrow;
  if ((ftc_w[0] | ftc_w[1] | ftc_w[2] | ftc_w[3]) == 0) return(-1);
  /* 100ns units -> seconds: /10^7 as /10000 then /1000 (16-bit divisors) */
  ftc_div64(10000); /* remainder r1 < 10000 does not affect hundredths: */
  r2 = ftc_div64(1000);
  /* sub-second remainder = r2*10000+r1 (100ns); hundredths = that /100000,
   * and since r1 < 10000: floor((r2*10000+r1)/100000) = floor(r2/10) */
  ftc_bh = (unsigned char)(r2 / 10);
  /* subtract seconds(1601->1980), word-wise with borrow */
  borrow = (ftc_w[0] < FTC_EPOCH_W0) ? 1 : 0;
  ftc_w[0] = (unsigned short)(ftc_w[0] - FTC_EPOCH_W0);
  t = (unsigned long)ftc_w[1];
  if (t < (unsigned long)FTC_EPOCH_W1 + borrow) {
    ftc_w[1] = (unsigned short)(ftc_w[1] - FTC_EPOCH_W1 - borrow);
    borrow = 1;
  } else {
    ftc_w[1] = (unsigned short)(ftc_w[1] - FTC_EPOCH_W1 - borrow);
    borrow = 0;
  }
  if (ftc_w[2] < FTC_EPOCH_W2 + borrow) return(-1); /* before 1980 */
  ftc_w[2] = (unsigned short)(ftc_w[2] - FTC_EPOCH_W2 - borrow);
  if ((ftc_w[2] | ftc_w[3]) != 0) return(-1); /* far past 2107 */
  secs = ((unsigned long)ftc_w[1] << 16) | ftc_w[0];
  /* days = secs/86400 = (secs>>7)/675 ; (secs>>7) <= 33.5M so hi word < 675 */
  t = secs >> 7;
  ftc_div3216((unsigned short)(t >> 16), (unsigned short)(t & 0xffffu), 675);
  days = ftc_q;
  /* tod = secs - days*86400 ; days*86400 = (days*675)<<7 */
  ftc_mul16(days, 675);
  tod = (((unsigned long)ftc_mhi << 16) | ftc_mlo) << 7;
  tod = secs - tod; /* < 86400 */
  /* time of day: tod <= 86399 so (tod>>16) <= 1 < 3600 */
  ftc_div3216((unsigned short)(tod >> 16), (unsigned short)(tod & 0xffffu), 3600);
  hh = ftc_q;         /* < 24 */
  mi = ftc_r / 60;
  ss = ftc_r % 60;
  /* date from day count */
  y = 1980;
  for (;;) {
    md = ftc_isleap(y) ? 366 : 365;
    if (days < md) break;
    days = (unsigned short)(days - md);
    y++;
    if (y > 2107) return(-1);
  }
  for (m = 1; m <= 12; m++) {
    md = ftc_mdays[m - 1];
    if ((m == 2) && ftc_isleap(y)) md++;
    if (days < md) break;
    days = (unsigned short)(days - md);
  }
  ftc_dosdate = (unsigned short)(((y - 1980) << 9) | (m << 5) | (days + 1));
  ftc_dostime = (unsigned short)((hh << 11) | (mi << 5) | (ss >> 1));
  ftc_bh = (unsigned char)(ftc_bh + ((ss & 1) ? 100 : 0));
  return(0);
}

/* DOS date/time (ftc_dosdate/ftc_dostime) -> FILETIME (in ftc_w).
 * 2-second granularity, no hundredths. Returns 0 on success, -1 on invalid. */
static int ftc_dos2ft(void) {
  unsigned short y, m, d, hh, mi, ss, days, md, yy;
  unsigned long t, tod;
  y  = (unsigned short)(1980 + (ftc_dosdate >> 9));
  m  = (unsigned short)((ftc_dosdate >> 5) & 0x0f);
  d  = (unsigned short)(ftc_dosdate & 0x1f);
  hh = (unsigned short)(ftc_dostime >> 11);
  mi = (unsigned short)((ftc_dostime >> 5) & 0x3f);
  ss = (unsigned short)((ftc_dostime & 0x1f) << 1);
  if ((m < 1) || (m > 12) || (d < 1) || (hh > 23) || (mi > 59)) return(-1);
  md = ftc_mdays[m - 1];
  if ((m == 2) && ftc_isleap(y)) md++;
  if (d > md) return(-1);
  days = 0;
  for (yy = 1980; yy < y; yy++)
    days = (unsigned short)(days + (ftc_isleap(yy) ? 366 : 365));
  for (yy = 1; yy < m; yy++) {
    md = ftc_mdays[yy - 1];
    if ((yy == 2) && ftc_isleap(y)) md++;
    days = (unsigned short)(days + md);
  }
  days = (unsigned short)(days + d - 1);
  /* seconds since 1601 = (days + 138426)*86400 + tod ; then *10^7.
   * total days <= 185177 (18 bits) -> keep in ftc_w and multiply word-wise */
  t = (unsigned long)days + 138426ul;
  ftc_w[0] = (unsigned short)(t & 0xffffu);
  ftc_w[1] = (unsigned short)(t >> 16);
  ftc_w[2] = 0;
  ftc_w[3] = 0;
  ftc_mul64(675, 0);   /* *86400 = *675 then <<7 */
  ftc_shl64(7);
  ftc_mul16(hh, 3600); /* tod = hh*3600 + mi*60 + ss (<= 86399) */
  tod = (((unsigned long)ftc_mhi << 16) | ftc_mlo)
        + (unsigned long)(mi * 60u) + ss;
  /* add tod into ftc_w, word-wise with carry */
  t = (unsigned long)ftc_w[0] + (tod & 0xffffu);
  ftc_w[0] = (unsigned short)(t & 0xffffu);
  t = (unsigned long)ftc_w[1] + (tod >> 16) + (t >> 16);
  ftc_w[1] = (unsigned short)(t & 0xffffu);
  t = (unsigned long)ftc_w[2] + (t >> 16);
  ftc_w[2] = (unsigned short)(t & 0xffffu);
  ftc_w[3] = (unsigned short)(ftc_w[3] + (unsigned short)(t >> 16));
  ftc_mul64(10000, 0); /* *10^7 = *10000 then *1000 */
  ftc_mul64(1000, 0);
  return(0);
}

#endif /* FTCONV_SENTINEL */
