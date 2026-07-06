/*
 * net_dos.c - Crynwr/FTP packet-driver backend for net.h (MS-DOS, DJGPP v2).
 *
 * "Option A": drive the real-mode packet-driver TSR directly from 32-bit
 * protected mode. Every pointer handed to the driver is a real-mode seg:off into
 * conventional memory (three DOS buffers: RX bounce, TX, and the ethertype
 * template). The receiver is a DPMI real-mode callback allocated with the RETF
 * variant, because the driver FAR-CALLs it and expects a far return, not IRET.
 * The callback runs at interrupt time after a real->protected switch, so it does
 * NO libc/DOS work beyond the leaf dosmemget; it drains one frame into a locked
 * single-producer/single-consumer ring that net_recv() consumes. Frame length
 * excludes the FCS and includes the 14-byte MAC header, on both the receive
 * upcall and send_pkt - matching the libpcap/WinPcap backends.
 *
 * The three DOS buffers are kept separate on purpose: reusing the RX bounce for
 * TX lets an inbound frame (whose AX=0 phase re-hands rx_seg to the driver)
 * clobber a frame mid-send, and reusing it for the ethertype template lets the
 * first received frame corrupt the filter if the driver retained the pointer.
 *
 * ethersrv is distributed under the terms of the MIT License (see ethersrv.c).
 */
#include <crt0.h>         /* _CRT0_FLAG_LOCK_MEMORY */
#include <dpmi.h>         /* __dpmi_regs, _go32_dpmi_*, __dpmi_int, __dpmi_yield */
#include <go32.h>         /* _go32_my_cs, _dos_ds, _go32_info_block */
#include <stdio.h>
#include <string.h>
#include <sys/farptr.h>   /* _farpeekl (BIOS tick) */
#include <sys/movedata.h> /* dosmemget, dosmemput */

#include "net.h"

/* Lock the whole image so nothing the interrupt-time callback touches (its own
 * code, the ring, and the libc dosmemget it calls) can be paged out. Safe on a
 * dedicated box with ample RAM. The selective locks below are belt-and-braces. */
int _crt0_startup_flags = _CRT0_FLAG_LOCK_MEMORY;

#define DOSBUF_SIZE 2048 /* >= max frame; the server frame buffer is 2048 */
#define RING_SLOTS 32

/* ---- SPSC ring: producer = callback (writes head), consumer = net_recv ---- */
typedef struct {
  volatile unsigned head; /* advanced only by the callback */
  volatile unsigned tail; /* advanced only by net_recv */
  volatile unsigned long drops;
  unsigned short len[RING_SLOTS];
  unsigned char data[RING_SLOTS][DOSBUF_SIZE];
} ring_t;
static ring_t ring;

/* ---- driver / DOS state ---- */
static int pkt_vec = 0;     /* packet-driver INT vector (0x60..0x80) */
static int pkt_handle = 0;  /* access_type handle (0 can be a VALID handle) */
static int handle_open = 0; /* separate flag: pkt_handle==0 is not 'unset' */
static unsigned short rx_seg = 0;
static int rx_sel = 0; /* RX bounce buffer */
static unsigned short tx_seg = 0;
static int tx_sel = 0; /* TX frame buffer */
static unsigned short typ_seg = 0;
static int typ_sel = 0; /* ethertype template */
static _go32_dpmi_seginfo cb_info;
static _go32_dpmi_registers cb_regs;
static int cb_installed = 0;

/* ================= interrupt-time receiver (locked, no DOS/libc) ========== */
static void rx_callback(_go32_dpmi_registers *r) {
  if ((r->x.ax & 0xff) == 0) {   /* AX=0: buffer request */
    unsigned clen = r->x.cx;     /* frame len incl MAC hdr, no FCS */
    if (clen == 0 || clen > DOSBUF_SIZE) { /* can't take it -> drop */
      r->x.es = 0;
      r->x.di = 0;
    } else {
      r->x.es = rx_seg; /* driver copies frame to rx_seg:0 */
      r->x.di = 0;
    }
    return;
  }
  { /* AX=1: copy complete */
    unsigned len = r->x.cx, h = ring.head, nxt = h + 1;
    if (nxt >= RING_SLOTS)
      nxt = 0;
    if (len > DOSBUF_SIZE)
      len = DOSBUF_SIZE;
    if (nxt == ring.tail) { /* ring full */
      ring.drops++;
      return;
    }
    dosmemget((unsigned long)rx_seg << 4, (int)len, ring.data[h]);
    ring.len[h] = (unsigned short)len;
    __asm__ __volatile__("" ::: "memory"); /* publish barrier */
    ring.head = nxt;
  }
}
static void rx_callback_end(void) {} /* code-span marker for locking */

/* ================= timing (BIOS tick @ 0040:006C, ~18.2065 Hz) ============ */
/* The BIOS tick dword counts 0..0x1800AF and is RESET TO 0 at midnight (it is
 * not a free-running power-of-2 wrap), so never compare against an absolute
 * deadline - a deadline computed within a tick of midnight could exceed the
 * counter's maximum and never be reached, hanging net_recv forever on an idle
 * link. All timing below is elapsed-based with explicit reset detection. */
#define BIOS_TICKS_PER_DAY 0x1800B0UL /* 1,573,040: counter range is 0..0x1800AF */
static unsigned long bios_ticks(void) { return _farpeekl(_dos_ds, 0x46C); }
static unsigned long ticks_elapsed(unsigned long start) {
  unsigned long now = bios_ticks();
  if (now >= start)
    return now - start;
  return now + (BIOS_TICKS_PER_DAY - start); /* counter reset at midnight */
}
static unsigned long ms_to_ticks(int ms) {
  /* round UP and floor at one tick: truncating would turn any timeout below
   * ~55 ms into 0 ticks, making net_recv return instantly without yielding */
  unsigned long t = ((unsigned long)ms * 1821UL + 99999UL) / 100000UL;
  if (ms > 0 && t == 0)
    t = 1;
  return t;
}

/* ================= driver detection ======================================= */
static int find_pkt_driver(void) {
  int v;
  char sig[8];
  unsigned long vec, lin;
  for (v = 0x60; v <= 0x80; v++) {
    dosmemget(v * 4, 4, &vec); /* IVT slot = {off16, seg16} */
    if (vec == 0)
      continue;
    lin = ((vec >> 16) << 4) + (vec & 0xffff) + 3; /* handler+3 (past the JMP) */
    dosmemget((int)lin, 8, sig);
    if (memcmp(sig, "PKT DRVR", 8) == 0) {
      pkt_vec = v;
      return 0;
    }
  }
  return -1;
}

/* Allocate a conventional-memory buffer; returns the rm segment or 0 on error. */
static unsigned short dos_alloc(int bytes, int *sel_out) {
  int para = (bytes + 15) / 16;
  int seg = __dpmi_allocate_dos_memory(para, sel_out);
  if (seg < 0)
    return 0;
  return (unsigned short)seg;
}

int net_open(unsigned short ethertype, const char *ifname,
             unsigned char mymac_out[6]) {
  __dpmi_regs r;
  unsigned char t[2];
  (void)ifname; /* a single packet driver: ifname is unused on DOS */

  if (find_pkt_driver() != 0) {
    fprintf(stderr, "Error: no packet driver found (scanned INT 60h..80h).\n");
    return -1;
  }

  /* driver_info (AH=01h, AL=0FFh mandatory): validate + class for diagnostic */
  memset(&r, 0, sizeof r);
  r.h.ah = 0x01;
  r.h.al = 0xFF;
  r.x.bx = 0;
  __dpmi_int(pkt_vec, &r);
  if ((r.x.flags & 1) || r.h.al == 0xFF) {
    fprintf(stderr, "Error: INT %02Xh is not a usable packet driver.\n",
            pkt_vec);
    return -1;
  }
  if (r.h.ch != 1) /* class 1 = DIX/Bluebook Ethernet */
    fprintf(stderr,
            "Warning: packet driver class %u is not DIX Ethernet (1).\n",
            (unsigned)r.h.ch);

  /* three DOS conventional-memory buffers */
  rx_seg = dos_alloc(DOSBUF_SIZE, &rx_sel);
  tx_seg = dos_alloc(DOSBUF_SIZE, &tx_sel);
  typ_seg = dos_alloc(16, &typ_sel);
  if (!rx_seg || !tx_seg || !typ_seg) {
    fprintf(stderr, "Error: DOS conventional-memory allocation failed.\n");
    net_close();
    return -1;
  }

  /* RETF real-mode callback (the driver FAR-CALLs it, returns via RETF) */
  cb_info.pm_offset = (unsigned long)rx_callback;
  cb_info.pm_selector = _go32_my_cs();
  if (_go32_dpmi_allocate_real_mode_callback_retf(&cb_info, &cb_regs) != 0) {
    fprintf(stderr, "Error: could not allocate a real-mode callback.\n");
    net_close();
    return -1;
  }
  cb_installed = 1;
  _go32_dpmi_lock_code(rx_callback, (unsigned long)((char *)rx_callback_end -
                                                    (char *)rx_callback));
  _go32_dpmi_lock_data(&ring, sizeof ring);

  /* ethertype template in NETWORK byte order (high byte first) */
  t[0] = (unsigned char)(ethertype >> 8);
  t[1] = (unsigned char)(ethertype & 0xff);
  dosmemput(t, 2, (int)((unsigned long)typ_seg << 4));

  /* access_type: AH=2 AL=1(class) BX=0FFFFh(any type) DL=0(if#) CX=2(typelen)
   *   DS:SI -> ethertype template, ES:DI -> RETF callback  =>  AX = handle */
  memset(&r, 0, sizeof r);
  r.h.ah = 0x02;
  r.h.al = 0x01;
  r.x.bx = 0xFFFF;
  r.h.dl = 0x00;
  r.x.cx = 2;
  r.x.ds = typ_seg;
  r.x.si = 0;
  r.x.es = cb_info.rm_segment;
  r.x.di = cb_info.rm_offset;
  __dpmi_int(pkt_vec, &r);
  if (r.x.flags & 1) {
    fprintf(stderr, "Error: access_type failed (DH=%u).\n", (unsigned)r.h.dh);
    net_close();
    return -1;
  }
  pkt_handle = r.x.ax;
  handle_open = 1;

  /* get_address (AH=06h): BX=handle ES:DI=buf CX=6. The MAC goes into TX_seg,
   * NOT rx_seg: the receiver installed by access_type above is already live,
   * so an inbound frame could overwrite rx_seg between this INT returning and
   * the dosmemget below. The receiver never touches tx_seg, and net_send
   * cannot run concurrently during net_open (single-threaded). */
  memset(&r, 0, sizeof r);
  r.h.ah = 0x06;
  r.x.bx = pkt_handle;
  r.x.es = tx_seg;
  r.x.di = 0;
  r.x.cx = 6;
  __dpmi_int(pkt_vec, &r);
  if (r.x.flags & 1) {
    fprintf(stderr, "Error: get_address failed (DH=%u).\n", (unsigned)r.h.dh);
    net_close();
    return -1;
  }
  dosmemget((unsigned long)tx_seg << 4, 6, mymac_out);
  return 0;
}

int net_recv(unsigned char *buf, int maxlen, int timeout_ms) {
  unsigned long start = bios_ticks();
  unsigned long needed = ms_to_ticks(timeout_ms);
  for (;;) {
    if (ring.tail != ring.head) { /* not empty */
      unsigned t = ring.tail, nxt = t + 1;
      int len = ring.len[t];
      if (nxt >= RING_SLOTS)
        nxt = 0;
      if (len > maxlen)
        len = maxlen;
      memcpy(buf, ring.data[t], (size_t)len);
      __asm__ __volatile__("" ::: "memory");
      ring.tail = nxt;
      return len;
    }
    if (timeout_ms >= 0 && ticks_elapsed(start) >= needed)
      return 0;
    __dpmi_yield(); /* no-op on bare DOS, yields the CPU under Windows/DOSBox */
  }
}

int net_send(const unsigned char *frame, int len) {
  __dpmi_regs r;
  if (len < 0 || len > DOSBUF_SIZE)
    return -1;
  if (len < 60) { /* pad short frames to the 60-byte Ethernet minimum (no FCS) */
    static unsigned char pad[DOSBUF_SIZE];
    memcpy(pad, frame, (size_t)len);
    memset(pad + len, 0, 60 - len);
    frame = pad;
    len = 60;
  }
  dosmemput(frame, len, (int)((unsigned long)tx_seg << 4));
  memset(&r, 0, sizeof r);
  r.h.ah = 0x04; /* send_pkt: DS:SI=frame, CX=len */
  r.x.ds = tx_seg;
  r.x.si = 0;
  r.x.cx = len;
  __dpmi_int(pkt_vec, &r);
  return (r.x.flags & 1) ? -1 : len;
}

void net_close(void) {
  __dpmi_regs r;
  if (handle_open) { /* release_type (AH=03h) FIRST, before freeing anything */
    memset(&r, 0, sizeof r);
    r.h.ah = 0x03;
    r.x.bx = pkt_handle;
    __dpmi_int(pkt_vec, &r); /* NOT terminate (05h): we did not load the TSR */
    pkt_handle = 0;
    handle_open = 0;
  }
  if (cb_installed) {
    _go32_dpmi_free_real_mode_callback(&cb_info);
    cb_installed = 0;
  }
  if (rx_sel) {
    __dpmi_free_dos_memory(rx_sel);
    rx_sel = 0;
    rx_seg = 0;
  }
  if (tx_sel) {
    __dpmi_free_dos_memory(tx_sel);
    tx_sel = 0;
    tx_seg = 0;
  }
  if (typ_sel) {
    __dpmi_free_dos_memory(typ_sel);
    typ_sel = 0;
    typ_seg = 0;
  }
}
