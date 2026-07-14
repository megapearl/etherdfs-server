/*
 * EtherDFS - a network drive for DOS running over raw ethernet
 * http://etherdfs.sourceforge.net
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

#include <i86.h>     /* union INTPACK */
#include "chint.h"   /* _mvchain_intr() */
#include "version.h" /* program & protocol version */

/* set DEBUGLEVEL to 0, 1 or 2 to turn on debug mode with desired verbosity */
#define DEBUGLEVEL 0

/* define the maximum size of a frame, as sent or received by etherdfs.
 * example: value 1084 accomodates payloads up to 1024 bytes +all headers */
#define FRAMESIZE 1090

#include "dosstruc.h" /* definitions of structures used by DOS */
#include "globals.h"  /* global variables used by etherdfs */

/* define NULL, for readability of the code */
#ifndef NULL
  #define NULL (void *)0
#endif

/* all the resident code goes to segment 'BEGTEXT' */
#pragma code_seg(BEGTEXT, CODE)


/* copies l bytes from *s to *d */
static void copybytes(void far *d, void far *s, unsigned int l) {
  while (l != 0) {
    l--;
    *(unsigned char far *)d = *(unsigned char far *)s;
    d = (unsigned char far *)d + 1;
    s = (unsigned char far *)s + 1;
  }
}

static unsigned short mystrlen(void far *s) {
  unsigned short res = 0;
  while (*(unsigned char far *)s != 0) {
    res++;
    s = ((unsigned char far *)s) + 1;
  }
  return(res);
}

/* returns -1 if the NULL-terminated s string contains any wildcard (?, *)
 * character. otherwise returns the length of the string. */
static int len_if_no_wildcards(char far *s) {
  int r = 0;
  for (;;) {
    switch (*s) {
      case 0: return(r);
      case '?':
      case '*': return(-1);
    }
    r++;
    s++;
  }
}

/* computes a BSD checksum of l bytes at dataptr location */
static unsigned short bsdsum(unsigned char *dataptr, unsigned short l) {
  unsigned short cksum = 0;
  _asm {
    cld           /* clear direction flag */
    xor bx, bx    /* bx will hold the result */
    xor ax, ax
    mov cx, l
    mov si, dataptr
    iterate:
    lodsb         /* load a byte from DS:SI into AL and INC SI */
    ror bx, 1
    add bx, ax
    dec cx        /* DEC CX + JNZ could be replaced by a single LOOP */
    jnz iterate   /* instruction, but DEC+JNZ is 3x faster (on 8086) */
    mov cksum, bx
  }
  return(cksum);
}

/* this function is called two times by the packet driver. One time for
 * telling that a packet is incoming, and how big it is, so the application
 * can prepare a buffer for it and hand it back to the packet driver. the
 * second call is just to let know that the frame has been copied into the
 * buffer. This is a naked function - I don't need the compiler to get into
 * the way when dealing with packet driver callbacks.
 * IMPORTANT: this function must take care to modify ONLY the registers
 * ES and DI - packet drivers can be easily confused should anything else
 * be modified. */
void __declspec(naked) far pktdrv_recv(void) {
  _asm {
    jmp skip
    SIG db 'p','k','t','r'
    skip:
    /* save DS and flags to stack */
    push ds  /* save old ds (I will change it) */
    push bx  /* save bx (I use it as a temporary register) */
    pushf    /* save flags */
    /* set my custom DS (not 0, it has been patched at runtime already) */
    mov bx, 0
    mov ds, bx
    /* handle the call */
    cmp ax, 0
    jne secondcall /* if ax != 0, then packet driver just filled my buffer */
    /* first call: the packet driver needs a buffer of CX bytes */
    cmp cx, FRAMESIZE /* is cx > FRAMESIZE ? (unsigned) */
    ja nobufferavail  /* it is too small (that's what she said!) */
    /* see if buffer not filled already... */
    cmp glob_pktdrv_recvbufflen, 0 /* is bufflen > 0 ? (signed) */
    jg nobufferavail  /* if signed > 0, then we are busy already */

    /* buffer is available, set its seg:off in es:di */
    push ds /* set es:di to recvbuff */
    pop es
    mov di, offset glob_pktdrv_recvbuff
    /* set bufferlen to expected len and switch it to neg until data comes */
    mov glob_pktdrv_recvbufflen, cx
    neg glob_pktdrv_recvbufflen
    /* restore flags, bx and ds, then return */
    jmp restoreandret

  nobufferavail: /* no buffer available, or it's too small -> fail */
    xor bx,bx      /* set bx to zero... */
    push bx        /* and push it to the stack... */
    push bx        /* twice */
    pop es         /* zero out es and di - this tells the */
    pop di         /* packet driver 'sorry no can do'     */
    /* restore flags, bx and ds, then return */
    jmp restoreandret

  secondcall: /* second call: I've just got data in buff */
    /* I switch back bufflen to positive so the app can see that something is there now */
    neg glob_pktdrv_recvbufflen
    /* restore flags, bx and ds, then return */
  restoreandret:
    popf   /* restore flags */
    pop bx /* restore bx */
    pop ds /* restore ds */
    retf
  }
}


/* translates a drive letter (either upper- or lower-case) into a number (A=0,
 * B=1, C=2, etc) */
#define DRIVETONUM(x) (((x) >= 'a') && ((x) <= 'z')?x-'a':x-'A')

/* The CDS of a SPECIFIC drive, from the CDS array we grabbed out of the List of
 * Lists at install. Use this -- never glob_sdaptr->drive_cdsptr -- whenever the
 * drive is chosen by US (a relative LFN path resolving against the default
 * drive). drive_cdsptr belongs to the CURRENT DOS OPERATION and is stale in that
 * context: e.g. Norton Commander's F3 opens C:\APPS\NC\NCVIEW.MSG and only then
 * asks for the true name of the bare relative "viewtest.txt". drive_cdsptr then
 * still points at C: while the default drive is E:, so we used to decline the
 * call, DOSLFN took it over, mangled it, and NC reported "file not found".
 * Returns NULL if the CDS array is unavailable or the drive is out of range. */
static struct cdsstruct far *cds_for_drive(unsigned char drv) {
  if ((glob_cdsarr == 0) || (drv >= glob_lastdrv)) return NULL;
  return (struct cdsstruct far *)(glob_cdsarr +
                                  ((unsigned short)drv * glob_cdssz));
}
/* Target drive index for an LFN INT 21h path. Use the "X:" prefix if present,
 * otherwise the path is relative to the CURRENT default drive, which DOS keeps
 * at SDA offset 16h. Without this, when our drive is the current drive the
 * shell/DOSLFN hands us a drive-less path (e.g. "\\DIR\\*") and every LFN
 * handler declined it, so the caller silently fell back to the 8.3 legacy path
 * (no long names, broken subdir navigation). We only adopt the current drive
 * for ROOT-relative paths ("\\..."); a bare relative name would need the CWD we
 * do not resolve here, so those stay 0xFF (not ours -> chain, DOS resolves). */
#define LFN_PATHDRV(p) ( ((p)[0] != 0 && (p)[1] == ':') ? DRIVETONUM((p)[0]) \
                       : (((p)[0] == '\\' || (p)[0] == '/') \
                          ? ((unsigned char far *)glob_sdaptr)[0x16] : 0xff) )


/* all the calls I support are in the range AL=0..2Eh - the list below serves
 * as a convenience to compare AL (subfunction) values */
enum AL_SUBFUNCTIONS {
  AL_INSTALLCHK = 0x00,
  AL_RMDIR      = 0x01,
  AL_MKDIR      = 0x03,
  AL_CHDIR      = 0x05,
  AL_CLSFIL     = 0x06,
  AL_CMMTFIL    = 0x07,
  AL_READFIL    = 0x08,
  AL_WRITEFIL   = 0x09,
  AL_LOCKFIL    = 0x0A,
  AL_UNLOCKFIL  = 0x0B,
  AL_DISKSPACE  = 0x0C,
  AL_SETATTR    = 0x0E,
  AL_GETATTR    = 0x0F,
  AL_RENAME     = 0x11,
  AL_DELETE     = 0x13,
  AL_OPEN       = 0x16,
  AL_CREATE     = 0x17,
  AL_FINDFIRST  = 0x1B,
  AL_FINDNEXT   = 0x1C,
  AL_SKFMEND    = 0x21,
  AL_UNKNOWN_2D = 0x2D,
  AL_SPOPNFIL   = 0x2E,
  AL_UNKNOWN    = 0xFF
};

/* this table makes it easy to figure out if I want a subfunction or not */
static unsigned char supportedfunctions[0x2F] = {
  AL_INSTALLCHK,  /* 0x00 */
  AL_RMDIR,       /* 0x01 */
  AL_UNKNOWN,     /* 0x02 */
  AL_MKDIR,       /* 0x03 */
  AL_UNKNOWN,     /* 0x04 */
  AL_CHDIR,       /* 0x05 */
  AL_CLSFIL,      /* 0x06 */
  AL_CMMTFIL,     /* 0x07 */
  AL_READFIL,     /* 0x08 */
  AL_WRITEFIL,    /* 0x09 */
  AL_LOCKFIL,     /* 0x0A */
  AL_UNLOCKFIL,   /* 0x0B */
  AL_DISKSPACE,   /* 0x0C */
  AL_UNKNOWN,     /* 0x0D */
  AL_SETATTR,     /* 0x0E */
  AL_GETATTR,     /* 0x0F */
  AL_UNKNOWN,     /* 0x10 */
  AL_RENAME,      /* 0x11 */
  AL_UNKNOWN,     /* 0x12 */
  AL_DELETE,      /* 0x13 */
  AL_UNKNOWN,     /* 0x14 */
  AL_UNKNOWN,     /* 0x15 */
  AL_OPEN,        /* 0x16 */
  AL_CREATE,      /* 0x17 */
  AL_UNKNOWN,     /* 0x18 */
  AL_UNKNOWN,     /* 0x19 */
  AL_UNKNOWN,     /* 0x1A */
  AL_FINDFIRST,   /* 0x1B */
  AL_FINDNEXT,    /* 0x1C */
  AL_UNKNOWN,     /* 0x1D */
  AL_UNKNOWN,     /* 0x1E */
  AL_UNKNOWN,     /* 0x1F */
  AL_UNKNOWN,     /* 0x20 */
  AL_SKFMEND,     /* 0x21 */
  AL_UNKNOWN,     /* 0x22 */
  AL_UNKNOWN,     /* 0x23 */
  AL_UNKNOWN,     /* 0x24 */
  AL_UNKNOWN,     /* 0x25 */
  AL_UNKNOWN,     /* 0x26 */
  AL_UNKNOWN,     /* 0x27 */
  AL_UNKNOWN,     /* 0x28 */
  AL_UNKNOWN,     /* 0x29 */
  AL_UNKNOWN,     /* 0x2A */
  AL_UNKNOWN,     /* 0x2B */
  AL_UNKNOWN,     /* 0x2C */
  AL_UNKNOWN_2D,  /* 0x2D */
  AL_SPOPNFIL     /* 0x2E */
};

/*
an INTPACK struct contains following items:
regs.w.gs
regs.w.fs
regs.w.es
regs.w.ds
regs.w.di
regs.w.si
regs.w.bp
regs.w.sp
regs.w.bx
regs.w.dx
regs.w.cx
regs.w.ax
regs.w.ip
regs.w.cs
regs.w.flags (AND with INTR_CF to fetch the CF flag - INTR_CF is defined as 0x0001)

regs.h.bl
regs.h.bh
regs.h.dl
regs.h.dh
regs.h.cl
regs.h.ch
regs.h.al
regs.h.ah
*/


/* sends query out, as found in glob_pktdrv_sndbuff, and awaits for an answer.
 * this function returns the length of replyptr, or 0xFFFF on error. */
static unsigned short sendquery(unsigned char query, unsigned char drive, unsigned short bufflen, unsigned char **replyptr, unsigned short **replyax, unsigned int updatermac) {
  static unsigned char seq;
  unsigned short count;
  unsigned char t;
  unsigned char volatile far *rtc = (unsigned char far *)0x46C; /* this points to a char, while the rtc timer is a word - but I care only about the lowest 8 bits. Be warned that this location won't increment while interrupts are disabled! */

  /* resolve remote drive - no need to validate it, it has been validated
   * already by inthandler() */
  drive = glob_data.ldrv[drive];

  /* bufflen provides payload's lenght, but I prefer knowing the frame's len */
  bufflen += 60;

  /* if query too long then quit */
  if (bufflen > sizeof(glob_pktdrv_sndbuff)) return(0);
  /* inc seq */
  seq++;
  /* I do not fill in ethernet headers (src mac, dst mac, ethertype), nor
   * PROTOVER, since all these have been inited already at transient time */
  /* padding (38 bytes) */
  ((unsigned short *)glob_pktdrv_sndbuff)[26] = bufflen; /* total frame len */
  glob_pktdrv_sndbuff[57] = seq;   /* seq number */
  glob_pktdrv_sndbuff[58] = drive;
  glob_pktdrv_sndbuff[59] = query; /* AL value (query) */
  if (glob_pktdrv_sndbuff[56] & 128) { /* if CKSUM enabled, compute it */
    /* fill in the BSD checksum at offset 54 */
    ((unsigned short *)glob_pktdrv_sndbuff)[27] = bsdsum(glob_pktdrv_sndbuff + 56, bufflen - 56);
  }
  /* I do not copy anything more into glob_pktdrv_sndbuff - the caller is
   * expected to have already copied all relevant data into glob_pktdrv_sndbuff+60
   * copybytes((unsigned char far *)glob_pktdrv_sndbuff + 60, (unsigned char far *)buff, bufflen);
   */

  /* send the query frame and wait for an answer for about 100ms. then, resend
   * the query again and again, up to 5 times. the RTC clock at 0x46C is used
   * as a timing reference. */
  glob_pktdrv_recvbufflen = 0; /* mark the receiving buffer empty */
  for (count = 5; count != 0; count--) { /* faster than count=0; count<5; count++ */
    /* send the query frame out */
    _asm {
      /* save registers */
      push ax
      push cx
      push dx /* may be changed by the packet driver (set to errno) */
      push si
      pushf /* must be last register pushed (expected by 'call') */
      /* */
      mov ah, 4h   /* SendPkt */
      mov cx, bufflen
      mov si, offset glob_pktdrv_sndbuff /* DS:SI points to buff, I do not
                                 modify DS because the buffer should already
                                 be in my data segment (small memory model) */
      /* int to variable vector is a mess, so I have fetched its vector myself
       * and pushf + cli + call far it now to simulate a regular int */
      /* pushf -- already on the stack */
      cli
      call dword ptr glob_pktdrv_pktcall
      /* restore registers (but not pushf, already restored by call) */
      pop si
      pop dx
      pop cx
      pop ax
    }

    /* wait for (and validate) the answer frame */
    t = *rtc;
    for (;;) {
      int i;
      if ((t != *rtc) && (t+1 != *rtc) && (*rtc != 0)) break; /* timeout, retry */
      if (glob_pktdrv_recvbufflen < 1) continue;
      /* I've got something! */
      /* is the frame long enough for me to care? */
      if (glob_pktdrv_recvbufflen < 60) goto ignoreframe;
      /* is it for me? (correct src mac & dst mac) */
      for (i = 0; i < 6; i++) {
        if (glob_pktdrv_recvbuff[i] != GLOB_LMAC[i]) goto ignoreframe;
        if ((updatermac == 0) && (glob_pktdrv_recvbuff[i+6] != GLOB_RMAC[i])) goto ignoreframe;
      }
      /* is the ethertype and seq what I expect? */
      if ((((unsigned short *)glob_pktdrv_recvbuff)[6] != 0xF5EDu) || (glob_pktdrv_recvbuff[57] != seq)) goto ignoreframe;

      /* validate frame length (if provided) */
      if (((unsigned short *)glob_pktdrv_recvbuff)[26] > glob_pktdrv_recvbufflen) {
        /* frame appears to be truncated */
        goto ignoreframe;
      }
      if (((unsigned short *)glob_pktdrv_recvbuff)[26] < 60) {
        /* malformed frame */
        goto ignoreframe;
      }
      glob_pktdrv_recvbufflen = ((unsigned short *)glob_pktdrv_recvbuff)[26];

      /* if CKSUM enabled, check it on received frame */
      if (glob_pktdrv_sndbuff[56] & 128) {
        /* is the cksum ok? */
        if (bsdsum(glob_pktdrv_recvbuff + 56, glob_pktdrv_recvbufflen - 56) != (((unsigned short *)glob_pktdrv_recvbuff)[27])) {
          /* DEBUG - prints a '!' on screen on cksum error */ /*{
            unsigned short far *v = (unsigned short far *)0xB8000000l;
            v[0] = 0x4000 | '!';
          }*/
          goto ignoreframe;
        }
      }

      /* return buffer (without headers and seq) */
      *replyptr = glob_pktdrv_recvbuff + 60;
      *replyax = (unsigned short *)(glob_pktdrv_recvbuff + 58);
      /* update glob_rmac if needed, then return */
      if (updatermac != 0) copybytes(GLOB_RMAC, glob_pktdrv_recvbuff + 6, 6);
      return(glob_pktdrv_recvbufflen - 60);
      ignoreframe: /* ignore this frame and wait for the next one */
      glob_pktdrv_recvbufflen = 0; /* mark the buffer empty */
    }
  }
  return(0xFFFFu); /* return error */
}


/* reset CF (set on error only) and AX (expected to contain the error code,
 * I might set it later) - I assume a success */
#define SUCCESSFLAG glob_intregs.w.ax = 0; glob_intregs.w.flags &= ~(INTR_CF);
#define FAILFLAG(x) {glob_intregs.w.ax = x; glob_intregs.w.flags |= INTR_CF;}

/* this function contains the logic behind INT 2F processing */
void process2f(void) {
#if DEBUGLEVEL > 0
  char far *dbg_msg = NULL;
#endif
  short i;
  unsigned char *answer;
  unsigned char *buff; /* pointer to the "query arguments" part of glob_pktdrv_sndbuff */
  unsigned char subfunction;
  unsigned short *ax; /* used to collect the resulting value of AX */
  buff = glob_pktdrv_sndbuff + 60;

  /* DEBUG output (RED) */
#if DEBUGLEVEL > 0
  dbg_xpos &= 511;
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x4e00 | ' ';
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x4e00 | (dbg_hexc[(glob_intregs.h.al >> 4) & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x4e00 | (dbg_hexc[glob_intregs.h.al & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x4e00 | ' ';
#endif

  /* remember the AL register (0x2F subfunction id) */
  subfunction = glob_intregs.h.al;

  /* if we got here, then the call is definitely for us. set AX and CF to */
  /* 'success' (being a natural optimist I assume success) */
  SUCCESSFLAG;

  /* look what function is called exactly and process it */
  switch (subfunction) {
    case AL_RMDIR: /*** 01h: RMDIR ******************************************/
      /* RMDIR is like MKDIR, but I need to check if dir is not current first */
      for (i = 0; glob_sdaptr->fn1[i] != 0; i++) {
        if (glob_sdaptr->fn1[i] != glob_sdaptr->drive_cdsptr[i]) goto proceedasmkdir;
      }
      FAILFLAG(16); /* err 16 = "attempted to remove current directory" */
      break;
      proceedasmkdir:
    case AL_MKDIR: /*** 03h: MKDIR ******************************************/
      i = mystrlen(glob_sdaptr->fn1);
      /* fn1 must be at least 2 bytes long */
      if (i < 2) {
        FAILFLAG(3); /* "path not found" */
        break;
      }
      /* copy fn1 to buff (but skip drive part) */
      i -= 2;
      copybytes(buff, glob_sdaptr->fn1 + 2, i);
      /* send query providing fn1 */
      if (sendquery(subfunction, glob_reqdrv, i, &answer, &ax, 0) == 0) {
        glob_intregs.w.ax = *ax;
        if (*ax != 0) glob_intregs.w.flags |= INTR_CF;
      } else {
        FAILFLAG(2);
      }
      break;
    case AL_CHDIR: /*** 05h: CHDIR ******************************************/
      /* The INT 2Fh/1105h redirector callback is executed by DOS when
       * changing directories. The Phantom authors (and RBIL contributors)
       * clearly thought that it was the redirector's job to update the CDS,
       * but in fact the callback is only meant to validate that the target
       * directory exists; DOS subsequently updates the CDS. */
      /* fn1 must be at least 2 bytes long */
      i = mystrlen(glob_sdaptr->fn1);
      if (i < 2) {
        FAILFLAG(3); /* "path not found" */
        break;
      }
      /* copy fn1 to buff (but skip the drive: part) */
      i -= 2;
      copybytes(buff, glob_sdaptr->fn1 + 2, i);
      /* send query providing fn1 */
      if (sendquery(AL_CHDIR, glob_reqdrv, i, &answer, &ax, 0) == 0) {
        glob_intregs.w.ax = *ax;
        if (*ax != 0) glob_intregs.w.flags |= INTR_CF;
      } else {
        FAILFLAG(3); /* "path not found" */
      }
      break;
    case AL_CLSFIL: /*** 06h: CLSFIL ****************************************/
      /* my only job is to decrement the SFT's handle count (which I didn't
       * have to increment during OPENFILE since DOS does it... talk about
       * consistency. I also inform the server about this, just so it knows */
      /* ES:DI points to the SFT */
      {
      struct sftstruct far *sftptr = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
      if (sftptr->handle_count > 0) sftptr->handle_count--;
      ((unsigned short *)buff)[0] = sftptr->start_sector;
      if (sendquery(AL_CLSFIL, glob_reqdrv, 2, &answer, &ax, 0) == 0) {
        if (*ax != 0) FAILFLAG(*ax);
      }
      }
      break;
    case AL_CMMTFIL: /*** 07h: CMMTFIL **************************************/
      /* I have nothing to do here */
      break;
    case AL_READFIL: /*** 08h: READFIL **************************************/
      { /* ES:DI points to the SFT (whose file_pos needs to be updated) */
        /* CX = number of bytes to read (to be updated with number of bytes actually read) */
        /* SDA DTA = read buffer */
      struct sftstruct far *sftptr = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
      unsigned short totreadlen;
      /* is the file open for write-only? */
      if (sftptr->open_mode & 1) {
        FAILFLAG(5); /* "access denied" */
        break;
      }
      /* return immediately if the caller wants to read 0 bytes */
      if (glob_intregs.x.cx == 0) break;
      /* do multiple read operations so chunks can fit in my eth frames */
      totreadlen = 0;
      for (;;) {
        int chunklen, len;
        if ((glob_intregs.x.cx - totreadlen) < (FRAMESIZE - 60)) {
          chunklen = glob_intregs.x.cx - totreadlen;
        } else {
          chunklen = FRAMESIZE - 60;
        }
        /* query is OOOOSSLL (offset, start sector, lenght to read) */
        ((unsigned long *)buff)[0] = sftptr->file_pos + totreadlen;
        ((unsigned short *)buff)[2] = sftptr->start_sector;
        ((unsigned short *)buff)[3] = chunklen;
        len = sendquery(AL_READFIL, glob_reqdrv, 8, &answer, &ax, 0);
        if (len == 0xFFFFu) { /* network error */
          FAILFLAG(2);
          break;
        } else if (*ax != 0) { /* backend error */
          FAILFLAG(*ax);
          break;
        } else { /* success */
          copybytes(glob_sdaptr->curr_dta + totreadlen, answer, len);
          totreadlen += len;
          if ((len < chunklen) || (totreadlen == glob_intregs.x.cx)) { /* EOF - update SFT and break out */
            sftptr->file_pos += totreadlen;
            glob_intregs.x.cx = totreadlen;
            break;
          }
        }
      }
      }
      break;
    case AL_WRITEFIL: /*** 09h: WRITEFIL ************************************/
      { /* ES:DI points to the SFT (whose file_pos needs to be updated) */
        /* CX = number of bytes to write (to be updated with number of bytes actually written) */
        /* SDA DTA = read buffer */
      struct sftstruct far *sftptr = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
      unsigned short bytesleft, chunklen, written = 0;
      /* is the file open for read-only? */
      if ((sftptr->open_mode & 3) == 0) {
        FAILFLAG(5); /* "access denied" */
        break;
      }
      /* TODO FIXME I should update the file's time in the SFT here */
      /* do multiple write operations so chunks can fit in my eth frames */
      bytesleft = glob_intregs.x.cx;

      while (bytesleft > 0) {
        unsigned short len;
        chunklen = bytesleft;
        if (chunklen > FRAMESIZE - 66) chunklen = FRAMESIZE - 66;
        /* query is OOOOSS (file offset, start sector/fileid) */
        ((unsigned long *)buff)[0] = sftptr->file_pos;
        ((unsigned short *)buff)[2] = sftptr->start_sector;
        copybytes(buff + 6, glob_sdaptr->curr_dta + written, chunklen);
        len = sendquery(AL_WRITEFIL, glob_reqdrv, chunklen + 6, &answer, &ax, 0);
        if (len == 0xFFFFu) { /* network error */
          FAILFLAG(2);
          break;
        } else if ((*ax != 0) || (len != 2)) { /* backend error */
          FAILFLAG(*ax);
          break;
        } else { /* success - write amount of bytes written into CX and update SFT */
          len = ((unsigned short *)answer)[0];
          written += len;
          bytesleft -= len;
          glob_intregs.x.cx = written;
          sftptr->file_pos += len;
          if (sftptr->file_pos > sftptr->file_size) sftptr->file_size = sftptr->file_pos;
          if (len != chunklen) break; /* something bad happened on the other side */
        }
      }
      }
      break;
    case AL_LOCKFIL: /*** 0Ah: LOCKFIL **************************************/
      {
      struct sftstruct far *sftptr = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
      ((unsigned short *)buff)[0] = glob_intregs.x.cx;
      ((unsigned short *)buff)[1] = sftptr->start_sector;
      if (glob_intregs.h.bl > 1) FAILFLAG(2); /* BL should be either 0 (lock) or 1 (unlock) */
      /* copy 8*CX bytes from DS:DX to buff+4 (parameters block) */
      copybytes(buff + 4, MK_FP(glob_intregs.x.ds, glob_intregs.x.dx), glob_intregs.x.cx << 3);
      if (sendquery(AL_LOCKFIL + glob_intregs.h.bl, glob_reqdrv, (glob_intregs.x.cx << 3) + 4, &answer, &ax, 0) != 0) {
        FAILFLAG(2);
      }
      }
      break;
    case AL_UNLOCKFIL: /*** 0Bh: UNLOCKFIL **********************************/
      /* Nothing here - this isn't supposed to be used by DOS 4+ */
      FAILFLAG(2);
      break;
    case AL_DISKSPACE: /*** 0Ch: get disk information ***********************/
      if (sendquery(AL_DISKSPACE, glob_reqdrv, 0, &answer, &ax, 0) == 6) {
        glob_intregs.w.ax = *ax; /* sectors per cluster */
        glob_intregs.w.bx = ((unsigned short *)answer)[0]; /* total clusters */
        glob_intregs.w.cx = ((unsigned short *)answer)[1]; /* bytes per sector */
        glob_intregs.w.dx = ((unsigned short *)answer)[2]; /* num of available clusters */
      } else {
        FAILFLAG(2);
      }
      break;
    case AL_SETATTR: /*** 0Eh: SETATTR **************************************/
      /* sdaptr->fn1 -> file to set attributes for
         stack word -> new attributes (stack must not be changed!) */
      /* fn1 must be at least 2 characters long */
      i = mystrlen(glob_sdaptr->fn1);
      if (i < 2) {
        FAILFLAG(2);
        break;
      }
      /* */
      buff[0] = glob_reqstkword;
      /* copy fn1 to buff (but without the drive part) */
      copybytes(buff + 1, glob_sdaptr->fn1 + 2, i - 2);
    #if DEBUGLEVEL > 0
      dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x1000 | dbg_hexc[(glob_reqstkword >> 4) & 15];
      dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x1000 | dbg_hexc[glob_reqstkword & 15];
    #endif
      i = sendquery(AL_SETATTR, glob_reqdrv, i - 1, &answer, &ax, 0);
      if (i != 0) {
        FAILFLAG(2);
      } else if (*ax != 0) {
        FAILFLAG(*ax);
      }
      break;
    case AL_GETATTR: /*** 0Fh: GETATTR **************************************/
      i = mystrlen(glob_sdaptr->fn1);
      if (i < 2) {
        FAILFLAG(2);
        break;
      }
      i -= 2;
      copybytes(buff, glob_sdaptr->fn1 + 2, i);
      i = sendquery(AL_GETATTR, glob_reqdrv, i, &answer, &ax, 0);
      if ((unsigned short)i == 0xffffu) {
        FAILFLAG(2);
      } else if ((i != 9) || (*ax != 0)) {
        FAILFLAG(*ax);
      } else { /* all good */
        /* CX = timestamp
         * DX = datestamp
         * BX:DI = fsize
         * AX = attr
         * NOTE: Undocumented DOS talks only about setting AX, no fsize, time
         *       and date, these are documented in RBIL and used by SHSUCDX */
        glob_intregs.w.cx = ((unsigned short *)answer)[0]; /* time */
        glob_intregs.w.dx = ((unsigned short *)answer)[1]; /* date */
        glob_intregs.w.bx = ((unsigned short *)answer)[3]; /* fsize hi word */
        glob_intregs.w.di = ((unsigned short *)answer)[2]; /* fsize lo word */
        glob_intregs.w.ax = answer[8];                     /* file attribs */
      }
      break;
    case AL_RENAME: /*** 11h: RENAME ****************************************/
      /* sdaptr->fn1 = old name
       * sdaptr->fn2 = new name */
      /* is the operation for the SAME drive? */
      if (glob_sdaptr->fn1[0] != glob_sdaptr->fn2[0]) {
        FAILFLAG(2);
        break;
      }
      /* prepare the query (LSSS...DDD...) */
      i = mystrlen(glob_sdaptr->fn1);
      if (i < 2) {
        FAILFLAG(2);
        break;
      }
      i -= 2; /* trim out the drive: part (C:\FILE --> \FILE) */
      buff[0] = i;
      copybytes(buff + 1, glob_sdaptr->fn1 + 2, i);
      i = len_if_no_wildcards(glob_sdaptr->fn2);
      if (i < 2) {
        FAILFLAG(3);
        break;
      }
      i -= 2; /* trim out the drive: part (C:\FILE --> \FILE) */
      copybytes(buff + 1 + buff[0], glob_sdaptr->fn2 + 2, i);
      /* send the query out */
      i = sendquery(AL_RENAME, glob_reqdrv, 1 + buff[0] + i, &answer, &ax, 0);
      if (i != 0) {
        FAILFLAG(2);
      } else if (*ax != 0) {
        FAILFLAG(*ax);
      }
      break;
    case AL_DELETE: /*** 13h: DELETE ****************************************/
    #if DEBUGLEVEL > 0
      dbg_msg = glob_sdaptr->fn1;
    #endif
      /* compute length of fn1 and copy it to buff (w/o the 'drive:' part) */
      i = mystrlen(glob_sdaptr->fn1);
      if (i < 2) {
        FAILFLAG(2);
        break;
      }
      i -= 2;
      copybytes(buff, glob_sdaptr->fn1 + 2, i);
      /* send query */
      i = sendquery(AL_DELETE, glob_reqdrv, i, &answer, &ax, 0);
      if ((unsigned short)i == 0xffffu) {
        FAILFLAG(2);
      } else if ((i != 0) || (*ax != 0)) {
        FAILFLAG(*ax);
      }
      break;
    case AL_OPEN: /*** 16h: OPEN ********************************************/
    case AL_CREATE: /*** 17h: CREATE ****************************************/
    case AL_SPOPNFIL: /*** 2Eh: SPOPNFIL ************************************/
    #if DEBUGLEVEL > 0
      dbg_msg = glob_sdaptr->fn1;
    #endif
      /* fail if fn1 contains any wildcard, otherwise get len of fn1 */
      i = len_if_no_wildcards(glob_sdaptr->fn1);
      if (i < 2) {
        FAILFLAG(3);
        break;
      }
      i -= 2;
      /* prepare and send query (SSCCMMfff...) */
      ((unsigned short *)buff)[0] = glob_reqstkword; /* WORD from the stack */
      ((unsigned short *)buff)[1] = glob_sdaptr->spop_act; /* action code (SPOP only) */
      ((unsigned short *)buff)[2] = glob_sdaptr->spop_mode; /* open mode (SPOP only) */
      copybytes(buff + 6, glob_sdaptr->fn1 + 2, i);
      i = sendquery(subfunction, glob_reqdrv, i + 6, &answer, &ax, 0);
      if ((unsigned short)i == 0xffffu) {
        FAILFLAG(2);
      } else if ((i != 25) || (*ax != 0)) {
        FAILFLAG(*ax);
      } else {
        /* ES:DI contains an uninitialized SFT */
        struct sftstruct far *sftptr = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
        /* special treatment for SPOP, (set open_mode and return CX, too) */
        if (subfunction == AL_SPOPNFIL) {
          glob_intregs.w.cx = ((unsigned short *)answer)[11];
        }
        if (sftptr->open_mode & 0x8000) { /* if bit 15 is set, then it's a "FCB open", and requires the internal DOS "Set FCB Owner" function to be called */
          /* TODO FIXME set_sft_owner() */
        #if DEBUGLEVEL > 0
          dbg_VGA[25*80] = 0x1700 | '$';
        #endif
        }
        sftptr->file_attr = answer[0];
        sftptr->dev_info_word = 0x8040 | glob_reqdrv; /* mark device as network & unwritten drive */
        sftptr->dev_drvr_ptr = NULL;
        sftptr->start_sector = ((unsigned short *)answer)[10];
        sftptr->file_time = ((unsigned long *)answer)[3];
        sftptr->file_size = ((unsigned long *)answer)[4];
        sftptr->file_pos = 0;
        sftptr->open_mode &= 0xff00u;
        sftptr->open_mode |= answer[24];
        sftptr->rel_sector = 0xffff;
        sftptr->abs_sector = 0xffff;
        sftptr->dir_sector = 0;
        sftptr->dir_entry_no = 0xff; /* why such value? no idea, PHANTOM.C uses that, too */
        copybytes(sftptr->file_name, answer + 1, 11);
      }
      break;
    case AL_FINDFIRST: /*** 1Bh: FINDFIRST **********************************/
    case AL_FINDNEXT:  /*** 1Ch: FINDNEXT ***********************************/
      {
      /* AX = 111Bh
      SS = DS = DOS DS
      [DTA] = uninitialized 21-byte findfirst search data
      (see #01626 at INT 21/AH=4Eh)
      SDA first filename pointer (FN1, 9Eh) -> fully-qualified search template
      SDA CDS pointer -> current directory structure for drive with file
      SDA search attribute = attribute mask for search

      Return:
      CF set on error
      AX = DOS error code (see #01680 at INT 21/AH=59h/BX=0000h)
           -> http://www.ctyme.com/intr/rb-3012.htm
      CF clear if successful
      [DTA] = updated findfirst search data
      (bit 7 of first byte must be set)
      [DTA+15h] = standard directory entry for file (see #01352)

      FindNext is the same, but only DTA should be used to fetch search params
      */
      struct sdbstruct far *dta;

#if DEBUGLEVEL > 0
      dbg_msg = glob_sdaptr->fn1;
#endif
      /* prepare the query buffer (i must provide query's length) */
      if (subfunction == AL_FINDFIRST) {
        dta = (struct sdbstruct far *)(glob_sdaptr->curr_dta);
        /* FindFirst needs to fetch search arguments from SDA */
        buff[0] = glob_sdaptr->srch_attr; /* file attributes to look for */
        /* copy fn1 (w/o drive) to buff */
        for (i = 2; glob_sdaptr->fn1[i] != 0; i++) buff[i-1] = glob_sdaptr->fn1[i];
        i--; /* adjust i because its one too much otherwise */
      } else { /* FindNext needs to fetch search arguments from DTA (es:di) */
        dta = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
        ((unsigned short *)buff)[0] = dta->par_clstr;
        ((unsigned short *)buff)[1] = dta->dir_entry;
        buff[4] = dta->srch_attr;
        /* copy search template to buff */
        for (i = 0; i < 11; i++) buff[i+5] = dta->srch_tmpl[i];
        i += 5; /* i must provide the exact query's length */
      }
      /* send query to remote peer and wait for answer */
      i = sendquery(subfunction, glob_reqdrv, i, &answer, &ax, 0);
      if (i == 0xffffu) {
        if (subfunction == AL_FINDFIRST) {
          FAILFLAG(2); /* a failed findfirst returns error 2 (file not found) */
        } else {
          FAILFLAG(18); /* a failed findnext returns error 18 (no more files) */
        }
        break;
      } else if ((*ax != 0) || (i != 24)) {
        FAILFLAG(*ax);
        break;
      }
      /* fill in the directory entry 'found_file' (32 bytes)
       * 00h unsigned char fname[11]
       * 0Bh unsigned char fattr (1=RO 2=HID 4=SYS 8=VOL 16=DIR 32=ARCH 64=DEV)
       * 0Ch unsigned char f1[10]
       * 16h unsigned short time_lstupd
       * 18h unsigned short date_lstupd
       * 1Ah unsigned short start_clstr  *optional*
       * 1Ch unsigned long fsize
       */
      copybytes(glob_sdaptr->found_file.fname, answer+1, 11); /* found file name */
      glob_sdaptr->found_file.fattr = answer[0]; /* found file attributes */
      glob_sdaptr->found_file.time_lstupd = ((unsigned short *)answer)[6]; /* time (word) */
      glob_sdaptr->found_file.date_lstupd = ((unsigned short *)answer)[7]; /* date (word) */
      glob_sdaptr->found_file.start_clstr = 0; /* start cluster (I don't care) */
      glob_sdaptr->found_file.fsize = ((unsigned long *)answer)[4]; /* fsize (word) */

      /* put things into DTA so I can understand where I left should FindNext
       * be called - this shall be a valid FindFirst structure (21 bytes):
       * 00h unsigned char drive letter (7bits, MSB must be set for remote drives)
       * 01h unsigned char search_tmpl[11]
       * 0Ch unsigned char search_attr (1=RO 2=HID 4=SYS 8=VOL 16=DIR 32=ARCH 64=DEV)
       * 0Dh unsigned short entry_count_within_directory
       * 0Fh unsigned short cluster number of start of parent directory
       * 11h unsigned char reserved[4]
       * -- RBIL says: [DTA+15h] = standard directory entry for file
       * 15h 11-bytes (FCB-style) filename+ext ("FILE0000TXT")
       * 20h unsigned char attr. of file found (1=RO 2=HID 4=SYS 8=VOL 16=DIR 32=ARCH 64=DEV)
       * 21h 10-bytes reserved
       * 2Bh unsigned short file time
       * 2Dh unsigned short file date
       * 2Fh unsigned short cluster
       * 31h unsigned long file size
       */
      /* init some stuff only on FindFirst (FindNext contains valid values already) */
      if (subfunction == AL_FINDFIRST) {
        dta->drv_lett = glob_reqdrv | 128; /* bit 7 set means 'network drive' */
        copybytes(dta->srch_tmpl, glob_sdaptr->fcb_fn1, 11);
        dta->srch_attr = glob_sdaptr->srch_attr;
      }
      dta->par_clstr = ((unsigned short *)answer)[10];
      dta->dir_entry = ((unsigned short *)answer)[11];
      /* then 32 bytes as in the found_file record */
      copybytes(dta + 0x15, &(glob_sdaptr->found_file), 32);
      }
      break;
    case AL_SKFMEND: /*** 21h: SKFMEND **************************************/
    {
      struct sftstruct far *sftptr = MK_FP(glob_intregs.x.es, glob_intregs.x.di);
      ((unsigned short *)buff)[0] = glob_intregs.x.dx;
      ((unsigned short *)buff)[1] = glob_intregs.x.cx;
      ((unsigned short *)buff)[2] = sftptr->start_sector;
      /* send query to remote peer and wait for answer */
      i = sendquery(AL_SKFMEND, glob_reqdrv, 6, &answer, &ax, 0);
      if (i == 0xffffu) {
        FAILFLAG(2);
      } else if ((*ax != 0) || (i != 4)) {
        FAILFLAG(*ax);
      } else { /* put new position into DX:AX */
        glob_intregs.w.ax = ((unsigned short *)answer)[0];
        glob_intregs.w.dx = ((unsigned short *)answer)[1];
      }
      break;
    }
    case AL_UNKNOWN_2D: /*** 2Dh: UNKNOWN_2D ********************************/
      /* this is only called in MS-DOS v4.01, its purpose is unknown. MSCDEX
       * returns AX=2 there, and so do I. */
      glob_intregs.w.ax = 2;
      break;
  }

  /* DEBUG */
#if DEBUGLEVEL > 0
  while ((dbg_msg != NULL) && (*dbg_msg != 0)) dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x4f00 | *(dbg_msg++);
#endif
}

/* this function is hooked on INT 2Fh */
void __interrupt __far inthandler(union INTPACK r) {
  /* insert a static code signature so I can reliably patch myself later,
   * this will also contain the DS segment to use and actually set it */
  _asm {
    jmp SKIPTSRSIG
    TSRSIG DB 'M','V','e','t'
    SKIPTSRSIG:
    /* save AX */
    push ax
    /* switch to new (patched) DS */
    mov ax, 0
    mov ds, ax
    /* save one word from the stack (might be used by SETATTR later)
     * The original stack should be at SS:BP+30 */
    mov ax, ss:[BP+30]
    mov glob_reqstkword, ax

    /* uncomment the debug code below to insert a stack's dump into snd eth
     * frame - debugging ONLY! */
    /*
    mov ax, ss:[BP+20]
    mov word ptr [glob_pktdrv_sndbuff+16], ax
    mov ax, ss:[BP+22]
    mov word ptr [glob_pktdrv_sndbuff+18], ax
    mov ax, ss:[BP+24]
    mov word ptr [glob_pktdrv_sndbuff+20], ax
    mov ax, ss:[BP+26]
    mov word ptr [glob_pktdrv_sndbuff+22], ax
    mov ax, ss:[BP+28]
    mov word ptr [glob_pktdrv_sndbuff+24], ax
    mov ax, ss:[BP+30]
    mov word ptr [glob_pktdrv_sndbuff+26], ax
    mov ax, ss:[BP+32]
    mov word ptr [glob_pktdrv_sndbuff+28], ax
    mov ax, ss:[BP+34]
    mov word ptr [glob_pktdrv_sndbuff+30], ax
    mov ax, ss:[BP+36]
    mov word ptr [glob_pktdrv_sndbuff+32], ax
    mov ax, ss:[BP+38]
    mov word ptr [glob_pktdrv_sndbuff+34], ax
    mov ax, ss:[BP+40]
    mov word ptr [glob_pktdrv_sndbuff+36], ax
    */
    /* restore AX */
    pop ax
  }

  /* DEBUG output (BLUE) */
#if DEBUGLEVEL > 1
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x1e00 | (dbg_hexc[(r.h.ah >> 4) & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x1e00 | (dbg_hexc[r.h.ah & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x1e00 | (dbg_hexc[(r.h.al >> 4) & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x1e00 | (dbg_hexc[r.h.al & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0;
#endif

  /* is it a multiplex call for me? */
  if (r.h.ah == glob_multiplexid) {
    if (r.h.al == 0) { /* install check */
      r.h.al = 0xff;    /* 'installed' */
      r.w.bx = 0x4d86;  /* MV          */
      r.w.cx = 0x7e1;   /* 2017        */
      return;
    }
    if ((r.h.al == 1) && (r.x.cx == 0x4d86)) { /* get shared data ptr (AX=0, ptr under BX:CX) */
      _asm {
        push ds
        pop glob_reqstkword
      }
      r.w.ax = 0; /* zero out AX */
      r.w.bx = glob_reqstkword; /* ptr returned at BX:CX */
      r.w.cx = FP_OFF(&glob_data);
      return;
    }
  }

  /* Stateless reentrancy guard: if we are entered with SS already == DS, we are
   * nested inside an outer handler that already switched to the resident stack
   * (a 2Fh or a 21h-LFN send blocked in sendquery with interrupts on). Switching
   * again would reset SP=DATASEGSZ-2 and clobber the outer's live frame, so chain
   * this rare interrupt-issued call to the previous handler instead. In the
   * normal (non-nested) case SS is DOS's/the app's stack, never our resident DS. */
  { volatile unsigned char _nested = 0;
    _asm {
      push ax
      push bx
      mov ax, ss
      mov bx, ds
      cmp ax, bx
      jne n2fok
      mov byte ptr _nested, 1
    n2fok:
      pop bx
      pop ax
    }
    if (_nested != 0) goto CHAINTOPREVHANDLER;
  }

  /* if not related to a redirector function (AH=11h), or the function is
   * an 'install check' (0), or the function is over our scope (2Eh), or it's
   * an otherwise unsupported function (as pointed out by supportedfunctions),
   * then call the previous INT 2F handler immediately */
  if ((r.h.ah != 0x11) || (r.h.al == AL_INSTALLCHK) || (r.h.al > 0x2E) || (supportedfunctions[r.h.al] == AL_UNKNOWN)) goto CHAINTOPREVHANDLER;

  /* DEBUG output (GREEN) */
#if DEBUGLEVEL > 0
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x2e00 | (dbg_hexc[(r.h.al >> 4) & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x2e00 | (dbg_hexc[r.h.al & 0xf]);
  dbg_VGA[dbg_startoffset + dbg_xpos++] = 0;
#endif

  /* determine whether or not the query is meant for a drive I control,
   * and if not - chain to the previous INT 2F handler */
  if (((r.h.al >= AL_CLSFIL) && (r.h.al <= AL_UNLOCKFIL)) || (r.h.al == AL_SKFMEND) || (r.h.al == AL_UNKNOWN_2D)) {
  /* ES:DI points to the SFT: if the bottom 6 bits of the device information
   * word in the SFT are > last drive, then it relates to files not associated
   * with drives, such as LAN Manager named pipes. */
    struct sftstruct far *sft = MK_FP(r.w.es, r.w.di);
    glob_reqdrv = sft->dev_info_word & 0x3F;
  } else {
    switch (r.h.al) {
      case AL_FINDNEXT:
        glob_reqdrv = glob_sdaptr->sdb.drv_lett & 0x1F;
        break;
      case AL_SETATTR:
      case AL_GETATTR:
      case AL_DELETE:
      case AL_OPEN:
      case AL_CREATE:
      case AL_SPOPNFIL:
      case AL_MKDIR:
      case AL_RMDIR:
      case AL_CHDIR:
      case AL_RENAME: /* check sda.fn1 for drive */
        glob_reqdrv = DRIVETONUM(glob_sdaptr->fn1[0]);
        break;
      default: /* otherwise check out the CDS (at ES:DI) */
        {
        struct cdsstruct far *cds = MK_FP(r.w.es, r.w.di);
        glob_reqdrv = DRIVETONUM(cds->current_path[0]);
      #if DEBUGLEVEL > 0 /* DEBUG output (ORANGE) */
        dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x6e00 | ('A' + glob_reqdrv);
        dbg_VGA[dbg_startoffset + dbg_xpos++] = 0x6e00 | ':';
      #endif
        }
        break;
    }
  }
  /* validate drive */
  if ((glob_reqdrv > 25) || (glob_data.ldrv[glob_reqdrv] == 0xff)) {
    goto CHAINTOPREVHANDLER;
  }

  /* This should not be necessary. DOS usually generates an FCB-style name in
   * the appropriate SDA area. However, in the case of user input such as
   * 'CD ..' or 'DIR ..' it leaves the fcb area all spaces, hence the need to
   * normalize the fcb area every time. */
  if (r.h.al != AL_DISKSPACE) {
    unsigned short i;
    unsigned char far *path = glob_sdaptr->fn1;

    /* fast forward 'path' to first character of the filename */
    for (i = 0;; i++) {
      if (glob_sdaptr->fn1[i] == '\\') path = glob_sdaptr->fn1 + i + 1;
      if (glob_sdaptr->fn1[i] == 0) break;
    }

    /* clear out fcb_fn1 by filling it with spaces */
    for (i = 0; i < 11; i++) glob_sdaptr->fcb_fn1[i] = ' ';

    /* copy 'path' into fcb_name using the fcb syntax ("FILE    TXT") */
    for (i = 0; *path != 0; path++) {
      if (*path == '.') {
        i = 8;
      } else {
        glob_sdaptr->fcb_fn1[i++] = *path;
      }
    }
  }

  /* copy interrupt registers into glob_intregs so the int handler can access them without using any stack */
  copybytes(&glob_intregs, &r, sizeof(union INTPACK));
  /* set stack to my custom memory */
  _asm {
    cli /* make sure to disable interrupts, so nobody gets in the way while I'm fiddling with the stack */
    mov glob_oldstack_seg, SS
    mov glob_oldstack_off, SP
    /* set SS to DS */
    mov ax, ds
    mov ss, ax
    /* set SP to the end of my DATASEGSZ (-2) */
    mov sp, DATASEGSZ-2
    sti
  }
  /* call the actual INT 2F processing function */
  process2f();
  /* switch stack back */
  _asm {
    cli
    mov SS, glob_oldstack_seg
    mov SP, glob_oldstack_off
    sti
  }
  /* copy all registers back so watcom will set them as required 'for real' */
  copybytes(&r, &glob_intregs, sizeof(union INTPACK));
  return;

  /* hand control to the previous INT 2F handler */
  CHAINTOPREVHANDLER:
  _mvchain_intr(MK_FP(glob_data.prev_2f_handler_seg, glob_data.prev_2f_handler_off));
}


/* ===================== LFN client service (increment 2) =====================
 * Services INT 21h/AX=714Eh (FindFirstFile), 714Fh (FindNextFile), 71A1h
 * (FindClose) for our own drive(s) by talking to the server's additive LFN
 * opcodes (AL_LFN_FINDFIRST 0x41 / FINDNEXT 0x42). 71A0h volume-info is answered
 * locally (advertising LFN so LFN-aware shells route here). 8.3 and the INT 2Fh
 * redirector path are completely untouched. */
#define AL_LFN_FINDFIRST 0x41
#define AL_LFN_FINDNEXT  0x42
#define AL_LFN_OPEN      0x43
#define AL_LFN_CREATE    0x44
#define AL_LFN_RENAME    0x47
#define AL_LFN_MKDIR     0x49
#define AL_LFN_TRUENAME  0x4D
/* resident-phase op selectors that are NOT wire opcodes (values chosen far
 * above the wire opcode range) */
#define LFNOP_TRUENAME   0xE0  /* 7160h CL=1/2: result to caller ES:DI */
#define LFNOP_PDPREP     0xE1  /* truename to alias path, then classic pass-down */
#define LFNOP_RENAME     0xE2  /* 7156h via server 0x47 */
#define LFNOP_MKDIR      0xE3  /* 7139h via server 0x49 */
#define LFNOP_GETCWD2    0xE4  /* 7147h phase 2: alias cwd -> long, to DS:SI */

/* FILETIME <-> DOS date/time conversion core for the 71A7h responder (resident;
 * no 32-bit mul/div -- see the header for the resident-safety rules) */
#include "ftconv.h"

static unsigned char lfn_upc(unsigned char c) {
  return ((c >= 'a') && (c <= 'z')) ? (unsigned char)(c - 32) : c;
}

/* Replicate the server's LFN mask FCB-ization (lfn_mask2fcb = filename2fcb +
 * the Win95 wildcard rule): expand an 8.3 leaf mask into an 11-byte FCB
 * template, '*' -> '?' to end of field, uppercased, space-padded. Win95 LFN
 * rule (RBIL, 714Eh): '*' matches ACROSS the dot and "*" == "*.*", so a mask
 * containing '*' but NO dot must wildcard the extension field too -- classic
 * FCB expansion would leave it blank ("matches only extension-less names"),
 * which made DIR under 4DOS list only directories. Must stay IDENTICAL to the
 * server's conversion or FindFirst (server template) and FindNext (this
 * template) would enumerate different sets. (s is a near ASCIZ leaf; this only
 * runs on the resident stack where SS==DS.) */
static void lfn_leaf2fcb(unsigned char *d, unsigned char *s) {
  int i;
  unsigned char sawstar = 0, sawdot = 0;
  for (i = 0; s[i] != 0; i++) {
    if (s[i] == '*') sawstar = 1;
    if (s[i] == '.') sawdot = 1;
  }
  for (i = 0; i < 11; i++) d[i] = ' ';
  for (i = 0; i < 8; i++) {          /* '.'/'..' entries */
    if (s[i] != '.') break;
    d[i] = '.';
  }
  for (; i < 8; i++) {               /* name field */
    if (s[i] == '*') { for (; i < 8; i++) d[i] = '?'; break; }
    if ((s[i] == '.') || (s[i] == 0)) break;
    d[i] = lfn_upc(s[i]);
  }
  if (sawstar && (sawdot == 0)) {    /* Win95: dot-less '*' wildcards the ext */
    for (i = 8; i < 11; i++) d[i] = '?';
    return;
  }
  while ((*s != '.') && (*s != 0)) s++;
  if (*s == 0) return;
  s++;                               /* skip the dot */
  d += 8;
  for (i = 0; i < 3; i++) {          /* extension field */
    if (s[i] == '*') { for (; i < 3; i++) d[i] = '?'; break; }
    if ((s[i] == '.') || (s[i] == 0)) break; /* '.'-break mirrors the server's
                                              * filename2fcb: multi-dot masks
                                              * (e.g. "*.c.bak") must FCB-ize
                                              * identically on both sides */
    d[i] = lfn_upc(s[i]);
  }
}

/* Format an 11-byte FCB name ("NAME    EXT") into an ASCIZ "NAME.EXT" at the
 * caller's (far) cAlternateFileName buffer. */
static void lfn_fcb2asciz(unsigned char far *d, unsigned char *fcb) {
  int i, k = 0;
  for (i = 0; i < 8; i++) { if (fcb[i] == ' ') break; d[k++] = fcb[i]; }
  if (fcb[8] != ' ') {
    d[k++] = '.';
    for (i = 8; i < 11; i++) { if (fcb[i] == ' ') break; d[k++] = fcb[i]; }
  }
  d[k] = 0;
}

/* Fill the caller's 318-byte WIN32_FIND_DATA (at fd, far) from an
 * AL_LFN_FINDFIRST/NEXT reply payload r (near, in the resident recv buffer).
 * Server §9.3 layout: [0]attr [1..11]FCB [12..15]DOS-time [16..19]size
 * [20..21]dirss [22..23]fpos [24]resv [25..32]FILETIME [33..34]ln [35..]longname.
 * si = the caller's date/time format selector (1 = DOS-packed, else FILETIME). */
static void lfn_fill_finddata(unsigned char far *fd, unsigned char *r, unsigned short si) {
  unsigned short i, ln;
  for (i = 0; i < 0x2c; i++) fd[i] = 0;      /* zero the fixed header */
  fd[0] = r[0];                              /* dwFileAttributes (low byte) */
  if (si == 1) {                             /* DOS-packed date/time in low dword of write-time */
    fd[0x14] = r[12]; fd[0x15] = r[13]; fd[0x16] = r[14]; fd[0x17] = r[15];
  } else {                                   /* 64-bit FILETIME in all three slots */
    for (i = 0; i < 8; i++) {
      unsigned char b = r[25 + i];
      fd[0x04 + i] = b; fd[0x0c + i] = b; fd[0x14 + i] = b;
    }
  }
  fd[0x20] = r[16]; fd[0x21] = r[17];        /* nFileSizeLow (high stays 0) */
  fd[0x22] = r[18]; fd[0x23] = r[19];
  ln = (unsigned short)r[33] | ((unsigned short)r[34] << 8);
  if (ln > 259) ln = 259;
  for (i = 0; i < ln; i++) fd[0x2c + i] = r[35 + i]; /* cFileName (long) */
  fd[0x2c + ln] = 0;
  lfn_fcb2asciz(fd + 0x130, r + 1);          /* cAlternateFileName (8.3 alias) */
}

/* Runs ON THE RESIDENT STACK (SS=DS) via the same swap as the 2Fh handler, so
 * it uses ONLY glob_intregs / resident globals, never the caller's 'r'. Sends
 * the FindFirst/Next query (per glob_lfn_op), fills the caller's WIN32_FIND_DATA
 * on success, updates the slot cursor, and sets glob_intregs (handle+CF-clear,
 * or AX=0x12 no-more + CF). */
/* Resolve the target drive for an LFN path, INCLUDING drive-less relative paths
 * ("*.*", "file.ext") which are relative to the current directory of the current
 * drive: adopt that drive only if its current dir is readable from its CDS
 * (lfn_server_path needs it). Qualified/root-relative paths go through
 * LFN_PATHDRV unchanged. Returns 0xFF when we must not claim (-> the call falls
 * back to the classic path, which stays correct). */
static unsigned char lfn_claimdrv(unsigned char far *p) {
  unsigned char idx = LFN_PATHDRV(p);
  if (idx == 0xff) {
    /* A bare relative name belongs to the DEFAULT drive, full stop (SDA 16h).
     * We used to additionally demand that glob_sdaptr->drive_cdsptr point at
     * that same drive, and declined the call when it did not -- but that
     * pointer tracks the CURRENT DOS OPERATION, so any preceding access to
     * another drive made us decline and hand the call to DOSLFN, which mangles
     * it for our PHYSICAL-flagged drive. The CWD now comes from the drive's own
     * CDS (cds_for_drive), so no such guard is needed. */
    idx = ((unsigned char far *)glob_sdaptr)[0x16];
  }
  return idx;
}

/* Copy an INT 21h LFN path into dst as a DRIVE-relative server path
 * ("\dir\file"): strip "X:", and for a relative (drive-less, non-rooted) path
 * prepend the current directory of drive `drv` (from its CDS) so e.g. "*.*"
 * resolves against the current dir, not the root. Returns the char count (no
 * NUL). Falls back to root-relative if the CDS is stale / for another drive. */
static unsigned short lfn_server_path(unsigned char *dst, unsigned char far *p,
                                      unsigned char drv) {
  unsigned short n = 0, i;
  if ((p[0] != 0) && (p[1] == ':')) p = p + 2;
  if ((p[0] != '\\') && (p[0] != '/')) {
    struct cdsstruct far *cds = cds_for_drive(drv);
    unsigned char far *cp = (cds != NULL) ? cds->current_path : NULL;
    if ((cp != NULL) && (cp[0] != 0) && (cp[1] == ':') &&
        ((unsigned char)DRIVETONUM(cp[0]) == drv)) {
      i = 2;
      while ((cp[i] != 0) && (n < 250)) { dst[n] = cp[i]; n++; i++; }
      if ((n == 0) || (dst[n - 1] != '\\')) { dst[n] = '\\'; n++; }
    }
  }
  for (i = 0; (p[i] != 0) && (n < 255); i++) { dst[n] = p[i]; n++; }
  return n;
}

static void lfn_do_find(void) {
  unsigned char *sb = glob_pktdrv_sndbuff + 60;
  unsigned char *ans;
  unsigned short *rax;
  unsigned short rc, plen;
  unsigned char slot = glob_lfn_slot;
  if (glob_lfn_op == AL_LFN_FINDFIRST) {
    unsigned char far *path = MK_FP(glob_intregs.w.ds, glob_intregs.w.dx);
    unsigned short n = 0, ls = 0, k;
    unsigned char leaf[128]; /* big enough to hold any realistic mask leaf so
                              * lfn_leaf2fcb finds the '.' exactly like the
                              * server does (it truncates only absurd >126-char
                              * search masks, which never occur in practice) */
    n = lfn_server_path(sb + 3, path, glob_lfn_drv);
    sb[0] = glob_lfn_find[slot].attr;   /* allowable attr */
    sb[1] = (unsigned char)(n & 0xff);  /* LFNSTR u16 length LE */
    sb[2] = (unsigned char)((n >> 8) & 0xff);
    plen = 3 + n;
    for (k = 0; k < n; k++) if (sb[3 + k] == '\\') ls = k + 1; /* leaf start */
    for (k = 0; (ls + k < n) && (k < sizeof(leaf) - 1); k++) leaf[k] = sb[3 + ls + k];
    leaf[k] = 0;
    lfn_leaf2fcb(glob_lfn_find[slot].tmpl, leaf); /* store mask for FindNext */
    /* also keep the long mask so FindNext can long-match like FindFirst
       (Win95); masks that don't fit degrade to SFN-template-only matching */
    for (k = 0; (leaf[k] != 0) && (k < 63); k++)
      glob_lfn_find[slot].mask[k] = leaf[k];
    if (leaf[k] == 0)
      glob_lfn_find[slot].mask[k] = 0;
    else
      glob_lfn_find[slot].mask[0] = 0; /* >63 chars: don't send a partial mask */
    { /* FindFirst is idempotent (server regenerates the listing at nth==0);
         retry once more on a total timeout so a single missed reply is not
         reported to the shell as an empty directory ("File not found") */
      unsigned char att;
      for (att = 0; att < 2; att++) {
        rc = sendquery(AL_LFN_FINDFIRST, glob_lfn_drv, plen, &ans, &rax, 0);
        if (rc != 0xffffu) break;
      }
    }
  } else { /* FINDNEXT */
    unsigned short i;
    sb[0] = (unsigned char)(glob_lfn_find[slot].dirss & 0xff);
    sb[1] = (unsigned char)((glob_lfn_find[slot].dirss >> 8) & 0xff);
    sb[2] = (unsigned char)(glob_lfn_find[slot].fpos & 0xff);
    sb[3] = (unsigned char)((glob_lfn_find[slot].fpos >> 8) & 0xff);
    sb[4] = glob_lfn_find[slot].attr;
    for (i = 0; i < 11; i++) sb[5 + i] = glob_lfn_find[slot].tmpl[i];
    plen = 16;
    if (glob_lfn_find[slot].mask[0] != 0) {
      /* OPTIONAL additive tail: LFNSTR long-name mask, so a new server
         long-matches FindNext like FindFirst; old servers ignore it */
      unsigned short ml = 0;
      while (glob_lfn_find[slot].mask[ml] != 0) ml++;
      sb[16] = (unsigned char)(ml & 0xff);
      sb[17] = (unsigned char)((ml >> 8) & 0xff);
      for (i = 0; i < ml; i++) sb[18 + i] = glob_lfn_find[slot].mask[i];
      plen = (unsigned short)(18 + ml);
    }
    rc = sendquery(AL_LFN_FINDNEXT, glob_lfn_drv, plen, &ans, &rax, 0);
  }
  if ((rc >= 35) && (rc != 0xffffu)) {        /* a real record */
    unsigned char far *fd = MK_FP(glob_intregs.w.es, glob_intregs.w.di);
    lfn_fill_finddata(fd, ans, glob_intregs.w.si);
    glob_lfn_find[slot].dirss = (unsigned short)ans[20] | ((unsigned short)ans[21] << 8);
    glob_lfn_find[slot].fpos  = (unsigned short)ans[22] | ((unsigned short)ans[23] << 8);
    glob_lfn_find[slot].inuse = 1;
    glob_lfn_find[slot].drv = glob_lfn_drv;
    if (glob_lfn_op == AL_LFN_FINDFIRST)
      glob_intregs.w.ax = LFN_HANDLE_MAGIC | slot; /* find handle */
    glob_intregs.w.cx = 0;                    /* Unicode-conversion flags = none */
    glob_intregs.w.flags &= ~INTR_CF;
  } else {                                    /* no more files / timeout */
    if (glob_lfn_op == AL_LFN_FINDFIRST) glob_lfn_find[slot].inuse = 0;
    glob_intregs.w.ax = 0x12;                 /* ERROR_NO_MORE_FILES */
    glob_intregs.w.flags |= INTR_CF;
  }
}

/* Send AL_LFN_TRUENAME (0x4D) for the (drive-stripped) caller path. subfn:
 * 1 = long -> full 8.3-alias path, 2 = alias/mixed -> long. Returns the
 * sendquery result (payload length, or 0xFFFF on timeout); *ansp -> payload
 * (u16 LE length + path bytes), *raxp -> the reply AX. Resident-stack only. */
static unsigned short lfn_send_truename(unsigned char subfn,
                                        unsigned char far *path,
                                        unsigned char **ansp,
                                        unsigned short **raxp) {
  unsigned char *sb = glob_pktdrv_sndbuff + 60;
  unsigned short n = 0, rc;
  unsigned char att;
  n = lfn_server_path(sb + 3, path, glob_lfn_drv);
  if (n == 0) { sb[3] = '\\'; n = 1; } /* bare "X:" -> root, never send an
                          empty path (an old/short-guarded server drops it) */
  sb[0] = subfn;
  sb[1] = (unsigned char)(n & 0xff);
  sb[2] = (unsigned char)((n >> 8) & 0xff);
  /* truename is idempotent: retry once more on a total timeout so a single
     missed reply does not surface as a spurious error to the caller */
  for (att = 0; att < 2; att++) {
    rc = sendquery(AL_LFN_TRUENAME, glob_lfn_drv, (unsigned short)(3 + n),
                   ansp, raxp, 0);
    if (rc != 0xffffu) break;
  }
  return rc;
}

/* 716Ch open/create, part 1 of 2 -- the server work. Runs ON THE RESIDENT
 * STACK (uses only glob_intregs/resident globals, like lfn_do_find). Probes
 * existence via AL_LFN_OPEN (a server-side stat: no open file, no side
 * effects), applies the Win95 action word (glob_intregs.w.dx: bit0
 * open-if-exists, bit1 truncate-if-exists, bit4 create-if-missing), creating/
 * truncating via AL_LFN_CREATE when required (which creates the file under
 * its REAL long name server-side and applies the CX attributes), and prepares
 * for part 2 (the classic 6C00h pass-down, done by the dispatcher AFTER the
 * stack is restored -- the nested DOS open re-enters our 2Fh handler, which
 * must not see SS==DS):
 *  - glob_lfn_openpath = ASCIZ "X:\dir\ALIAS.EXT" (caller's dir part + the
 *    server-reported 8.3 alias of the leaf),
 *  - glob_lfn_opensyn  = CX action-taken to report (1 opened / 2 created /
 *    3 replaced) -- synthesized here because 6C00h on redirector drives has
 *    documented CX-return kernel bugs,
 *  - glob_lfn_openerr  = 0 to proceed, else the DOS error to fail with. */
static void lfn_do_open(void) {
  unsigned char *sb = glob_pktdrv_sndbuff + 60;
  unsigned char *ans;
  unsigned short *rax;
  unsigned short rc, n, k, action, exists;
  unsigned char far *path = MK_FP(glob_intregs.w.ds, glob_intregs.w.si);
  action = glob_intregs.w.dx & 0x0013; /* bit0 open, bit1 truncate, bit4 create */
  glob_lfn_openerr = 0;
  /* copy the drive-stripped path into the request as LFNSTR (probe), resolving
   * a relative path against the current dir (so 7z etc. can open a long name
   * while our drive is current) */
  n = lfn_server_path(sb + 3, path, glob_lfn_drv);
  sb[0] = 0;                          /* open mode byte (server ignores it) */
  sb[1] = (unsigned char)(n & 0xff);  /* LFNSTR u16 length LE */
  sb[2] = (unsigned char)((n >> 8) & 0xff);
  rc = sendquery(AL_LFN_OPEN, glob_lfn_drv, (unsigned short)(3 + n), &ans, &rax, 0);
  if (rc == 0xffffu) { glob_lfn_openerr = 0x02; return; } /* net timeout */
  exists = (rc >= 35) ? 1 : 0;
  /* Win95 716Ch action semantics */
  if (exists) {
    if (action & 0x02) {        /* truncate/replace-if-exists */
      glob_lfn_opensyn = 3;
    } else if (action & 0x01) { /* open-if-exists */
      glob_lfn_opensyn = 1;
    } else {                    /* create-new-only, but it exists */
      glob_lfn_openerr = 0x50;  /* file already exists */
      return;
    }
  } else {
    if (*rax != 0x02) { glob_lfn_openerr = *rax ? *rax : 0x02; return; }
    if (action & 0x10) {        /* create-if-missing */
      glob_lfn_opensyn = 2;
    } else {                    /* open/truncate of a missing file */
      glob_lfn_openerr = 0x02;  /* file not found */
      return;
    }
  }
  if ((glob_lfn_opensyn == 2) || (glob_lfn_opensyn == 3)) {
    /* (re)create server-side: lands under the REAL long name, truncates an
     * existing file, applies the create attributes; reply carries the alias */
    unsigned char cattr = (unsigned char)(glob_intregs.w.cx & 0xff);
    unsigned short m = 0;
    path = MK_FP(glob_intregs.w.ds, glob_intregs.w.si);
    m = lfn_server_path(sb + 4, path, glob_lfn_drv);
    sb[0] = cattr;
    sb[1] = 0;                          /* reserved */
    sb[2] = (unsigned char)(m & 0xff);  /* LFNSTR u16 length LE */
    sb[3] = (unsigned char)((m >> 8) & 0xff);
    rc = sendquery(AL_LFN_CREATE, glob_lfn_drv, (unsigned short)(4 + m), &ans, &rax, 0);
    if ((rc < 35) || (rc == 0xffffu)) {
      glob_lfn_openerr = (rc == 0xffffu) ? 0x05 : (*rax ? *rax : 0x05);
      return;
    }
  }
  /* Build the pass-down path via server TRUENAME (0x4D CL=1): the WHOLE
   * path is translated to its 8.3-alias form component-wise, so LONG
   * intermediate directories work (the old code spliced caller-dir + alias
   * leaf, which required 8.3-clean parents). Prefixed with OUR drive letter
   * so DOS resolves against our drive. The result is absolute: a
   * drive-relative input ("X:FILE.TXT") resolves against the share root --
   * consistent with what the probe/create above already did. */
  path = MK_FP(glob_intregs.w.ds, glob_intregs.w.si);
  {
    unsigned short *trax;
    rc = lfn_send_truename(1, path, &ans, &trax);
    if (rc == 0xffffu) { glob_lfn_openerr = 0x02; return; }
    if (rc < 3) {
      glob_lfn_openerr = (*trax != 0) ? *trax : 0x03;
      return;
    }
  }
  n = (unsigned short)ans[0] | ((unsigned short)ans[1] << 8);
  if (n + 3 >= sizeof(glob_lfn_openpath)) { /* alias path too long */
    glob_lfn_openerr = 0x03;
    return;
  }
  glob_lfn_openpath[0] = (unsigned char)('A' + glob_lfn_drv);
  glob_lfn_openpath[1] = ':';
  for (k = 0; k < n; k++) glob_lfn_openpath[2 + k] = ans[2 + k];
  glob_lfn_openpath[2 + n] = 0;
}
/* Remaining LFN ops, resident-stack phase (uses only glob_intregs + resident
 * globals + far pointers, like lfn_do_find/lfn_do_open). Selected via
 * glob_lfn_op -- see the LFNOP_* constants. */
static void lfn_do_misc(void) {
  unsigned char *sb = glob_pktdrv_sndbuff + 60;
  unsigned char *ans;
  unsigned short *rax;
  unsigned short rc, n, k;
  if (glob_lfn_op == LFNOP_TRUENAME) {
    /* 7160h CL=1/2: path from caller DS:SI, result "X:\..." to caller ES:DI */
    unsigned char far *src = MK_FP(glob_intregs.w.ds, glob_intregs.w.si);
    unsigned char far *dst = MK_FP(glob_intregs.w.es, glob_intregs.w.di);
    rc = lfn_send_truename(glob_lfn_sub, src, &ans, &rax);
    if (rc == 0xffffu) {
      glob_intregs.w.ax = 0x02;
      glob_intregs.w.flags |= INTR_CF;
      return;
    }
    if (rc < 3) {
      glob_intregs.w.ax = (*rax != 0) ? *rax : 0x03;
      glob_intregs.w.flags |= INTR_CF;
      return;
    }
    n = (unsigned short)ans[0] | ((unsigned short)ans[1] << 8);
    if ((glob_lfn_sub == 1) && (n > 64)) {
      /* RBIL rb-3207: the CL=1 result buffer is only 67 bytes (classic SFN
       * path limit). "X:" + n + NUL must fit -> fail rather than overrun. */
      glob_intregs.w.ax = 0x03;
      glob_intregs.w.flags |= INTR_CF;
      return;
    }
    if (n > 257) n = 257; /* CL=2 caller buffer is 261 bytes incl. "X:" + NUL */
    dst[0] = (unsigned char)('A' + glob_lfn_drv);
    dst[1] = ':';
    for (k = 0; k < n; k++) dst[2 + k] = ans[2 + k];
    dst[2 + n] = 0;
    glob_intregs.w.ax = 0; /* RBIL: AX destroyed on success */
    glob_intregs.w.flags &= ~INTR_CF;
  } else if (glob_lfn_op == LFNOP_PDPREP) {
    /* del/rd/cd/attr: translate caller DS:DX path to "X:\ALIAS\..." into
     * glob_lfn_openpath; the dispatcher then passes the classic call down */
    unsigned char far *src = MK_FP(glob_intregs.w.ds, glob_intregs.w.dx);
    glob_lfn_openerr = 0;
    rc = lfn_send_truename(1, src, &ans, &rax);
    if (rc == 0xffffu) { glob_lfn_openerr = 0x02; return; }
    if (rc < 3) {
      glob_lfn_openerr = (*rax != 0) ? *rax : 0x03;
      return;
    }
    n = (unsigned short)ans[0] | ((unsigned short)ans[1] << 8);
    if (n + 3 >= sizeof(glob_lfn_openpath)) { glob_lfn_openerr = 0x03; return; }
    glob_lfn_openpath[0] = (unsigned char)('A' + glob_lfn_drv);
    glob_lfn_openpath[1] = ':';
    for (k = 0; k < n; k++) glob_lfn_openpath[2 + k] = ans[2 + k];
    glob_lfn_openpath[2 + n] = 0;
  } else if (glob_lfn_op == LFNOP_RENAME) {
    /* 7156h: old DS:DX + new ES:DI -> server 0x47 (LFNSTR + LFNSTR); the
     * target leaf keeps its REAL long name server-side */
    unsigned char far *po = MK_FP(glob_intregs.w.ds, glob_intregs.w.dx);
    unsigned char far *pn = MK_FP(glob_intregs.w.es, glob_intregs.w.di);
    unsigned short l1 = 0, l2 = 0;
    l1 = lfn_server_path(sb + 2, po, glob_lfn_drv);
    sb[0] = (unsigned char)(l1 & 0xff);
    sb[1] = (unsigned char)((l1 >> 8) & 0xff);
    l2 = lfn_server_path(sb + 4 + l1, pn, glob_lfn_drv);
    sb[2 + l1] = (unsigned char)(l2 & 0xff);
    sb[3 + l1] = (unsigned char)((l2 >> 8) & 0xff);
    rc = sendquery(AL_LFN_RENAME, glob_lfn_drv,
                   (unsigned short)(4 + l1 + l2), &ans, &rax, 0);
    if (rc == 0xffffu) {
      glob_intregs.w.ax = 0x05;
      glob_intregs.w.flags |= INTR_CF;
    } else if (*rax != 0) {
      glob_intregs.w.ax = *rax;
      glob_intregs.w.flags |= INTR_CF;
    } else {
      glob_intregs.w.ax = 0;
      glob_intregs.w.flags &= ~INTR_CF;
    }
  } else if (glob_lfn_op == LFNOP_MKDIR) {
    /* 7139h: path DS:DX -> server 0x49 (created under the real long name) */
    unsigned char far *src = MK_FP(glob_intregs.w.ds, glob_intregs.w.dx);
    unsigned short l1 = 0;
    l1 = lfn_server_path(sb + 2, src, glob_lfn_drv);
    sb[0] = (unsigned char)(l1 & 0xff);
    sb[1] = (unsigned char)((l1 >> 8) & 0xff);
    rc = sendquery(AL_LFN_MKDIR, glob_lfn_drv, (unsigned short)(2 + l1),
                   &ans, &rax, 0);
    if (rc == 0xffffu) {
      glob_intregs.w.ax = 0x05;
      glob_intregs.w.flags |= INTR_CF;
    } else if (*rax != 0) {
      glob_intregs.w.ax = *rax;
      glob_intregs.w.flags |= INTR_CF;
    } else {
      glob_intregs.w.ax = 0;
      glob_intregs.w.flags &= ~INTR_CF;
    }
  } else if (glob_lfn_op == LFNOP_GETCWD2) {
    /* 7147h phase 2: glob_lfn_openpath = alias cwd from the classic 47h
     * pass-down (no drive, no leading backslash, RBIL form). Translate to
     * long via 0x4D CL=2 and write to caller DS:SI in the same form. */
    unsigned char far *dst = MK_FP(glob_intregs.w.ds, glob_intregs.w.si);
    unsigned short l1 = 0, skip;
    /* scan bound = the buffer's own size: 254 exceeded the 128-byte
     * glob_lfn_openpath and could read adjacent resident globals if the
     * classic 47h ever left it unterminated */
    while ((glob_lfn_openpath[l1] != 0) &&
           (l1 < sizeof(glob_lfn_openpath) - 2)) l1++;
    sb[0] = 2;
    sb[1] = (unsigned char)((l1 + 1) & 0xff);
    sb[2] = (unsigned char)(((l1 + 1) >> 8) & 0xff);
    sb[3] = 0x5C; /* re-add the leading backslash for the server walk */
    for (k = 0; k < l1; k++) sb[4 + k] = glob_lfn_openpath[k];
    rc = sendquery(AL_LFN_TRUENAME, glob_lfn_drv, (unsigned short)(4 + l1),
                   &ans, &rax, 0);
    if ((rc == 0xffffu) || (rc < 3)) {
      /* fall back to the alias cwd the classic call already returned */
      for (k = 0; k <= l1; k++) dst[k] = glob_lfn_openpath[k];
      glob_intregs.w.ax = 0;
      glob_intregs.w.flags &= ~INTR_CF;
      return;
    }
    n = (unsigned short)ans[0] | ((unsigned short)ans[1] << 8);
    skip = ((n > 0) && (ans[2] == 0x5C)) ? 1 : 0;
    if ((unsigned short)(n - skip) > 259) n = (unsigned short)(259 + skip);
    for (k = 0; k < (unsigned short)(n - skip); k++) dst[k] = ans[2 + skip + k];
    dst[n - skip] = 0;
    glob_intregs.w.ax = 0;
    glob_intregs.w.flags &= ~INTR_CF;
  }
}

/* Generic classic-call pass-down on the CALLER's stack (same proven pattern
 * as the 716Ch 6C00h block): load the register image while BP is still valid,
 * simulate INT 21h to the previous handler, restore all registers, and only
 * THEN store the results into DS-relative globals (DOS may clobber BP during
 * the call, so BP-relative locals are unsafe until after the restore).
 * pdx/psi are raw register values; for pointer-taking calls pass the OFFSET
 * of a RESIDENT buffer (DS = our resident segment during the call; ES is set
 * = DS as well). Results: glob_lfn_pdax / glob_lfn_pdcx / glob_lfn_pdfl. */
static void lfn_passdown(unsigned short pax, unsigned short pbx,
                         unsigned short pcx, unsigned short pdx,
                         unsigned short psi) {
  _asm {
    push bp
    push ds
    push es
    push si
    push di
    push bx
    mov ax, pax
    mov bx, pbx
    mov cx, pcx
    mov dx, pdx
    mov si, psi
    push ds
    pop es
    sti
    pushf
    cli
    call dword ptr glob_prev21call
    pop bx
    pop di
    pop si
    pop es
    pop ds
    pop bp
    mov glob_lfn_pdax, ax
    mov glob_lfn_pdcx, cx
    pushf
    pop ax
    mov glob_lfn_pdfl, ax
  }
}
/* ========================================================================== */


/* This function is hooked on INT 21h. It is RESIDENT (defined before
 * begtextend) and carries its own DS-patch signature ("MV21"), exactly like
 * inthandler() above.
 *
 * It currently services the disk-space queries (AH=36h and AX=7303h) for our
 * own drive(s) -- see the comment on those branches below -- and chains
 * everything else (including the not-yet-implemented LFN AX=71xxh calls) to the
 * previous handler. The AH==71h branch is reserved for a future increment that
 * will advertise LFN (71A0h) and service FindFirst/Next/Open/Create for our
 * drives so DOSLFN no longer needs to (and stops mangling) those drives. */

void __interrupt __far inthandler21(union INTPACK r) {
  _asm {
    jmp SKIPTSRSIG21
    TSRSIG21 DB 'M','V','2','1'
    SKIPTSRSIG21:
    /* save AX, switch to the patched (resident) DS, restore AX */
    push ax
    mov ax, 0 /* 0 is patched to the resident DS segment by updatetsrds() */
    mov ds, ax
    pop ax
  }
  /* The INTPACK 'r' lives on the (SS-relative) stack frame, so reading it is
   * unaffected by the DS switch above. */

  /* Answer disk-space queries for our own drive(s) directly, with valid values.
   * DOS satisfies INT 21h/AH=36h locally for our redirector drive (it carries
   * the CDS PHYSICAL bit, needed so MS-DOS doesn't ignore the drive) and returns
   * AX=0xFFFF (invalid drive) instead of routing to us via INT 2Fh/110Ch.
   * COMMAND.COM ignores that and lists anyway, but 4DOS's DIR calls its
   * QueryDiskInfo FIRST and treats AX=0xFFFF as a fatal invalid-drive: it does
   * `continue' and skips the whole listing, showing only the volume label. By
   * reporting a plain, valid volume here we let 4DOS proceed to the file
   * enumeration (which we DO serve via INT 2Fh), and both shells get a sane
   * "bytes free" footer instead of garbage.
   *
   * We report using the SAME scheme the server uses for INT 2Fh/110Ch (see
   * ethersrv.c): sectors-per-cluster = 1 (MS-DOS tolerates only 1), 32768 bytes
   * per sector, capped at ~2 GiB. NOTE: DOS swaps BX<->DX between 110Ch (BX=total
   * DX=avail) and AH=36h (BX=avail DX=total); since we answer AH=36h *directly*
   * we use the AH=36h convention here. total==avail so the order is moot. */
  if (r.h.ah == 0x36) { /* GET FREE DISK SPACE; DL = drive (0=default,1=A,..) */
    /* DL=0 means the CURRENT default drive; resolve it from the SDA (offset 16h
     * = current logical drive, 0=A). COMMAND.COM uses DL=0 for its DIR footer
     * when the prompt is already ON our drive, so we must handle it too -- else
     * the footer shows only when DIR is run from another drive (e.g. "dir e:"
     * from C:). glob_sdaptr is the DOS SDA obtained at install. */
    unsigned char idx = (r.h.dl == 0)
                          ? ((unsigned char far *)glob_sdaptr)[0x16]
                          : (unsigned char)(r.h.dl - 1);
    if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) {
      r.w.ax = 1;      /* sectors per cluster (MS-DOS tolerates only 1 here) */
      r.w.cx = 32768;  /* bytes per sector */
      r.w.bx = 0xffff; /* number of available clusters (~2 GiB, server-capped) */
      r.w.dx = 0xffff; /* total number of clusters      (~2 GiB, server-capped) */
      return;          /* handled here -- do NOT chain */
    }
  }
  if (r.w.ax == 0x7303) { /* Win95 GET EXTENDED FREE SPACE (FAT32) */
    /* DS:DX -> ASCIZ drive root ("E:\"); ES:DI -> caller buffer (ExtGetDskFre-
     * SpcStruc, 44 bytes); CX = buffer length. Both 4DOS's QueryDiskInfo AND
     * COMMAND.COM (PC DOS 7.x, FAT32-aware) use 7303h for the DIR free-space
     * footer. If we just chain it, DOS answers locally for our PHYSICAL drive
     * and it fails; if we force it "unsupported", COMMAND.COM shows no footer at
     * all. So we FILL the struct with the same values we report for AH=36h. The
     * field layout matches 4DOS's FAT32 struct (4DOS.H) and RBIL:
     *   00h W size, 02h W version, 04h D sec/clus, 08h D bytes/sec,
     *   0Ch D avail clusters, 10h D total clusters, 14h D avail phys sectors,
     *   18h D total phys sectors, 1Ch D avail alloc units, 20h D total alloc
     *   units, 24h..2Bh reserved. */
    unsigned char far *rootpath = MK_FP(r.w.ds, r.w.dx);
    unsigned char drv = 0xff;
    if ((rootpath[0] != 0) && (rootpath[1] == ':'))
      drv = DRIVETONUM(rootpath[0]);
    if ((drv <= 25) && (glob_data.ldrv[drv] != 0xff)) {
      if (r.w.cx >= 0x2c) { /* caller buffer big enough for the full struct */
        unsigned char far *b = MK_FP(r.w.es, r.w.di);
        unsigned short far *w = (unsigned short far *)b;
        unsigned long far *dw;
        unsigned int k;
        for (k = 0; k < 0x2c; k++) b[k] = 0;
        w[0] = 0x2c;              /* 00h structure size */
        w[1] = 0;                 /* 02h structure version (0) */
        dw = (unsigned long far *)(b + 4);
        dw[0] = 1ul;              /* 04h sectors per cluster */
        dw[1] = 32768ul;          /* 08h bytes per sector */
        dw[2] = 0xfffful;         /* 0Ch available clusters   (~2 GiB) */
        dw[3] = 0xfffful;         /* 10h total clusters        (~2 GiB) */
        dw[4] = 0xfffful;         /* 14h available phys sectors */
        dw[5] = 0xfffful;         /* 18h total phys sectors */
        dw[6] = 0xfffful;         /* 1Ch available allocation units */
        dw[7] = 0xfffful;         /* 20h total allocation units */
        r.w.ax = 0;               /* success */
        r.w.flags &= ~INTR_CF;    /* CF clear = OK */
      } else {
        /* buffer too small: force "unsupported" so 4DOS falls back to AH=36h */
        r.w.ax = 0x7100;
        r.w.flags |= INTR_CF;
      }
      return;                     /* handled here -- do NOT chain */
    }
  }
  if (r.w.ax == 0x6900) { /* GET DISK SERIAL NUMBER (DOS 4+) */
    /* BL = drive (0=default,1=A,..); DS:DX -> 25-byte info buffer:
     *   00h WORD info level, 02h DWORD serial, 06h 11B label, 11h 8B fstype.
     * DOS has no serial for our (PHYSICAL) redirector drive, so DIR shows no
     * "Volume Serial Number" line (4DOS and COMMAND.COM print it only when the
     * serial != 0). We return a stable synthetic serial EDF5-xxxx (high word =
     * the EtherDFS ethertype 0xEDF5; low word = the last 2 bytes of the server
     * MAC, so it differs per server). NOTE: shells that skip the serial query
     * for network drives (4DOS's QueryVolumeInfo does: "if QueryDriveRemote goto
     * dos_3") never call this -- only COMMAND.COM benefits. */
    unsigned char idx = (r.h.bl == 0)
                          ? ((unsigned char far *)glob_sdaptr)[0x16]
                          : (unsigned char)(r.h.bl - 1);
    if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) {
      unsigned char far *buf = MK_FP(r.w.ds, r.w.dx);
      unsigned int k;
      for (k = 0; k < 25; k++) buf[k] = 0;
      /* 00h..01h info level = 0 (left zeroed) */
      buf[2] = GLOB_RMAC[5]; /* 02h serial (DWORD, little-endian): low word = */
      buf[3] = GLOB_RMAC[4]; /*    server MAC[4..5]; high word = 0xEDF5        */
      buf[4] = 0xf5;
      buf[5] = 0xed;
      for (k = 0; k < 11; k++) buf[6 + k] = ' '; /* 06h label (shells read the */
      buf[6] = 'R'; buf[7] = 'E'; buf[8] = 'T'; /*    real label via FindFirst) */
      buf[9] = 'R'; buf[10] = 'O';
      buf[17] = 'F'; buf[18] = 'A'; buf[19] = 'T'; /* 11h filesystem type */
      buf[20] = '1'; buf[21] = '6';
      buf[22] = ' '; buf[23] = ' '; buf[24] = ' ';
      r.w.ax = 0;            /* success */
      r.w.flags &= ~INTR_CF; /* CF clear = OK */
      return;               /* handled here -- do NOT chain */
    }
  }
  /* DOSLFN treats our PHYSICAL redirector drive as a native local FAT volume and
   * services the LEGACY MkDir (INT 21h AH=39h) itself, trying to write the new
   * directory's VFAT long-name entry via direct sector I/O - which our sectorless
   * drive cannot do, so a plain `MD X:\dir` (COMMAND.COM, batch, or any program
   * whose runtime issues AH=39h) HANGS on our drive. Norton/Volkov Commander work
   * because they issue the LFN MkDir 7139h, which reaches us directly. Our INT 21h
   * hook runs BEFORE DOSLFN (etherdfs loads after doslfn), so rewrite a legacy
   * MkDir of a drive-qualified path on one of our drives into its LFN twin: AH
   * 39h -> 71h keeps AL=39h, i.e. AX=7139h, with the same DS:DX ASCIIZ path and
   * the same CF/AX return. The AH=71h dispatch below then sends it to the server,
   * bypassing DOSLFN. Only drive-qualified paths ("X:\..") are rerouted - the
   * exact condition the 7139h branch itself accepts - so the rewrite can never
   * hand that branch a call it would decline and fall through into the chain with
   * a mangled AH. (DN OSP's own F7 make-directory does not take this path: it
   * expands via 7160h and creates via the LFN 7139h; its silent-no-op on our
   * drive was a separate 7160h/CL=0 bug, fixed in the TRUENAME handler below.) */
  if (r.h.ah == 0x39) {
    unsigned char far *pp = MK_FP(r.w.ds, r.w.dx);
    unsigned char idx = 0xff;
    if ((pp[0] != 0) && (pp[1] == ':')) idx = DRIVETONUM(pp[0]);
    if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) r.h.ah = 0x71;
  }
  if (r.h.ah == 0x71) {
    unsigned char do_lfn = 0; /* set to 1 to run the guarded server round-trip */
    /* Nested-context flag, computed BEFORE any branch may write the shared
     * glob_lfn_* dispatch globals: while an outer invocation is blocked in
     * sendquery (interrupts on, SS==DS), an ISR-issued LFN call must NOT
     * overwrite glob_lfn_op/pdop/drv/... -- the outer would resume and
     * execute the WRONG operation (e.g. a set-attr pass-down flipped into a
     * delete). Every our-drive branch bails on this flag before its first
     * global write; the guard inside the do_lfn block stays as backstop. */
    volatile unsigned char lfn_nested = 0;
    _asm {
      push ax
      push bx
      mov ax, ss
      mov bx, ds
      cmp ax, bx
      jne n71top
      mov byte ptr lfn_nested, 1
    n71top:
      pop bx
      pop ax
    }
    if (r.h.al == 0xA0) { /* 71A0h GET VOLUME INFO -- advertise LFN locally */
      unsigned char far *rp = MK_FP(r.w.ds, r.w.dx); /* ASCIZ "X:\" */
      unsigned char idx = 0xff;
      idx = LFN_PATHDRV(rp);
      if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) {
        if (r.w.cx >= 4) { /* ES:DI file-system name "EDF5" */
          unsigned char far *fsn = MK_FP(r.w.es, r.w.di);
          fsn[0] = 'E'; fsn[1] = 'D'; fsn[2] = 'F'; fsn[3] = '5';
          if (r.w.cx > 4) fsn[4] = 0;
        }
        r.w.bx = 0x4002; /* bit14 supports LFN | bit1 preserves case */
        r.w.cx = 255;    /* max filename component length */
        r.w.dx = 260;    /* max path length */
        r.w.flags &= ~INTR_CF;
        return;          /* handled locally, no server round-trip */
      }
    } else if (r.h.al == 0x4E) { /* 714Eh FindFirstFile */
      unsigned char far *pp = MK_FP(r.w.ds, r.w.dx); /* ASCIZ search path */
      unsigned char idx = 0xff, s;
      idx = lfn_claimdrv(pp);
      if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) { /* our drive */
        if (lfn_nested) { r.w.ax = 0x0005; r.w.flags |= INTR_CF; return; }
        for (s = 0; s < LFN_FINDMAX; s++) if (glob_lfn_find[s].inuse == 0) break;
        if (s >= LFN_FINDMAX) { /* find table full */
          r.w.ax = 0x12; r.w.flags |= INTR_CF; return;
        }
        glob_lfn_slot = s;
        glob_lfn_drv = idx;
        glob_lfn_find[s].attr = r.h.cl; /* allowable-attribute mask */
        glob_lfn_op = AL_LFN_FINDFIRST;
        do_lfn = 1;
      }
    } else if (r.h.al == 0x4F) { /* 714Fh FindNextFile */
      if ((r.w.bx & 0xff00u) == LFN_HANDLE_MAGIC) {
        unsigned char s = (unsigned char)(r.w.bx & 0xff);
        if ((s < LFN_FINDMAX) && (glob_lfn_find[s].inuse != 0)) { /* our handle */
          if (lfn_nested) { r.w.ax = 0x0005; r.w.flags |= INTR_CF; return; }
          glob_lfn_slot = s;
          glob_lfn_drv = glob_lfn_find[s].drv;
          glob_lfn_op = AL_LFN_FINDNEXT;
          do_lfn = 1;
        }
      }
    } else if (r.h.al == 0xA1) { /* 71A1h FindClose */
      if ((r.w.bx & 0xff00u) == LFN_HANDLE_MAGIC) {
        unsigned char s = (unsigned char)(r.w.bx & 0xff);
        if ((s < LFN_FINDMAX) && (glob_lfn_find[s].inuse != 0)) {
          if (lfn_nested) { r.w.ax = 0x0005; r.w.flags |= INTR_CF; return; }
          glob_lfn_find[s].inuse = 0;
          r.w.flags &= ~INTR_CF; /* success */
          return;
        }
      }
    } else if (r.h.al == 0x6C) { /* 716Ch LFN open/create */
      /* Path is at DS:SI (unlike find's DS:DX!). Server work first (probe/
       * create + alias, on the resident stack), then a classic 6C00h open of
       * the alias path is passed down to DOS on the CALLER's stack -- DOS
       * allocates JFT/SFT/handle and routes through our proven 2Fh redirector,
       * so read/write/seek/close just work. DI (alias hint) is ignored unless
       * BX bit 10, which nothing we know sets. */
      unsigned char far *pp = MK_FP(r.w.ds, r.w.si);
      unsigned char idx = 0xff;
      idx = lfn_claimdrv(pp);
      if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) { /* our drive */
        if (lfn_nested) { r.w.ax = 0x0005; r.w.flags |= INTR_CF; return; }
        glob_lfn_drv = idx;
        glob_lfn_op = AL_LFN_OPEN;
        do_lfn = 1;
      }
    } else if (r.h.al == 0x60) { /* 7160h TRUENAME (CL=0/1/2) */
      unsigned char far *pp = MK_FP(r.w.ds, r.w.si);
      unsigned char idx = 0xff;
      idx = lfn_claimdrv(pp);
      if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) {
        if (r.h.cl == 0) {
          /* 7160h CL=0 = canonicalize to an ABSOLUTE, un-shortened path (Win9x
           * uppercases the SFN parts). The old code only uppercased the input,
           * assuming it was already drive-qualified -- true for 4DOS's mkfname,
           * but NOT for DN OSP 6.4.0's DPMI build: its SIM95TrueName expands a
           * bare RELATIVE make-dir name ("QDIR") through CL=0, and when the
           * result carries no drive letter DN's CreateDirInheritance bails
           * silently ("no ':' -> Exit") -- so F7 "new directory" did nothing on
           * our drive. Make a relative path absolute here by prepending "X:" +
           * the current directory (from the CDS, the same source lfn_server_path
           * uses), so "QDIR" at E:\OS canonicalizes to "E:\OS\QDIR". A path that
           * is already drive-qualified or UNC is copied (uppercased) unchanged. */
          unsigned char far *dst = MK_FP(r.w.es, r.w.di);
          unsigned char far *sp = pp;
          unsigned short n = 0;
          unsigned char c;
          if ((pp[1] != ':') && !((pp[0] == '\\') && (pp[1] == '\\'))) {
            dst[0] = (unsigned char)('A' + idx);
            dst[1] = ':';
            n = 2;
            if ((pp[0] != '\\') && (pp[0] != '/')) { /* truly relative: add cwd */
              struct cdsstruct far *cds = cds_for_drive(idx);
              unsigned char far *cp = (cds != NULL) ? cds->current_path : NULL;
              if ((cp != NULL) && (cp[0] != 0) && (cp[1] == ':') &&
                  ((unsigned char)DRIVETONUM(cp[0]) == idx)) {
                unsigned short i = 2; /* skip the CDS path's own "X:" */
                while ((cp[i] != 0) && (n < 256)) {
                  c = cp[i++];
                  dst[n++] = ((c >= 'a') && (c <= 'z')) ? (unsigned char)(c - 32) : c;
                }
                if (dst[n - 1] != '\\') dst[n++] = '\\';
              } else {
                dst[n++] = '\\'; /* CDS stale -> resolve against the root */
              }
            }
          }
          for (; (sp[0] != 0) && (n < 260); sp++) {
            c = sp[0];
            dst[n++] = ((c >= 'a') && (c <= 'z')) ? (unsigned char)(c - 32) : c;
          }
          dst[n] = 0;
          r.w.ax = 0;
          r.w.flags &= ~INTR_CF;
          return;
        }
        if ((r.h.cl == 1) || (r.h.cl == 2)) {
          if (lfn_nested) { r.w.ax = 0x0005; r.w.flags |= INTR_CF; return; }
          glob_lfn_drv = idx;
          glob_lfn_sub = r.h.cl;
          glob_lfn_op = LFNOP_TRUENAME;
          do_lfn = 1;
        }
        /* other CL -> chain */
      }
    } else if (r.h.al == 0x41) { /* 7141h delete (exact long names) */
      unsigned char far *pp = MK_FP(r.w.ds, r.w.dx);
      unsigned char idx = 0xff, wild = 0;
      unsigned short k2;
      idx = lfn_claimdrv(pp);
      if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) {
        for (k2 = 0; (pp[k2] != 0) && (k2 < 260); k2++)
          if ((pp[k2] == '*') || (pp[k2] == '?')) wild = 1;
        if (wild) {
          /* RBIL: SI=0 forbids wildcards (error 3); SI=1 wildcard delete is
           * not implemented (4DOS never sends it) -> access denied */
          r.w.ax = ((r.w.si & 1) == 0) ? 0x03 : 0x05;
          r.w.flags |= INTR_CF;
          return;
        }
        if (lfn_nested) { r.w.ax = 0x0005; r.w.flags |= INTR_CF; return; }
        glob_lfn_drv = idx;
        glob_lfn_pdop = 0x4100u;
        glob_lfn_op = LFNOP_PDPREP;
        do_lfn = 1;
      }
    } else if ((r.h.al == 0x3A) || (r.h.al == 0x3B)) { /* 713Ah rd / 713Bh cd */
      unsigned char far *pp = MK_FP(r.w.ds, r.w.dx);
      unsigned char idx = 0xff;
      idx = lfn_claimdrv(pp);
      if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) {
        if (lfn_nested) { r.w.ax = 0x0005; r.w.flags |= INTR_CF; return; }
        glob_lfn_drv = idx;
        glob_lfn_pdop = (r.h.al == 0x3A) ? 0x3A00u : 0x3B00u;
        glob_lfn_op = LFNOP_PDPREP;
        do_lfn = 1;
        /* on success DOS itself updates the CDS with the (alias) path we
         * passed down -- FreeDOS dosfns.c DosChangeDir does the copy-back */
      }
    } else if (r.h.al == 0x39) { /* 7139h mkdir: MUST keep the long name */
      unsigned char far *pp = MK_FP(r.w.ds, r.w.dx);
      unsigned char idx = 0xff;
      idx = lfn_claimdrv(pp);
      if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) {
        unsigned short k2;
        if (lfn_nested) { r.w.ax = 0x0005; r.w.flags |= INTR_CF; return; }
        for (k2 = 0; (pp[k2] != 0) && (k2 < 260); k2++) {
          if ((pp[k2] == '*') || (pp[k2] == '?')) { /* wildcards: a literal
              '*'/'?' name would be creatable server-side yet unreachable from
              DOS afterwards */
            r.w.ax = 0x0003; r.w.flags |= INTR_CF; return;
          }
        }
        glob_lfn_drv = idx;
        glob_lfn_op = LFNOP_MKDIR;
        do_lfn = 1;
      }
    } else if (r.h.al == 0x43) { /* 7143h get/set attributes by path */
      if (r.h.bl <= 1) { /* BL=0 get (out CX) / BL=1 set (in CX) */
        unsigned char far *pp = MK_FP(r.w.ds, r.w.dx);
        unsigned char idx = 0xff;
        idx = lfn_claimdrv(pp);
        if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) {
          if (lfn_nested) { r.w.ax = 0x0005; r.w.flags |= INTR_CF; return; }
          glob_lfn_drv = idx;
          glob_lfn_pdop = (unsigned short)(0x4300u | r.h.bl);
          glob_lfn_op = LFNOP_PDPREP;
          do_lfn = 1;
        }
      }
      /* BL>=2 (file times by path) -> chain; 4DOS TOUCH uses handle-based
       * 5705h/5707h instead, which ride the open-handle path */
    } else if (r.h.al == 0x56) { /* 7156h rename (long target preserved) */
      unsigned char far *po = MK_FP(r.w.ds, r.w.dx);
      unsigned char far *pn = MK_FP(r.w.es, r.w.di);
      unsigned char idx = 0xff, idx2 = 0xff;
      idx = lfn_claimdrv(po);
      if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) {
        idx2 = lfn_claimdrv(pn);
        if (idx2 != idx) { /* RBIL: not across disks */
          r.w.ax = 0x11;
          r.w.flags |= INTR_CF;
          return;
        }
        if (lfn_nested) { r.w.ax = 0x0005; r.w.flags |= INTR_CF; return; }
        {
          unsigned short k2;
          for (k2 = 0; (po[k2] != 0) && (k2 < 260); k2++)
            if ((po[k2] == '*') || (po[k2] == '?')) {
              r.w.ax = 0x0003; r.w.flags |= INTR_CF; return;
            }
          for (k2 = 0; (pn[k2] != 0) && (k2 < 260); k2++)
            if ((pn[k2] == '*') || (pn[k2] == '?')) {
              r.w.ax = 0x0003; r.w.flags |= INTR_CF; return;
            }
        }
        glob_lfn_drv = idx;
        glob_lfn_op = LFNOP_RENAME;
        do_lfn = 1;
      }
    } else if (r.h.al == 0x47) { /* 7147h get current directory (long) */
      unsigned char idx = (r.h.dl == 0)
                            ? ((unsigned char far *)glob_sdaptr)[0x16]
                            : (unsigned char)(r.h.dl - 1);
      if ((idx <= 25) && (glob_data.ldrv[idx] != 0xff)) {
        /* nested guard BEFORE the phase-1 pass-down AND the buffer write:
         * if we are nested inside a blocked send, DOS is mid-operation and
         * must not be re-entered (and glob_lfn_openpath belongs to the outer) */
        if (lfn_nested) { r.w.ax = 0x0005; r.w.flags |= INTR_CF; return; }
        /* phase 1 NOW, on the caller stack: classic 47h pass-down reads the
         * (alias) cwd text DOS keeps in the CDS into our resident buffer */
        lfn_passdown(0x4700u, 0, 0, (unsigned short)r.h.dl,
                     (unsigned short)(unsigned char near *)glob_lfn_openpath);
        if (glob_lfn_pdfl & 0x0001) {
          r.w.ax = glob_lfn_pdax;
          r.w.flags |= INTR_CF;
          return;
        }
        glob_lfn_drv = idx;
        glob_lfn_op = LFNOP_GETCWD2; /* phase 2: alias -> long, to DS:SI */
        do_lfn = 1;
      }
    } else if (r.h.al == 0xA7) { /* 71A7h FILETIME <-> DOS date/time */
      /* NOT drive-specific: a pure calendar conversion (see ftconv.h). LFN
       * shells (4DOS) convert our FindData FILETIMEs for display with BL=0;
       * without this, the call chains to a non-LFN DOS kernel, fails, and the
       * DIR date/time columns stay blank. Pure local math -- no server
       * round-trip, no stack switch (scalars live on the caller stack; the
       * multi-word state is in resident DS statics). */
      if (r.h.bl == 0) { /* FileTimeToDosDateTime: DS:SI -> 8-byte FILETIME */
        unsigned char far *src = MK_FP(r.w.ds, r.w.si);
        unsigned short k;
        int rc;
        if (ftc_busy) { /* nested conversion would break the DIV precondition */
          r.w.ax = 0x000d; r.w.flags |= INTR_CF; return;
        }
        ftc_busy = 1;
        for (k = 0; k < 4; k++)
          ftc_w[k] = (unsigned short)src[k + k] | ((unsigned short)src[k + k + 1] << 8);
        rc = ftc_ft2dos();
        if (rc == 0) {
          r.w.dx = ftc_dosdate;
          r.w.cx = ftc_dostime;
          r.h.bh = ftc_bh;       /* hundredths (incl. odd second: +100) */
          r.w.flags &= ~INTR_CF;
        } else {
          r.w.ax = 0x000d;       /* ERROR_INVALID_DATA (zero/out of range) */
          r.w.flags |= INTR_CF;
        }
        ftc_busy = 0;
        return;
      }
      if (r.h.bl == 1) { /* DosDateTimeToFileTime: DX=date CX=time -> ES:DI.
                          * NOTE: the RBIL-specified BH hundredths input is
                          * ignored (DOS times are 2-second granular anyway). */
        int rc;
        if (ftc_busy) {
          r.w.ax = 0x000d; r.w.flags |= INTR_CF; return;
        }
        ftc_busy = 1;
        ftc_dosdate = r.w.dx;
        ftc_dostime = r.w.cx;
        rc = ftc_dos2ft();
        if (rc == 0) {
          unsigned char far *dst = MK_FP(r.w.es, r.w.di);
          unsigned short k;
          for (k = 0; k < 4; k++) {
            dst[k + k] = (unsigned char)(ftc_w[k] & 0xff);
            dst[k + k + 1] = (unsigned char)(ftc_w[k] >> 8);
          }
          r.w.flags &= ~INTR_CF;
        } else {
          r.w.ax = 0x000d;
          r.w.flags |= INTR_CF;
        }
        ftc_busy = 0;
        return;
      }
      /* other BL subfunctions -> chain */
    }
    if (do_lfn) { /* guarded blocking server round-trip on the resident stack */
      /* Stateless nesting guard: if SS is already DS we are nested inside an
       * outer switched context (a 2Fh or 21h send blocked in sendquery); a
       * second switch would clobber it, so bail without touching the stack. */
      { volatile unsigned char _nested = 0;
        _asm {
          push ax
          push bx
          mov ax, ss
          mov bx, ds
          cmp ax, bx
          jne n21ok
          mov byte ptr _nested, 1
        n21ok:
          pop bx
          pop ax
        }
        if (_nested != 0) { r.w.ax = 0x0005; r.w.flags |= INTR_CF; return; }
      }
      copybytes(&glob_intregs, &r, sizeof(union INTPACK));
      _asm {
        cli
        mov glob_o21ss, SS
        mov glob_o21sp, SP
        mov ax, ds
        mov ss, ax
        mov sp, DATASEGSZ-2
        sti
      }
      if (glob_lfn_op == AL_LFN_OPEN)
        lfn_do_open();
      else if ((glob_lfn_op == AL_LFN_FINDFIRST) ||
               (glob_lfn_op == AL_LFN_FINDNEXT))
        lfn_do_find();
      else
        lfn_do_misc();
      _asm {
        cli
        mov SS, glob_o21ss
        mov SP, glob_o21sp
        sti
      }
      if (glob_lfn_op == LFNOP_PDPREP) {
        /* phase 2 of del/rd/cd/attr: classic pass-down of the alias path, on
         * the CALLER's stack (the nested 2Fh op must not see SS==DS) */
        unsigned short pcxin;
        if (glob_lfn_openerr != 0) {
          r.w.ax = glob_lfn_openerr;
          r.w.flags |= INTR_CF;
          return;
        }
        pcxin = (glob_lfn_pdop == 0x4301u) ? r.w.cx : 0;
        lfn_passdown(glob_lfn_pdop, 0, pcxin,
                     (unsigned short)(unsigned char near *)glob_lfn_openpath,
                     0);
        r.w.ax = glob_lfn_pdax;
        if (glob_lfn_pdfl & 0x0001) {
          r.w.flags |= INTR_CF;
        } else {
          if (glob_lfn_pdop == 0x4300u)
            r.w.cx = glob_lfn_pdcx; /* attributes from the classic get */
          r.w.flags &= ~INTR_CF;
        }
        return;
      }
      if (glob_lfn_op != AL_LFN_OPEN) {
        copybytes(&r, &glob_intregs, sizeof(union INTPACK));
        return;
      }
      /* 716Ch part 2: the pass-down, on the CALLER's stack (a nested 2Fh open
       * of our drive must not see SS==DS). Results are captured into
       * DS-relative globals only AFTER all registers (incl. BP) are restored,
       * because DOS may clobber BP during the call and stack locals are
       * BP-relative. */
      if (glob_lfn_openerr != 0) {
        r.w.ax = glob_lfn_openerr;
        r.w.flags |= INTR_CF;
        return;
      }
      {
        unsigned short pbx = (unsigned short)(r.w.bx & ~0x1F00u); /* strip
                              716Ch-only bits 8-10 + reserved 11-12; bits 0-7
                              (access/share/inherit) and 13-14 map 1:1 */
        unsigned short pcx = r.w.cx;
        _asm {
          push bp
          push ds
          push es
          push si
          push di
          push bx
          mov ax, 6C00h
          mov bx, pbx
          mov cx, pcx
          mov dx, 0001h      /* always open-existing: the server already
                                created/truncated per the 716Ch action word */
          mov si, offset glob_lfn_openpath /* DS:SI, DS = resident segment */
          sti
          pushf
          cli
          call dword ptr glob_prev21call
          pop bx
          pop di
          pop si
          pop es
          pop ds
          pop bp
          mov glob_lfn_pdax, ax
          pushf
          pop ax
          mov glob_lfn_pdfl, ax
        }
        if (glob_lfn_pdfl & 0x0001) { /* CF set: open failed */
          if (glob_lfn_pdax == 0x0001) {
            /* AX=1 invalid function: this DOS lacks 6C00h -- retry with the
             * classic 3Dh open (mode = caller's low BX bits) */
            unsigned short pmode = (unsigned short)(0x3D00u | (pbx & 0xffu));
            _asm {
              push bp
              push ds
              push es
              push si
              push di
              push bx
              mov ax, pmode
              mov si, offset glob_lfn_openpath
              mov dx, si   /* 3Dh takes the path at DS:DX */
              sti
              pushf
              cli
              call dword ptr glob_prev21call
              pop bx
              pop di
              pop si
              pop es
              pop ds
              pop bp
              mov glob_lfn_pdax, ax
              pushf
              pop ax
              mov glob_lfn_pdfl, ax
            }
          }
        }
        if (glob_lfn_pdfl & 0x0001) {
          r.w.ax = glob_lfn_pdax;   /* pass the DOS error through */
          r.w.flags |= INTR_CF;
        } else {
          r.w.ax = glob_lfn_pdax;   /* the real DOS handle */
          r.w.cx = glob_lfn_opensyn; /* synthesized action-taken (1/2/3) */
          r.w.flags &= ~INTR_CF;
        }
        return;
      }
    }
    /* other 71xx, or not our drive/handle -> chain */
  }
  /* chain everything else to the previous handler */
  _mvchain_intr(MK_FP(glob_data.prev_21_handler_seg, glob_data.prev_21_handler_off));
}


/*********************** HERE ENDS THE RESIDENT PART ***********************/

#pragma code_seg("_TEXT", "CODE");

/* this function obviously does nothing - but I need it because it is a
 * 'low-water' mark for the end of my resident code (so I know how much memory
 * exactly I can trim when going TSR) */
void begtextend(void) {
}

/* registers a packet driver handle to use on subsequent calls */
static int pktdrv_accesstype(void) {
  unsigned char cflag = 0;

  _asm {
    mov ax, 201h        /* AH=subfunction access_type(), AL=if_class=1(eth) */
    mov bx, 0ffffh      /* if_type = 0xffff means 'all' */
    mov dl, 0           /* if_number: 0 (first interface) */
    /* DS:SI should point to the ethertype value in network byte order */
    mov si, offset glob_pktdrv_sndbuff + 12 /* I don't set DS, it's good already */
    mov cx, 2           /* typelen (ethertype is 16 bits) */
    /* ES:DI points to the receiving routine */
    push cs /* write segment of pktdrv_recv into es */
    pop es
    mov di, offset pktdrv_recv
    mov cflag, 1        /* pre-set the cflag variable to failure */
    /* int to variable vector is a mess, so I have fetched its vector myself
     * and pushf + cli + call far it now to simulate a regular int */
    pushf
    cli
    call dword ptr glob_pktdrv_pktcall
    /* get CF state - reset cflag if CF clear, and get pkthandle from AX */
    jc badluck   /* Jump if Carry */
    mov word ptr [glob_data + GLOB_DATOFF_PKTHANDLE], ax /* Pkt handle should be in AX */
    mov cflag, 0
    badluck:
  }

  if (cflag != 0) return(-1);
  return(0);
}

/* get my own MAC addr. target MUST point to a space of at least 6 chars */
static void pktdrv_getaddr(unsigned char *dst) {
  _asm {
    mov ah, 6                       /* subfunction: get_addr() */
    mov bx, word ptr [glob_data + GLOB_DATOFF_PKTHANDLE];  /* handle */
    push ds                         /* write segment of dst into es */
    pop es
    mov di, dst                     /* offset of dst (in small mem model dst IS an offset) */
    mov cx, 6                       /* expected length (ethernet = 6 bytes) */
    /* int to variable vector is a mess, so I have fetched its vector myself
     * and pushf + cli + call far it now to simulate a regular int */
    pushf
    cli
    call dword ptr glob_pktdrv_pktcall
  }
}


static int pktdrv_init(unsigned short pktintparam, int nocksum) {
  unsigned short far *intvect = (unsigned short far *)MK_FP(0, pktintparam << 2);
  unsigned short pktdrvfuncoffs = *intvect;
  unsigned short pktdrvfuncseg = *(intvect+1);
  unsigned short rseg = 0, roff = 0;
  char far *pktdrvfunc = (char far *)MK_FP(pktdrvfuncseg, pktdrvfuncoffs);
  int i;
  char sig[8];
  /* preload sig with "PKT DRVR" -- I could it just as well with
   * char sig[] = "PKT DRVR", but I want to avoid this landing in
   * my DATA segment so it doesn't pollute the TSR memory space. */
  sig[0] = 'P';
  sig[1] = 'K';
  sig[2] = 'T';
  sig[3] = ' ';
  sig[4] = 'D';
  sig[5] = 'R';
  sig[6] = 'V';
  sig[7] = 'R';

  /* set my ethertype to 0xF5ED (EDF5 in network byte order) */
  glob_pktdrv_sndbuff[12] = 0xED;
  glob_pktdrv_sndbuff[13] = 0xF5;
  /* set protover and CKSUM flag in send buffer (I won't touch it again) */
  if (nocksum == 0) {
    glob_pktdrv_sndbuff[56] = PROTOVER | 128; /* protocol version */
  } else {
    glob_pktdrv_sndbuff[56] = PROTOVER;       /* protocol version */
  }

  pktdrvfunc += 3; /* skip three bytes of executable code */
  for (i = 0; i < 8; i++) if (sig[i] != pktdrvfunc[i]) return(-1);

  glob_data.pktint = pktintparam;

  /* fetch the vector of the pktdrv interrupt and save it for later */
  _asm {
    mov ah, 35h /* AH=GetVect */
    mov al, byte ptr [glob_data] + GLOB_DATOFF_PKTINT; /* AL=int number */
    push es /* save ES and BX (will be overwritten) */
    push bx
    int 21h
    mov rseg, es
    mov roff, bx
    pop bx
    pop es
  }
  glob_pktdrv_pktcall = rseg;
  glob_pktdrv_pktcall <<= 16;
  glob_pktdrv_pktcall |= roff;

  return(pktdrv_accesstype());
}


static void pktdrv_free(unsigned long pktcall) {
  _asm {
    mov ah, 3
    mov bx, word ptr [glob_data + GLOB_DATOFF_PKTHANDLE]
    /* int to variable vector is a mess, so I have fetched its vector myself
     * and pushf + cli + call far it now to simulate a regular int */
    pushf
    cli
    call dword ptr glob_pktdrv_pktcall
  }
  /* if (regs.x.cflag != 0) return(-1);
  return(0);*/
}

static struct sdastruct far *getsda(void) {
  /* DOS 3.0+ - GET ADDRESS OF SDA (Swappable Data Area)
   * AX = 5D06h
   *
   * CF set on error (AX=error code)
   * DS:SI -> sda pointer
   */
  unsigned short rds = 0, rsi = 0;
  _asm {
    mov ax, 5d06h
    push ds
    push si
    int 21h
    mov bx, ds
    mov cx, si
    pop si
    pop ds
    mov rds, bx
    mov rsi, cx
  }
  return(MK_FP(rds, rsi));
}

/* returns the CDS struct for drive. requires DOS 4+ */
static struct cdsstruct far *getcds(unsigned int drive) {
  /* static to preserve state: only do init once */
  static unsigned char far *dir;
  static int ok = -1;
  static unsigned char lastdrv;
  /* init of never inited yet */
  if (ok == -1) {
    /* DOS 3.x+ required - no CDS in earlier versions */
    ok = 1;
    /* offsets of CDS and lastdrv in the List of Lists depends on the DOS version:
     * DOS < 3   no CDS at all
     * DOS 3.0   lastdrv at 1Bh, CDS pointer at 17h
     * DOS 3.1+  lastdrv at 21h, CDS pointer at 16h */
    /* fetch lastdrv and CDS through a little bit of inline assembly */
    _asm {
      push si /* SI needs to be preserved */
      /* get the List of Lists into ES:BX */
      mov ah, 52h
      int 21h
      /* get the LASTDRIVE value */
      mov si, 21h /* 21h for DOS 3.1+, 1Bh on DOS 3.0 */
      mov ah, byte ptr es:[bx+si]
      mov lastdrv, ah
      /* get the CDS */
      mov si, 16h /* 16h for DOS 3.1+, 17h on DOS 3.0 */
      les bx, es:[bx+si]
      mov word ptr dir+2, es
      mov word ptr dir, bx
      /* restore the original SI value*/
      pop si
    }
    /* some OSes (at least OS/2) set the CDS pointer to FFFF:FFFF */
    if (dir == (unsigned char far *) -1l) ok = 0;
  } /* end of static initialization */
  if (ok == 0) return(NULL);
  if (drive > lastdrv) return(NULL);
  /* return the CDS array entry for drive - note that currdir_size depends on
   * DOS version: 0x51 on DOS 3.x, and 0x58 on DOS 4+ */
  return((struct cdsstruct __far *)((unsigned char __far *)dir + (drive * 0x58 /*currdir_size*/)));
}
/******* end of CDS-related stuff *******/

/* primitive message output used instead of printf() to limit memory usage
 * and binary size */
static void outmsg(char *s) {
  _asm {
    mov ah, 9h  /* DOS 1+ - WRITE STRING TO STANDARD OUTPUT */
    mov dx, s   /* small memory model: no need to set DS, 's' is an offset */
    int 21h
  }
}

/* zero out an object of l bytes */
static void zerobytes(void *obj, unsigned short l) {
  unsigned char *o = obj;
  while (l-- != 0) {
    *o = 0;
    o++;
  }
}

/* expects a hex string of exactly two chars "XX" and returns its value, or -1
 * if invalid */
static int hexpair2int(char *hx) {
  unsigned char h[2];
  unsigned short i;
  /* translate hx[] to numeric values and validate */
  for (i = 0; i < 2; i++) {
    if ((hx[i] >= 'A') && (hx[i] <= 'F')) {
      h[i] = hx[i] - ('A' - 10);
    } else if ((hx[i] >= 'a') && (hx[i] <= 'f')) {
      h[i] = hx[i] - ('a' - 10);
    } else if ((hx[i] >= '0') && (hx[i] <= '9')) {
      h[i] = hx[i] - '0';
    } else { /* invalid */
      return(-1);
    }
  }
  /* compute the end result and return it */
  i = h[0];
  i <<= 4;
  i |= h[1];
  return(i);
}

/* translates an ASCII MAC address into a 6-bytes binary string */
static int string2mac(unsigned char *d, char *mac) {
  int i, v;
  /* is it exactly 17 chars long? */
  for (i = 0; mac[i] != 0; i++);
  if (i != 17) return(-1);
  /* are nibble pairs separated by colons? */
  for (i = 2; i < 16; i += 3) if (mac[i] != ':') return(-1);
  /* translate each byte to its numeric value */
  for (i = 0; i < 16; i += 3) {
    v = hexpair2int(mac + i);
    if (v < 0) return(-1);
    *d = v;
    d++;
  }
  return(0);
}


#define ARGFL_QUIET 1
#define ARGFL_AUTO 2
#define ARGFL_UNLOAD 4
#define ARGFL_NOCKSUM 8

/* a structure used to pass and decode arguments between main() and parseargv() */
struct argstruct {
  int argc;    /* original argc */
  char **argv; /* original argv */
  unsigned short pktint; /* custom packet driver interrupt */
  unsigned char flags; /* ARGFL_QUIET, ARGFL_AUTO, ARGFL_UNLOAD, ARGFL_CKSUM */
};


/* parses (and applies) command-line arguments. returns 0 on success,
 * non-zero otherwise */
static int parseargv(struct argstruct *args) {
  int i, drivemapflag = 0, gotmac = 0;

  /* iterate through arguments, if any */
  for (i = 1; i < args->argc; i++) {
    char opt;
    char *arg;
    /* is it a drive mapping, like "c-x"? */
    if ((args->argv[i][0] >= 'A') && (args->argv[i][1] == '-') && (args->argv[i][2] >= 'A') && (args->argv[i][3] == 0)) {
      unsigned char ldrv, rdrv;
      rdrv = DRIVETONUM(args->argv[i][0]);
      ldrv = DRIVETONUM(args->argv[i][2]);
      if ((ldrv > 25) || (rdrv > 25)) return(-2);
      if (glob_data.ldrv[ldrv] != 0xff) return(-2);
      glob_data.ldrv[ldrv] = rdrv;
      drivemapflag = 1;
      continue;
    }
    /* not a drive mapping -> is it an option? */
    if (args->argv[i][0] == '/') {
      if (args->argv[i][1] == 0) return(-3);
      opt = args->argv[i][1];
      /* fetch option's argument, if any */
      if (args->argv[i][2] == 0) { /* single option */
        arg = NULL;
      } else if (args->argv[i][2] == '=') { /* trailing argument */
        arg = args->argv[i] + 3;
      } else {
        return(-3);
      }
      /* normalize the option char to lower case */
      if ((opt >= 'A') && (opt <= 'Z')) opt += ('a' - 'A');
      /* what is the option about? */
      switch (opt) {
        case 'q':
          if (arg != NULL) return(-4);
          args->flags |= ARGFL_QUIET;
          break;
        case 'p':
          if (arg == NULL) return(-4);
          /* I expect an exactly 2-characters string */
          if ((arg[0] == 0) || (arg[1] == 0) || (arg[2] != 0)) return(-1);
          if ((args->pktint = hexpair2int(arg)) < 1) return(-4);
          break;
        case 'n':  /* disable CKSUM */
          if (arg != NULL) return(-4);
          args->flags |= ARGFL_NOCKSUM;
          break;
        case 'u':  /* unload EtherDFS */
          if (arg != NULL) return(-4);
          args->flags |= ARGFL_UNLOAD;
          break;
        default: /* invalid parameter */
          return(-5);
      }
      continue;
    }
    /* not a drive mapping nor an option -> so it's a MAC addr perhaps? */
    if (gotmac != 0) return(-1);  /* fail if got a MAC already */
    /* read the srv mac address, unless it's "::" (auto) */
    if ((args->argv[i][0] == ':') && (args->argv[i][1] == ':') && (args->argv[i][2] == 0)) {
      args->flags |= ARGFL_AUTO;
    } else {
      if (string2mac(GLOB_RMAC, args->argv[i]) != 0) return(-1);
    }
    gotmac = 1;
  }

  /* fail if MAC+unload or mapping+unload */
  if (args->flags & ARGFL_UNLOAD) {
    if ((gotmac != 0) || (drivemapflag != 0)) return(-1);
    return(0);
  }

  /* did I get at least one drive mapping? and a MAC? */
  if ((drivemapflag == 0) || (gotmac == 0)) return(-6);

  return(0);
}

/* translates an unsigned byte into a 2-characters string containing its hex
 * representation. s needs to be at least 3 bytes long. */
static void byte2hex(char *s, unsigned char b) {
  char h[16];
  unsigned short i;
  /* pre-compute h[] with a string 0..F -- I could do the same thing easily
   * with h[] = "0123456789ABCDEF", but then this would land inside the DATA
   * segment, while I want to keep it in stack to avoid polluting the TSR's
   * memory space */
  for (i = 0; i < 10; i++) h[i] = '0' + i;
  for (; i < 16; i++) h[i] = ('A' - 10) + i;
  /* */
  s[0] = h[b >> 4];
  s[1] = h[b & 15];
  s[2] = 0;
}

/* allocates sz bytes of memory and returns the segment to allocated memory or
 * 0 on error. the allocation strategy is 'highest possible' (last fit) to
 * avoid memory fragmentation */
static unsigned short allocseg(unsigned short sz) {
  unsigned short volatile res = 0;
  /* sz should contains number of 16-byte paragraphs instead of bytes */
  sz += 15; /* make sure to allocate enough paragraphs */
  sz >>= 4;
  /* ask DOS for memory */
  _asm {
    push cx /* save cx */
    /* set strategy to 'last fit' */
    mov ah, 58h
    xor al, al  /* al = 0 means 'get strategy' */
    int 21h     /* now current strategy is in ax */
    mov cx, ax  /* copy current strategy to cx */
    mov ah, 58h
    mov al, 1   /* al = 1 means 'set strategy' */
    mov bl, 2   /* 2 or greater means 'last fit' */
    int 21h
    /* do the allocation now */
    mov ah, 48h     /* alloc memory (DOS 2+) */
    mov bx, sz      /* number of paragraphs to allocate */
    mov res, 0      /* pre-set res to failure (0) */
    int 21h         /* returns allocated segment in AX */
    /* check CF */
    jc failed
    mov res, ax     /* set res to actual result */
    failed:
    /* set strategy back to its initial setting */
    mov ah, 58h
    mov al, 1
    mov bx, cx
    int 21h
    pop cx    /* restore cx */
  }
  return(res);
}

/* free segment previously allocated through allocseg() */
static void freeseg(unsigned short segm) {
  _asm {
    mov ah, 49h   /* free memory (DOS 2+) */
    mov es, segm  /* put segment to free into ES */
    int 21h
  }
}

/* patch the TSR routine and packet driver handler so they use my new DS.
 * return 0 on success, non-zero otherwise */
static int updatetsrds(void) {
  unsigned short newds;
  unsigned char far *ptr;
  unsigned short far *sptr;
  newds = 0;
  _asm {
    push ds
    pop newds
  }

  /* first patch the TSR routine. Like inthandler21 below, SCAN for the "MVet"
   * signature instead of relying on a hardcoded offset: the signature's offset
   * shifts whenever the function's locals/prologue change (a hardcoded +24
   * broke -- "DS/SS relocation failed" -- when a local was added). The
   * 'mov ax,IMM16' DS immediate sits 6 bytes past the signature start. */
  {
    unsigned short i;
    ptr = (unsigned char far *)inthandler;
    for (i = 0; i < 96; i++) {
      if ((ptr[i] == 'M') && (ptr[i + 1] == 'V') && (ptr[i + 2] == 'e') && (ptr[i + 3] == 't')) break;
    }
    if (i >= 96) return(-1); /* signature not found */
    sptr = (unsigned short far *)(ptr + i);
    sptr[3] = newds;
  }
  /* now patch the pktdrv_recv() routine */
  ptr = (unsigned char far *)pktdrv_recv + 3;
  sptr = (unsigned short far *)ptr;
  /*{
    int x;
    unsigned short far *VGA = (unsigned short far *)(0xB8000000l);
    for (x = 0; x < 128; x++) VGA[80*12 + ((x >> 6) * 80) + (x & 63)] = 0x1f00 | ptr[x];
  }*/
  /* check for the routine's signature first */
  if ((ptr[0] != 'p') || (ptr[1] != 'k') || (ptr[2] != 't') || (ptr[3] != 'r')) return(-1);
  sptr[4] = newds;
  /*{
    int x;
    unsigned short far *VGA = (unsigned short far *)(0xB8000000l);
    for (x = 0; x < 128; x++) VGA[80*20 + ((x >> 6) * 80) + (x & 63)] = 0x1f00 | ptr[x];
  }*/
  /* finally patch the INT 21h LFN handler (inthandler21). Instead of a
   * hardcoded offset (which shifts with optimization), SCAN the first bytes of
   * the routine for its "MV21" signature; the 'mov ax,IMM16' DS immediate sits
   * 6 bytes past the signature start (same layout as inthandler). */
  {
    unsigned short i;
    ptr = (unsigned char far *)inthandler21;
    for (i = 0; i < 96; i++) {
      if ((ptr[i] == 'M') && (ptr[i + 1] == 'V') && (ptr[i + 2] == '2') && (ptr[i + 3] == '1')) break;
    }
    if (i >= 96) return(-1); /* signature not found */
    sptr = (unsigned short far *)(ptr + i);
    sptr[3] = newds;
  }
  return(0);
}

/* scans the 2Fh interrupt for some available 'multiplex id' in the range
 * C0..FF. also checks for EtherDFS presence at the same time. returns:
 *  - the available id if found
 *  - the id of the already-present etherdfs instance
 *  - 0 if no available id found
 * presentflag set to 0 if no etherdfs found loaded, non-zero otherwise. */
static unsigned char findfreemultiplex(unsigned char *presentflag) {
  unsigned char id = 0, freeid = 0, pflag = 0;
  _asm {
    mov id, 0C0h /* start scanning at C0h */
    checkid:
    xor al, al   /* subfunction is 'installation check' (00h) */
    mov ah, id
    int 2Fh
    /* is it free? (AL == 0) */
    test al, al
    jnz notfree    /* not free - is it me perhaps? */
    mov freeid, ah /* it's free - remember it, I may use it myself soon */
    jmp checknextid
    notfree:
    /* is it me? (AL=FF + BX=4D86 CX=7E1 [MV 2017]) */
    cmp al, 0ffh
    jne checknextid
    cmp bx, 4d86h
    jne checknextid
    cmp cx, 7e1h
    jne checknextid
    /* if here, then it's me... */
    mov ah, id
    mov freeid, ah
    mov pflag, 1
    jmp gameover
    checknextid:
    /* if not me, then check next id */
    inc id
    jnz checkid /* if id is zero, then all range has been covered (C0..FF) */
    gameover:
  }
  *presentflag = pflag;
  return(freeid);
}

int main(int argc, char **argv) {
  struct argstruct args;
  struct cdsstruct far *cds;
  unsigned char tmpflag = 0;
  int i;
  unsigned short volatile newdataseg; /* 'volatile' just in case the compiler would try to optimize it out, since I set it through in-line assembly */

  /* set all drive mappings as 'unused' */
  for (i = 0; i < 26; i++) glob_data.ldrv[i] = 0xff;

  /* parse command-line arguments */
  zerobytes(&args, sizeof(args));
  args.argc = argc;
  args.argv = argv;
  if (parseargv(&args) != 0) {
    #include "msg/help.c"
    return(1);
  }

  /* check DOS version - I require DOS 5.0+ */
  _asm {
    mov ax, 3306h
    int 21h
    mov tmpflag, bl
    inc al /* if AL was 0xFF ("unsupported function"), it is 0 now */
    jnz done
    mov tmpflag, 0 /* if AL is 0 (hence was 0xFF), set dosver to 0 */
    done:
  }
  if (tmpflag < 5) { /* tmpflag contains DOS version or 0 for 'unknown' */
    #include "msg\\unsupdos.c"
    return(1);
  }

  /* look whether or not it's ok to install a network redirector at int 2F */
  _asm {
    mov tmpflag, 0
    mov ax, 1100h
    int 2Fh
    dec ax /* if AX was set to 1 (ie. "not ok to install"), it's zero now */
    jnz goodtogo
    mov tmpflag, 1
    goodtogo:
  }
  if (tmpflag != 0) {
    #include "msg\\noredir.c"
    return(1);
  }

  /* is it all about unloading myself? */
  if ((args.flags & ARGFL_UNLOAD) != 0) {
    unsigned char etherdfsid, pktint;
    unsigned short myseg, myoff, myhandle, mydataseg;
    unsigned long pktdrvcall;
    struct tsrshareddata far *tsrdata;
    unsigned char far *int2fptr;

    /* am I loaded at all? */
    etherdfsid = findfreemultiplex(&tmpflag);
    if (tmpflag == 0) { /* not loaded, cannot unload */
      #include "msg\\notload.c"
      return(1);
    }
    /* am I still at the top of the int 2Fh chain? */
    _asm {
      /* save AX, BX and ES */
      push ax
      push bx
      push es
      /* fetch int vector */
      mov ax, 352Fh  /* AH=35h 'GetVect' for int 2Fh */
      int 21h
      mov myseg, es
      mov myoff, bx
      /* restore AX, BX and ES */
      pop es
      pop bx
      pop ax
    }
    /* SCAN the first 96 bytes for the "MVet" signature instead of trusting a
     * hardcoded offset. The signature's distance from the handler entry shifts
     * as the prologue changes across builds (it moved from +24 to +25 when the
     * INT 21h/LFN code was added), and a fixed offset then silently mis-fires
     * and refuses a LEGITIMATE unload even though EtherDFS is still on top of
     * INT 2Fh. This mirrors the INT 21h "MV21" scan below. */
    int2fptr = (unsigned char far *)MK_FP(myseg, myoff);
    {
      unsigned short k2f;
      for (k2f = 0; k2f < 96; k2f++) {
        if ((int2fptr[k2f] == 'M') && (int2fptr[k2f + 1] == 'V') &&
            (int2fptr[k2f + 2] == 'e') && (int2fptr[k2f + 3] == 't')) break;
      }
      if (k2f >= 96) {
        /* genuinely not on top -- report WHO owns INT 2Fh (match with MEM /D) */
        char hx[12];
        outmsg("EtherDFS cannot be unloaded: INT 2Fh now owned by $");
        byte2hex(hx + 0, (unsigned char)(myseg >> 8));
        byte2hex(hx + 2, (unsigned char)(myseg & 0xff));
        hx[4] = ':';
        byte2hex(hx + 5, (unsigned char)(myoff >> 8));
        byte2hex(hx + 7, (unsigned char)(myoff & 0xff));
        hx[9] = '$';
        outmsg(hx);
        outmsg(" (a later TSR). Unload it first, or reboot.\r\n$");
        return(1);
      }
    }
    /* also confirm we are still the top of the INT 21h chain (signature
     * "MV21"). If another TSR hooked INT 21h after us, unloading would leave a
     * dangling hook in freed memory -> refuse the whole unload. */
    {
      unsigned short s21 = 0, o21 = 0, k; /* s21/o21 init: assigned via asm */
      unsigned char far *int21fptr;
      _asm {
        push ax
        push bx
        push es
        mov ax, 3521h /* AH=GetVect AL=21 */
        int 21h
        mov s21, es
        mov o21, bx
        pop es
        pop bx
        pop ax
      }
      int21fptr = (unsigned char far *)MK_FP(s21, o21);
      for (k = 0; k < 96; k++) {
        if ((int21fptr[k] == 'M') && (int21fptr[k + 1] == 'V') && (int21fptr[k + 2] == '2') && (int21fptr[k + 3] == '1')) break;
      }
      if (k >= 96) {
        {
          /* report WHICH handler now owns INT 21h (s21:o21) so it can be
           * matched against MEM /D -- it is a TSR loaded/hooked after us. */
          char hx[12];
          outmsg("EtherDFS cannot be unloaded: INT 21h now owned by $");
          byte2hex(hx + 0, (unsigned char)(s21 >> 8));
          byte2hex(hx + 2, (unsigned char)(s21 & 0xff));
          hx[4] = ':';
          byte2hex(hx + 5, (unsigned char)(o21 >> 8));
          byte2hex(hx + 7, (unsigned char)(o21 & 0xff));
          hx[9] = '$';
          outmsg(hx);
          outmsg(" (a later TSR). Unload it first, or reboot.\r\n$");
        }
        return(1);
      }
    }
    /* get the ptr to TSR's data */
    _asm {
      push ax
      push bx
      push cx
      pushf
      mov ah, etherdfsid
      mov al, 1
      mov cx, 4d86h
      mov myseg, 0ffffh
      int 2Fh /* AX should be 0, and BX:CX contains the address */
      test ax, ax
      jnz fail
      mov myseg, bx
      mov myoff, cx
      mov mydataseg, dx
      fail:
      popf
      pop cx
      pop bx
      pop ax
    }
    if (myseg == 0xffffu) {
      #include "msg\\tsrcomfa.c"
      return(1);
    }
    tsrdata = MK_FP(myseg, myoff);
    mydataseg = myseg;
    /* restore previous int 2f handler (under DS:DX, AH=25h, INT 21h)*/
    myseg = tsrdata->prev_2f_handler_seg;
    myoff = tsrdata->prev_2f_handler_off;
    _asm {
      /* save AX, DS and DX */
      push ax
      push ds
      push dx
      /* set DS:DX */
      mov ax, myseg
      push ax
      pop ds
      mov dx, myoff
      /* call INT 21h,25h for int 2Fh */
      mov ax, 252Fh
      int 21h
      /* restore AX, DS and DX */
      pop dx
      pop ds
      pop ax
    }
    /* restore the previous INT 21h handler too (we confirmed above that we are
     * still the top of the 21h chain, so this cannot unlink a foreign hook) */
    myseg = tsrdata->prev_21_handler_seg;
    myoff = tsrdata->prev_21_handler_off;
    _asm {
      push ax
      push ds
      push dx
      mov ax, myseg
      push ax
      pop ds
      mov dx, myoff
      mov ax, 2521h /* AH=SetVect AL=21 */
      int 21h
      pop dx
      pop ds
      pop ax
    }
    /* get the address of the packet driver routine */
    pktint = tsrdata->pktint;
    _asm {
      /* save AX, BX and ES */
      push ax
      push bx
      push es
      /* fetch int vector */
      mov ah, 35h  /* AH=35h 'GetVect' */
      mov al, pktint /* interrupt */
      int 21h
      mov myseg, es
      mov myoff, bx
      /* restore AX, BX and ES */
      pop es
      pop bx
      pop ax
    }
    pktdrvcall = myseg;
    pktdrvcall <<= 16;
    pktdrvcall |= myoff;
    /* unregister packet driver */
    myhandle = tsrdata->pkthandle;
    _asm {
      /* save AX and BX */
      push ax
      push bx
      /* prepare the release_type() call */
      mov ah, 3 /* release_type() */
      mov bx, myhandle
      /* call the pktdrv int */
      /* int to variable vector is a mess, so I have fetched its vector myself
       * and pushf + cli + call far it now to simulate a regular int */
      pushf
      cli
      call dword ptr pktdrvcall
      /* restore AX and BX */
      pop bx
      pop ax
    }
    /* set all mapped drives as 'not available' */
    for (i = 0; i < 26; i++) {
      if (tsrdata->ldrv[i] == 0xff) continue;
      cds = getcds(i);
      if (cds != NULL) cds->flags = 0;
    }
    /* free TSR's data/stack seg and its PSP */
    freeseg(mydataseg);
    freeseg(tsrdata->pspseg);
    /* all done */
    if ((args.flags & ARGFL_QUIET) == 0) {
      #include "msg\\unloaded.c"
    }
    return(0);
  }

  /* remember current int 2f handler, we might over-write it soon (also I
   * use it to see if I'm already loaded) */
  _asm {
    mov ax, 352fh; /* AH=GetVect AL=2F */
    push es /* save ES and BX (will be overwritten) */
    push bx
    int 21h
    mov word ptr [glob_data + GLOB_DATOFF_PREV2FHANDLERSEG], es
    mov word ptr [glob_data + GLOB_DATOFF_PREV2FHANDLEROFF], bx
    pop bx
    pop es
  }

  /* remember the current INT 21h handler too (the LFN hook will chain to it;
   * if DOSLFN is loaded, this is DOSLFN's handler, so it stays behind us for
   * non-our-drive calls). Stored via C since prev_21_* sits past the ASM
   * GLOB_DATOFF_* offsets. */
  {
    unsigned short s21 = 0, o21 = 0; /* init: assigned via asm, which Watcom's
                                      * flow analysis does not see (avoids W200) */
    _asm {
      mov ax, 3521h /* AH=GetVect AL=21 */
      push es
      push bx
      int 21h
      mov s21, es
      mov o21, bx
      pop bx
      pop es
    }
    glob_data.prev_21_handler_seg = s21;
    glob_data.prev_21_handler_off = o21;
    /* m16:16 form (offset low, segment high) for the 716Ch pass-down's
     * 'call dword ptr' -- same convention as glob_pktdrv_pktcall */
    glob_prev21call = ((unsigned long)s21 << 16) | o21;
  }

  /* is the TSR installed already? */
  glob_multiplexid = findfreemultiplex(&tmpflag);
  if (tmpflag != 0) { /* already loaded */
    #include "msg\\alrload.c"
    return(1);
  } else if (glob_multiplexid == 0) { /* no free multiplex id found */
    #include "msg\\nomultpx.c"
    return(1);
  }

  /* if any of the to-be-mapped drives is already active, fail */
  for (i = 0; i < 26; i++) {
    if (glob_data.ldrv[i] == 0xff) continue;
    cds = getcds(i);
    if (cds == NULL) {
      #include "msg\\mapfail.c"
      return(1);
    }
    if (cds->flags != 0) {
      #include "msg\\drvactiv.c"
      return(1);
    }
  }

  /* allocate a new segment for all my internal needs, and use it right away
   * as DS */
  newdataseg = allocseg(DATASEGSZ);
  if (newdataseg == 0) {
    #include "msg\\memfail.c"
    return(1);
  }

  /* copy current DS into the new segment and switch to new DS/SS */
  _asm {
    /* remember the original DS first (written before the copy below, so the
     * value lands in both copies) -- failure paths switch back to it */
    push ds
    pop glob_origds
    /* save registers on the stack */
    push es
    push cx
    push si
    push di
    pushf
    /* copy the memory block */
    mov cx, DATASEGSZ  /* copy cx bytes */
    xor si, si         /* si = 0*/
    xor di, di         /* di = 0 */
    cld                /* clear direction flag (increment si/di) */
    mov es, newdataseg /* load es with newdataseg */
    rep movsb          /* execute copy DS:SI -> ES:DI */
    /* restore registers (but NOT es, instead save it into AX for now) */
    popf
    pop di
    pop si
    pop cx
    pop ax
    /* switch to the new DS _AND_ SS now */
    push es
    push es
    pop ds
    pop ss
    /* restore ES */
    push ax
    pop es
  }

  /* patch the TSR and pktdrv_recv() so they use my new DS */
  if (updatetsrds() != 0) {
    /* switch SS/DS BACK to the original segment before freeing the new one:
     * our stack currently lives in newdataseg (identical copy, same SP), and
     * freeing the segment under our own SS then returning = freed-stack use
     * (hang / EMM386 #12 stack fault). glob_origds was written before the
     * segment copy, so both copies hold it; everything main() later pops on
     * return was pushed before the copy too, so the original stack is valid.
     * push mem/pop sreg avoids clobbering any register across the switch. */
    _asm {
      cli
      push glob_origds
      pop ds
      push glob_origds
      pop ss
      sti
    }
    #include "msg\\relfail.c"
    freeseg(newdataseg);
    return(1);
  }

  /* remember the SDA address (will be useful later) */
  glob_sdaptr = getsda();

  /* Grab the CDS array out of the DOS List of Lists (INT 21h/AH=52h -> ES:BX):
   *   [BX+16h] DWORD -> CDS array,  [BX+21h] BYTE  LASTDRIVE
   * One entry is 51h bytes on DOS 3.x and 58h on DOS 4.0+. We need this because
   * the SDA's drive_cdsptr is the CDS of the current DOS *operation*, which is
   * the wrong drive whenever an app touched another drive just before handing us
   * a relative path (see cds_for_drive). */
  {
    unsigned short lolseg = 0, loloff = 0, dosver = 0;
    _asm {
      mov ah, 52h
      push es
      push bx
      int 21h
      mov cx, es
      mov dx, bx
      pop bx
      pop es
      mov lolseg, cx
      mov loloff, dx
      mov ah, 30h
      int 21h
      mov dosver, ax
    }
    if (lolseg != 0) {
      unsigned char far *lol = MK_FP(lolseg, loloff);
      glob_cdsarr = *(unsigned char far * far *)(lol + 0x16);
      glob_lastdrv = lol[0x21];
      glob_cdssz = ((dosver & 0xff) >= 4) ? 0x58 : 0x51;
    }
  }

  /* init the packet driver interface */
  glob_data.pktint = 0;
  if (args.pktint == 0) { /* detect first packet driver within int 60h..80h */
    for (i = 0x60; i <= 0x80; i++) {
      if (pktdrv_init(i, args.flags & ARGFL_NOCKSUM) == 0) break;
    }
  } else { /* use the pktdrvr interrupt passed through command line */
    pktdrv_init(args.pktint, args.flags & ARGFL_NOCKSUM);
  }
  /* has it succeeded? */
  if (glob_data.pktint == 0) {
    #include "msg\\pktdfail.c"
    freeseg(newdataseg);
    return(1);
  }
  pktdrv_getaddr(GLOB_LMAC);

  /* should I auto-discover the server? */
  if ((args.flags & ARGFL_AUTO) != 0) {
    unsigned short *ax;
    unsigned char *answer;
    /* set (temporarily) glob_rmac to broadcast */
    for (i = 0; i < 6; i++) GLOB_RMAC[i] = 0xff;
    for (i = 0; glob_data.ldrv[i] == 0xff; i++); /* find first mapped disk */
    /* send a discovery frame that will update glob_rmac */
    if (sendquery(AL_DISKSPACE, i, 0, &answer, &ax, 1) != 6) {
      #include "msg\\nosrvfnd.c"
      pktdrv_free(glob_pktdrv_pktcall); /* free the pkt drv and quit */
      freeseg(newdataseg);
      return(1);
    }
  }

  /* set all drives as being 'network' drives (also add the PHYSICAL bit,
   * otherwise MS-DOS 6.0 will ignore the drive) */
  for (i = 0; i < 26; i++) {
    if (glob_data.ldrv[i] == 0xff) continue;
    cds = getcds(i);
    cds->flags = CDSFLAG_NET | CDSFLAG_PHY;
    /* set 'current path' to root, to avoid inheriting any garbage */
    cds->current_path[0] = 'A' + i;
    cds->current_path[1] = ':';
    cds->current_path[2] = '\\';
    cds->current_path[3] = 0;
  }

  if ((args.flags & ARGFL_QUIET) == 0) {
    char buff[20];
    #include "msg\\instlled.c"
    for (i = 0; i < 6; i++) {
      byte2hex(buff + i + i + i, GLOB_LMAC[i]);
    }
    for (i = 2; i < 16; i += 3) buff[i] = ':';
    buff[17] = '$';
    outmsg(buff);
    #include "msg\\pktdrvat.c"
    byte2hex(buff, glob_data.pktint);
    buff[2] = ')';
    buff[3] = '\r';
    buff[4] = '\n';
    buff[5] = '$';
    outmsg(buff);
    for (i = 0; i < 26; i++) {
      int z;
      if (glob_data.ldrv[i] == 0xff) continue;
      buff[0] = ' ';
      buff[1] = 'A' + i;
      buff[2] = ':';
      buff[3] = ' ';
      buff[4] = '-';
      buff[5] = '>';
      buff[6] = ' ';
      buff[7] = '[';
      buff[8] = 'A' + glob_data.ldrv[i];
      buff[9] = ':';
      buff[10] = ']';
      buff[11] = ' ';
      buff[12] = 'o';
      buff[13] = 'n';
      buff[14] = ' ';
      buff[15] = '$';
      outmsg(buff);
      for (z = 0; z < 6; z++) {
        byte2hex(buff + z + z + z, GLOB_RMAC[z]);
      }
      for (z = 2; z < 16; z += 3) buff[z] = ':';
      buff[17] = '\r';
      buff[18] = '\n';
      buff[19] = '$';
      outmsg(buff);
    }
  }

  /* get the segment of the PSP (might come handy later) */
  _asm {
    mov ah, 62h          /* get current PSP address */
    int 21h              /* returns the segment of PSP in BX */
    mov word ptr [glob_data + GLOB_DATOFF_PSPSEG], bx  /* copy PSP segment to glob_pspseg */
  }

  /* free the environment (env segment is at offset 2C of the PSP) */
  _asm {
    mov es, word ptr [glob_data + GLOB_DATOFF_PSPSEG] /* load ES with PSP's segment */
    mov es, es:[2Ch]    /* get segment of the env block */
    mov ah, 49h         /* free memory (DOS 2+) */
    int 21h
  }

  /* set up the TSR (INT 2F catching) */
  _asm {
    cli
    mov ax, 252fh /* AH=set interrupt vector  AL=2F */
    push ds /* preserve DS and DX */
    push dx
    push cs /* set DS to current CS, that is provide the */
    pop ds  /* int handler's segment */
    mov dx, offset inthandler /* int handler's offset */
    int 21h
    pop dx /* restore DS and DX to previous values */
    pop ds
    sti
  }

  /* also hook INT 21h, for native LFN. Done here, last, because: (a)
   * updatetsrds() has already patched inthandler21's DS, and (b) it minimises
   * the window in which our own init code runs through the new hook (only the
   * AH=31h keep below does, and that just chains). */
  _asm {
    cli
    mov ax, 2521h /* AH=set interrupt vector  AL=21 */
    push ds
    push dx
    push cs
    pop ds
    mov dx, offset inthandler21
    int 21h
    pop dx
    pop ds
    sti
  }

  /* Turn self into a TSR and free memory I won't need any more. That is, I
   * free all the libc startup code and my init functions by passing the
   * number of paragraphs to keep resident to INT 21h, AH=31h. How to compute
   * the number of paragraphs? Simple: look at the memory map and note down
   * the size of the BEGTEXT segment (that's where I store all TSR routines).
   * then: (sizeof(BEGTEXT) + sizeof(PSP) + 15) / 16
   * PSP is 256 bytes of course. And +15 is needed to avoid truncating the
   * last (partially used) paragraph. */
  _asm {
    mov ax, 3100h  /* AH=31 'terminate+stay resident', AL=0 exit code */
    mov dx, offset begtextend /* DX = offset of resident code end     */
    add dx, 256    /* add size of PSP (256 bytes)                     */
    add dx, 15     /* add 15 to avoid truncating last paragraph       */
    shr dx, 1      /* convert bytes to number of 16-bytes paragraphs  */
    shr dx, 1      /* the 8086/8088 CPU supports only a 1-bit version */
    shr dx, 1      /* of SHR, so I have to repeat it as many times as */
    shr dx, 1      /* many bits I need to shift.                      */
    int 21h
  }

  return(0); /* never reached, but compiler complains if not present */
}
