/*
 * This file is part of the etherdfs project.
 * http://etherdfs.sourceforge.net
 *
 * Copyright (C) 2017 Mateusz Viste
 *
 * Contains all global variables used by etherdfs.
 */

#ifndef GLOBALS_SENTINEL
#define GLOBALS_SENTINEL

/* required size (in bytes) of the data segment - this must be bigh enough as
 * to accomodate all "DATA" segments AND the stack, which will be located at
 * the very end of the data segment. packet drivers tend to require a stack
 * of several hundreds bytes at least - 1K should be safe... It is important
 * that DATASEGSZ can contain a stack of AT LEAST the size of the stack used
 * by the transient code, since the transient part of the program will switch
 * to it and expects the stack to not become corrupted in the process.
 *
 * CRITICAL: DATASEGSZ must cover the ENTIRE DGROUP *including the transient
 * STACK segment at its top* (check the linker map: DGROUP size, STACK at the
 * end -- currently DGROUP = 0xE30 = 3632 with STACK at 2608..3632). main()
 * copies DATASEGSZ bytes of DGROUP into the new segment and then switches
 * SS:SP there; any live stack bytes ABOVE the copy window (e.g. main()'s own
 * locals such as the parsed args) arrive as garbage. With the old value 3500
 * the top 132 stack bytes were not copied: whether that bit depended on which
 * locals the compiler spilled there -- adding code to main() made it drop the
 * ARGFL_AUTO flag, silently skipping server auto-discovery (mapping showed
 * MAC 00:00:00:00:00:00). MUST be >= the linker map's DGROUP size (which
 * includes the transient STACK segment at its top). As of increment 3:
 * DGROUP = 4064 (0xFE0), so 4608 covers it with margin and leaves ~1566 bytes
 * of resident stack (SP starts at DATASEGSZ-2, resident non-stack data ends
 * ~3040). RE-CHECK THE MAP after every globals change. */
#define DATASEGSZ 4608

/* a few globals useful only for debug messages */
#if DEBUGLEVEL > 0
static unsigned short dbg_xpos = 0;
static unsigned short far *dbg_VGA = (unsigned short far *)(0xB8000000l);
static unsigned char dbg_hexc[16] = "0123456789ABCDEF";
#define dbg_startoffset 80*16
#endif

/* whenever the tsrshareddata structure changes, offsets below MUST be
 * adjusted (these are required by assembly routines) */
#define GLOB_DATOFF_PREV2FHANDLERSEG 0
#define GLOB_DATOFF_PREV2FHANDLEROFF 2
#define GLOB_DATOFF_PSPSEG 4
#define GLOB_DATOFF_PKTHANDLE 6
#define GLOB_DATOFF_PKTINT 8
static struct tsrshareddata {
/*offs*/
/*  0 */ unsigned short prev_2f_handler_seg; /* seg:off of the previous 2F handler */
/*  2 */ unsigned short prev_2f_handler_off; /* (so I can call it for all queries  */
                                            /* that do not relate to my drive     */
/*  4 */ unsigned short pspseg;    /* segment of the program's PSP block */
/*  6 */ unsigned short pkthandle; /* handler returned by the packet driver */
/*  8 */ unsigned char pktint;     /* software interrupt of the packet driver */

         unsigned char ldrv[26]; /* local to remote drives mappings (0=A:, 1=B, etc */

         /* seg:off of the previous INT 21h handler (the LFN hook chains to it
          * for everything that is not an LFN call on one of our drives). Added
          * at the END of the struct so the GLOB_DATOFF_* assembly offsets above
          * are unchanged; these fields are only ever accessed from C. */
         unsigned short prev_21_handler_seg;
         unsigned short prev_21_handler_off;
} glob_data;

/* global variables related to packet driver management and handling frames */
static unsigned char glob_pktdrv_recvbuff[FRAMESIZE];
static signed short volatile glob_pktdrv_recvbufflen; /* length of the frame in buffer, 0 means "free", and neg value means "awaiting" */
static unsigned char glob_pktdrv_sndbuff[FRAMESIZE]; /* this not only is my send-frame buffer, but I also use it to store permanently lmac, rmac, ethertype and PROTOVER at proper places */
static unsigned long glob_pktdrv_pktcall;     /* vector address of the pktdrv interrupt */

/* a few definitions for data that points to my sending buffer */
#define GLOB_LMAC (glob_pktdrv_sndbuff + 6) /* local MAC address */
#define GLOB_RMAC (glob_pktdrv_sndbuff)     /* remote MAC address */

static unsigned char glob_reqdrv;  /* the requested drive, set by the INT 2F *
                                    * handler and read by process2f()        */

static unsigned short glob_reqstkword; /* WORD saved from the stack (used by SETATTR) */
static struct sdastruct far *glob_sdaptr; /* pointer to DOS SDA (set by main() at *
                                           * startup, used later by process2f()   */

/* Base of the DOS CDS array (Current Directory Structure, one entry per drive)
 * and the size of one entry, both taken from the List of Lists at install.
 * The SDA's own drive_cdsptr is the CDS of the drive of the CURRENT DOS
 * operation, so it goes STALE for our purposes: after an app touches C:, it
 * still points at C: while the default drive is E:. Indexing this array by
 * drive number always gives the RIGHT drive's CDS. */
static unsigned char far *glob_cdsarr;  /* CDS[0] (0 = not available) */
static unsigned char glob_cdssz;        /* bytes per CDS entry (51h or 58h) */
static unsigned char glob_lastdrv;      /* LASTDRIVE (number of CDS entries) */

/* seg:off addresses of the old (DOS) stack */
static unsigned short glob_oldstack_seg;
static unsigned short glob_oldstack_off;

/* the INT 2F "multiplex id" registerd by EtherDFS */
static unsigned char glob_multiplexid;

/* an INTPACK structure used to store registers as set when INT2F is called */
static union INTPACK glob_intregs;

/* --- LFN (long filename) client state (Phase-2 increment 2) --- */
#define LFN_FINDMAX 4        /* concurrent FindFirst/Next searches */
#define LFN_HANDLE_MAGIC 0xEF00u /* our find handles are 0xEF00|slot (avoids
                                  * collision with DOSLFN's handles) */
struct lfnfindslot {
  unsigned char inuse;
  unsigned char drv;         /* 0-based local drive index */
  unsigned short dirss;      /* server search-state (cursor) */
  unsigned short fpos;       /* server position/nth (cursor) */
  unsigned char attr;        /* search attribute mask */
  unsigned char tmpl[11];    /* 8.3 FCB search template (for FindNext) */
  unsigned char mask[64];    /* ASCIZ long-name mask, appended to FINDNEXT as
                              * an LFNSTR tail so the server long-matches like
                              * FindFirst (Win95). Empty = don't append (masks
                              * >63 chars degrade to SFN-template matching). */
};
static struct lfnfindslot glob_lfn_find[LFN_FINDMAX];
/* Reentrancy is guarded STATELESSLY (no flag that could get stuck): both the
 * INT 2Fh handler and the INT 21h LFN send switch SS to the resident data
 * segment (SS=DS, SP=DATASEGSZ-2) while they run. So if a handler is entered
 * with SS ALREADY equal to DS, it is nested inside an outer switched context --
 * switching again would reset SP and clobber the outer's stack. Such a nested
 * handler bails/chains WITHOUT switching. (See the SS==DS checks in the code.) */
static unsigned char glob_lfn_op = 0;    /* AL_LFN_FINDFIRST / FINDNEXT for the helper */
static unsigned char glob_lfn_slot = 0;  /* find slot the helper operates on */
static unsigned char glob_lfn_drv = 0;   /* 0-based drive index for the helper */
/* previous INT 21h handler as an m16:16 for 'call dword ptr' pass-down
 * (offset in the LOW word, segment in the HIGH word -- same convention as
 * glob_pktdrv_pktcall; the seg,off field ORDER of prev_21_handler_seg/off in
 * tsrshareddata is wrong for an indirect call operand) */
static unsigned long glob_prev21call = 0;
/* 716Ch open/create: state passed between the resident-stack helper
 * (lfn_do_open: server round-trip, alias resolution) and the dispatcher
 * (which does the classic 6C00h pass-down on the CALLER stack afterwards) */
static unsigned char glob_lfn_openpath[128]; /* ASCIZ 8.3 pass-down path */
static unsigned short glob_lfn_opensyn;      /* CX action-taken to synthesize */
static unsigned short glob_lfn_openerr;      /* 0 = proceed to pass-down, else
                                              * DOS error code to fail with */
static unsigned short glob_lfn_pdax;         /* pass-down result AX */
static unsigned short glob_lfn_pdfl;         /* pass-down result FLAGS */
static unsigned short glob_lfn_pdcx;         /* pass-down result CX (43h get) */
static unsigned short glob_lfn_pdop;         /* pass-down AX op for LFNOP_PDPREP */
static unsigned char glob_lfn_sub;           /* 7160h CL subfunction (1|2) */
static unsigned short glob_o21ss;         /* saved SS for the 21h-hook stack swap */
static unsigned short glob_o21sp;         /* saved SP for the 21h-hook stack swap */

/* original (program) DS, saved by main() BEFORE it switches DS/SS to the newly
 * allocated resident segment. Because it is written before the segment copy, it
 * is present in both copies. Install-failure paths MUST switch SS/DS back to
 * this segment BEFORE freeing the new one: freeing the segment your own SS
 * points into and then returning runs on freed stack memory (that exact bug
 * hung the machine / stack-faulted EMM386 #12 when a relocation check failed). */
static unsigned short glob_origds;


#endif
