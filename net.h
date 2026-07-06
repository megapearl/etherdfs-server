/*
 * net.h - platform-neutral raw-Ethernet packet I/O for ethersrv.
 *
 * The EtherDFS server needs only four things from the link layer: open a raw
 * interface filtered to a single ethertype (and learn our own MAC), block for a
 * frame with a timeout, send a fully-built frame, and close. Each platform
 * implements these in its own net_<platform>.c (net_linux.c = libpcap,
 * net_win.c = WinPcap 3.1, net_dos.c = packet driver); nothing above this line
 * touches pcap, sockets or the packet-driver interrupt.
 *
 * ethersrv is distributed under the terms of the MIT License (see ethersrv.c).
 */
#ifndef NET_H
#define NET_H

/* Open the raw interface, install a filter for `ethertype` (host byte order,
 * e.g. 0xEDF5) and fill mymac_out[6] with our interface MAC. Prints its own
 * diagnostics to stderr on failure.
 * Returns 0 on success, -1 on failure. */
int net_open(unsigned short ethertype, const char *ifname,
             unsigned char mymac_out[6]);

/* Wait up to timeout_ms for a frame. Copies at most maxlen bytes into buf.
 * Returns the frame length (>0), 0 on timeout, or -1 on error. */
int net_recv(unsigned char *buf, int maxlen, int timeout_ms);

/* Send a frame that already carries its full 14-byte Ethernet header (dst MAC,
 * src MAC, ethertype). Returns the number of bytes sent, or -1 on error. */
int net_send(const unsigned char *frame, int len);

/* Release the interface. Safe to call even if net_open() failed. */
void net_close(void);

#endif
