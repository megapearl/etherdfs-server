/*
 * net_win.c - WinPcap backend for net.h (Windows 9x).
 *
 * WinPcap 3.1 is the last release that runs on Windows 95/98/ME; it predates
 * libpcap 1.0, so this uses the LEGACY setup path - pcap_open_live() plus
 * pcap_setmintocopy(0) for low latency - NOT pcap_create/pcap_activate/
 * pcap_set_immediate_mode (those only exist in libpcap 1.x). The idle wait uses
 * pcap_getevent() + WaitForSingleObject(), because pcap_get_selectable_fd()
 * returns -1 on Windows and select() over a pcap HANDLE is invalid there.
 *
 * Build against the Npcap/WinPcap SDK headers; link wpcap + ws2_32 + iphlpapi.
 *
 * ethersrv is distributed under the terms of the MIT License (see ethersrv.c).
 */

#include <winsock2.h> /* must precede windows.h to avoid the winsock v1 clash */
#include <windows.h>
#include <iphlpapi.h> /* GetAdaptersInfo() for MAC discovery */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#include "net.h"

static pcap_t *handle = NULL;
static HANDLE waitevt = NULL; /* signaled by WinPcap when frames are waiting */

/* Find the 6-byte MAC of the adapter behind a WinPcap device name. WinPcap
 * device names look like "\Device\NPF_{GUID}"; GetAdaptersInfo keys each
 * adapter by that same "{GUID}", so a substring match ties the two together. */
static int get_mac_for_pcap_dev(const char *pcap_dev, unsigned char mac[6]) {
  IP_ADAPTER_INFO *info, *p;
  ULONG len = 0;
  int found = 0;

  if (GetAdaptersInfo(NULL, &len) != ERROR_BUFFER_OVERFLOW || len == 0)
    return 0;
  info = malloc(len);
  if (info == NULL)
    return 0;
  if (GetAdaptersInfo(info, &len) == NO_ERROR) {
    for (p = info; p != NULL; p = p->Next) {
      if (p->AddressLength == 6 && strstr(pcap_dev, p->AdapterName) != NULL) {
        memcpy(mac, p->Address, 6);
        found = 1;
        break;
      }
    }
  }
  free(info);
  return found;
}

int net_open(unsigned short ethertype, const char *ifname,
             unsigned char mymac_out[6]) {
  char errbuf[PCAP_ERRBUF_SIZE];
  char filter_exp[32];
  struct bpf_program fp;

  if (ifname == NULL || *ifname == 0)
    return -1;

  if (!get_mac_for_pcap_dev(ifname, mymac_out)) {
    fprintf(stderr, "Error: could not determine MAC for interface %s\n",
            ifname);
    return -1;
  }

  /* legacy open (WinPcap 3.1): snaplen 2048 matches the server frame buffer,
   * promiscuous like the Linux backend, 1 ms read timeout */
  handle = pcap_open_live(ifname, 2048, 1, 1, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
    return -1;
  }
  /* copy frames up to the app as soon as they arrive (low latency) */
  pcap_setmintocopy(handle, 0);

  sprintf(filter_exp, "ether proto 0x%04X", ethertype);
  if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    handle = NULL;
    return -1;
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "pcap_setfilter() failed: %s\n", pcap_geterr(handle));
    pcap_freecode(&fp);
    pcap_close(handle);
    handle = NULL;
    return -1;
  }
  pcap_freecode(&fp);

  waitevt = pcap_getevent(handle);
  return 0;
}

int net_recv(unsigned char *buf, int maxlen, int timeout_ms) {
  struct pcap_pkthdr *header;
  const u_char *data;
  int res, len;

  if (handle == NULL)
    return -1;

  /* Block until the capture event signals (a frame arrived) or the timeout.
   * pcap_get_selectable_fd()/select() are not usable on Windows. */
  if (waitevt != NULL)
    WaitForSingleObject(waitevt, (DWORD)timeout_ms);
  else
    Sleep(1);

  res = pcap_next_ex(handle, &header, &data);
  if (res == 0)
    return 0; /* timeout */
  if (res < 0)
    return -1; /* error */
  len = (int)header->caplen;
  if (len > maxlen)
    len = maxlen;
  memcpy(buf, data, (size_t)len);
  return len;
}

int net_send(const unsigned char *frame, int len) {
  if (handle == NULL)
    return -1;
  /* pcap_sendpacket returns 0 on success, -1 on error; the caller expects the
   * byte count on success, so report len when it went out. */
  if (pcap_sendpacket(handle, frame, len) == 0)
    return len;
  return -1;
}

void net_close(void) {
  if (handle != NULL) {
    pcap_close(handle);
    handle = NULL;
  }
  waitevt = NULL;
}
