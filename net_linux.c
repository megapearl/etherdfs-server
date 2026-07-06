/*
 * net_linux.c - libpcap backend for net.h (Linux/BSD reference implementation).
 *
 * This is the original raw_sock()/pcap_next_ex()/pcap_inject() code lifted out
 * of ethersrv.c behind the net_* interface, so the Linux build behaves
 * bit-identically to before the multi-platform refactor. libpcap and all
 * interface/MAC discovery live here and nowhere else.
 *
 * ethersrv is distributed under the terms of the MIT License (see ethersrv.c).
 */

#include <errno.h>
#include <ifaddrs.h> /* getifaddrs() */
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h> /* close() */

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

#include "net.h"

/* the one live capture handle plus its selectable fd (for the idle wait) */
static pcap_t *handle = NULL;
static int selfd = -1;

int net_open(unsigned short ethertype, const char *interface,
             unsigned char mymac_out[6]) {
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[32];
  struct ifaddrs *ifap, *ifa;
  int mac_found = 0;

  if ((interface == NULL) || (*interface == 0)) {
    errno = EINVAL;
    return -1;
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
            if (mymac_out != NULL)
              memcpy(mymac_out, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
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
            if (mymac_out != NULL)
              memcpy(mymac_out, LLADDR(sdl), ETH_ALEN);
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
    return -1;
  }

  /* Create pcap handle */
  handle = pcap_create(interface, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "pcap_create() failed: %s\n", errbuf);
    return -1;
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
    handle = NULL;
    return -1;
  }

  /* Compile and apply BPF filter natively within libpcap to drop unwanted
   * traffic */
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

  /* Keep the pcap handle in BLOCKING mode so select() on its selectable fd
   * waits correctly. Non-blocking mode makes select()/poll() on the pcap fd
   * unreliable and contributed to the idle busy-spin. The pcap read timeout set
   * above bounds pcap_next_ex() so it still returns promptly when idle. */
  selfd = pcap_get_selectable_fd(handle);

  errno = 0;
  return 0;
}

int net_recv(unsigned char *buf, int maxlen, int timeout_ms) {
  struct pcap_pkthdr *header;
  const unsigned char *data;
  int res, len;

  if (handle == NULL)
    return -1;

  /* Wait until the capture fd is READABLE (a frame arrived) or the timeout.
   * Monitor read only: a packet-capture fd is effectively always "writable", so
   * also passing it as the write/except set made select() return immediately on
   * every iteration -> the loop busy-spun a CPU core at 100% even when the link
   * was idle (0 pps). */
  if (selfd >= 0) {
    fd_set fdset;
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    FD_ZERO(&fdset);
    FD_SET(selfd, &fdset);
    select(selfd + 1, &fdset, NULL, NULL, &tv);
  } else {
    /* Polling fallback if selectable FD is not supported on this platform */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    select(0, NULL, NULL, NULL, &tv);
  }

  res = pcap_next_ex(handle, &header, &data);
  if (res == 0)
    return 0; /* timeout */
  if (res < 0)
    return -1; /* error/EOF */
  len = header->caplen;
  if (len > maxlen)
    len = maxlen;
  memcpy(buf, data, len);
  return len;
}

int net_send(const unsigned char *frame, int len) {
  if (handle == NULL)
    return -1;
  return pcap_inject(handle, frame, len);
}

void net_close(void) {
  if (handle != NULL) {
    pcap_close(handle);
    handle = NULL;
  }
  selfd = -1;
}
