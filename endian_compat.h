/*
 * endian_compat.h - little-endian byte helpers for ethersrv.
 *
 * The wire code uses the glibc names htons()/le16toh()/le32toh()/htole16()/
 * htole32(). Those live in <arpa/inet.h> and <endian.h>, which exist only on
 * Linux/BSD. All EtherDFS targets (x86 Linux, Win9x, DOS) are little-endian, so
 * on non-glibc platforms the host<->LE conversions are identities and the
 * host<->network (big-endian) conversions are a single byte swap - provided
 * here without pulling in those Linux-only headers (and without dragging in
 * winsock just for htons).
 *
 * ethersrv is distributed under the terms of the MIT License (see ethersrv.c).
 */
#ifndef ENDIAN_COMPAT_H
#define ENDIAN_COMPAT_H

#if defined(__linux__)

#include <arpa/inet.h> /* htons() */
#include <endian.h>    /* le16toh(), le32toh(), htole16(), htole32() */

#else /* Win9x / DOS / other non-glibc little-endian x86 */

#include <stdint.h>

#define le16toh(x) ((uint16_t)(x))
#define le32toh(x) ((uint32_t)(x))
#define htole16(x) ((uint16_t)(x))
#define htole32(x) ((uint32_t)(x))

#ifndef htons
#define htons(x) ((uint16_t)(((uint16_t)(x) >> 8) | ((uint16_t)(x) << 8)))
#endif
#ifndef ntohs
#define ntohs(x) htons(x)
#endif

#endif

#endif
