/*
 * Lagoon - NetBIOS name service over UDP port 137 (RFC 1001/1002): find
 * Windows and Samba hosts that do not announce themselves with mDNS (older
 * NAS boxes, Windows without Bonjour) and resolve NetBIOS names.
 *
 * ln_nb_discover() broadcasts name queries for "*" and "WORKGROUP" and a
 * node status request, then asks each host that answered for its name
 * table (node status, unicast). ln_nb_resolve() broadcasts a name query.
 * The packet layer is separate for tests (canned packets).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_NETBIOS_H
#define LN_NETBIOS_H

#include "ln_types.h"
#include "ln_err.h"
#include "ln_net.h"

#define LN_NB_PORT 137

typedef struct LnNbHost {
	char   name[16];         /* NetBIOS computer name ("NAS"), "" if unknown */
	char   group[16];        /* workgroup / domain ("WORKGROUP") */
	LnAddr addr;             /* IPv4 */
	int    server;           /* has the file server service (<20>) */
} LnNbHost;

/* encode name (up to 15 chars, upper-cased, space padded; "*" is padded
 * with NULs) + suffix byte into the 34-byte DNS-style label */
void ln_nb_encode(const char *name, u8 suffix, u8 *out34);
/* decode a 32-char encoded label back: name (trailing spaces cut) and suffix */
int  ln_nb_decode(const u8 *enc32, char *name16, u8 *suffix);

/* requests; return the length or LN_ENOSPC */
int ln_nb_build_query(u8 *buf, size_t n, u16 id, const char *name, u8 suffix, int broadcast);
int ln_nb_build_status(u8 *buf, size_t n, u16 id);
/* positive name query response with transaction id: addresses into out
 * (count), 0 for a negative response / other packet, LN_EPROTO malformed */
int ln_nb_parse_query(const u8 *pkt, size_t len, u16 id, LnAddr *out, int max);
/* node status response: fills name/group/server (addr untouched); LN_OK,
 * 0 < if not a status response */
int ln_nb_parse_status(const u8 *pkt, size_t len, LnNbHost *h);

/* network: hosts found in timeout_ms (count) or LN_E* */
int ln_nb_discover(int timeout_ms, LnNbHost *out, int max);
/* resolve a NetBIOS name (server service <20>, then workstation <00>) */
int ln_nb_resolve(const char *name, LnAddr *out, int max);
/* tests: send to this address (unicast) instead of 255.255.255.255:137 */
void ln_nb_set_target(const LnAddr *a);

#endif
