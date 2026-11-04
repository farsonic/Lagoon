/*
 * Lagoon - multicast DNS / DNS service discovery (RFC 6762, RFC 6763):
 * find file servers on the local network (_smb._tcp, _afpovertcp._tcp,
 * _nfs._tcp) and resolve "name.local" host names.
 *
 * One-shot queries only (no cache, no responder): ln_mdns_browse() sends
 * PTR queries for the service types, follows up with SRV/TXT/A queries for
 * what is still missing and collects answers for timeout_ms.
 * Queries go to 224.0.0.251:5353 from port 5353 when the stack lets us bind
 * it (with the QU bit: "answer by unicast"), and from an ephemeral port
 * (RFC 6762 6.7 "legacy unicast": the responder answers that port).
 *
 * The packet layer (ln_mdns_query, ln_mdns_feed, ln_mdns_services) is
 * separate so tests can run it on canned packets.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_MDNS_H
#define LN_MDNS_H

#include "ln_types.h"
#include "ln_err.h"
#include "ln_net.h"

#define LN_DNS_A    1
#define LN_DNS_PTR  12
#define LN_DNS_TXT  16
#define LN_DNS_AAAA 28
#define LN_DNS_SRV  33
#define LN_DNS_ANY  255

#define LN_MDNS_NAME 192         /* longest name we keep (dotted, NUL included) */

/* a discovered service */
typedef struct LnService {
	char   type[24];         /* "_smb._tcp" */
	char   scheme[8];        /* "smb", "afp", "nfs" ("" for other types) */
	char   instance[64];     /* "My NAS" (UTF-8, as advertised) */
	char   host[LN_MDNS_NAME]; /* "nas.local" (no trailing dot); "" if no SRV yet */
	LnAddr addr;             /* IPv4 (family 4), family 0 if not known */
	u16    port;             /* from SRV, 0 if not known */
	char   txt[256];         /* TXT strings separated by '\n' ("path=/srv/data") */
} LnService;

/* the service types Lagoon looks for, NULL terminated */
extern const char *const ln_mdns_file_types[];
/* "_smb._tcp" -> "smb" etc., NULL if not a file service */
const char *ln_mdns_scheme(const char *type);

/* look up key in a TXT list ("k=v\nk2=v2"): value into buf, or NULL */
const char *ln_mdns_txt(const LnService *s, const char *key, char *buf, size_t n);

/* ---- network ---- */
/* browse for types (NULL = ln_mdns_file_types) for timeout_ms; returns the
 * number of services written to out (sorted by type, then instance) or a
 * negative LN_E*. Services without an address are still returned. */
int ln_mdns_browse(const char *const *types, int timeout_ms, LnService *out, int max);
/* resolve "name.local" (A records), up to max addresses; count or LN_ENOHOST.
 * Fits net_amiga.c's ln_mdns_resolve_hook. */
int ln_mdns_resolve(const char *name, LnAddr *out, int max);
/* tests: send queries to this address (unicast, e.g. 127.0.0.1:port) instead
 * of the mDNS group; NULL restores the default */
void ln_mdns_set_server(const LnAddr *a);

/* ---- packet layer ---- */
typedef struct LnMdns LnMdns;    /* collected resource records */
LnMdns *ln_mdns_new(void);
void ln_mdns_free(LnMdns *m);
/* build a query for nq (name, type) pairs; qu = set the unicast-response
 * bit. Returns the length or LN_ENOSPC. */
int ln_mdns_query(u8 *buf, size_t n, u16 id, const char *const *names, const u16 *types, int nq, int qu);
/* take the records of a response (answers + additional); returns the number
 * of records kept, or LN_EPROTO for a malformed packet. Queries are ignored. */
int ln_mdns_feed(LnMdns *m, const u8 *pkt, size_t len);
/* join PTR -> SRV/TXT -> A into services of the given types (NULL = the file
 * types); returns the count */
int ln_mdns_services(LnMdns *m, const char *const *types, LnService *out, int max);
/* addresses of host (A records) collected so far */
int ln_mdns_addrs(LnMdns *m, const char *host, LnAddr *out, int max);

/* DNS name reader (with compression) shared with ln_netbios.c: reads the
 * name at *off into out (dotted, no trailing dot), advances *off past it.
 * first (may be NULL) receives the first label verbatim. LN_OK / LN_EPROTO. */
int ln_dns_get_name(const u8 *pkt, size_t len, size_t *off, char *out, size_t n, char *first, size_t fn);
/* writes a dotted name as DNS labels; returns bytes written or LN_ENOSPC */
int ln_dns_put_name(u8 *buf, size_t n, const char *name);

#endif
