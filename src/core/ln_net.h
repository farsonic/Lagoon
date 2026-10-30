/*
 * Lagoon - sockets. Implemented by src/host/net_posix.c and
 * src/amiga/net_amiga.c (bsdsocket.library: Riptide, Roadshow, Miami,
 * AmiTCP, ...). On the Amiga, bsdsocket.library is opened per task: call
 * ln_net_init() in every process that uses the network.
 * All calls return LN_OK / bytes, or a negative LN_E* code.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_NET_H
#define LN_NET_H

#include "ln_types.h"
#include "ln_err.h"

typedef struct LnSock LnSock;

int  ln_net_init(void);      /* LN_ENONET if there is no stack */
void ln_net_exit(void);

/* an address: IPv4 or IPv6, network byte order */
typedef struct LnAddr {
	int family;              /* 4 or 6 */
	u8  a[16];
	u16 port;                /* host order */
} LnAddr;

/* resolve "host" (name, a.b.c.d, or [v6]) into up to max addresses */
int  ln_resolve(const char *host, LnAddr *out, int max);
void ln_addr_str(const LnAddr *a, char *buf, size_t n);   /* "1.2.3.4" / "fe80::1" */

/* TCP: connect to host:port (tries every address), timeout in ms */
int  ln_tcp_connect(const char *host, u16 port, int timeout_ms, LnSock **out);
/* send everything / receive exactly n bytes; timeout per call in ms
 * (0 = wait forever, still breakable with Ctrl-C) */
int  ln_tcp_send(LnSock *s, const void *buf, size_t n, int timeout_ms);
int  ln_tcp_recv(LnSock *s, void *buf, size_t n, int timeout_ms);
/* receive up to n bytes, whatever is available (>0), 0 = closed by peer */
int  ln_tcp_recv_some(LnSock *s, void *buf, size_t n, int timeout_ms);
/* local address of a connected socket (NFS AUTH_SYS machine name etc.) */
int  ln_sock_local(LnSock *s, LnAddr *out);
void ln_sock_close(LnSock *s);

/* UDP: bind to port (0 = any); mcast_group joins an IPv4 group (mDNS) */
int  ln_udp_open(u16 port, const LnAddr *mcast_group, LnSock **out);
int  ln_udp_sendto(LnSock *s, const LnAddr *to, const void *buf, size_t n);
/* returns bytes, or LN_ETIMEDOUT */
int  ln_udp_recvfrom(LnSock *s, LnAddr *from, void *buf, size_t n, int timeout_ms);
/* enable broadcast (NetBIOS name queries) */
int  ln_udp_broadcast(LnSock *s, int on);

#endif
