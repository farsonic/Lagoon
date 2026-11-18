/*
 * Lagoon - sockets on the classic Mac OS (src/core/ln_net.h), on Riptide's own interface for
 * programs: the .IPP driver's private call RTMAC_API hands out a table of the stack's socket
 * calls, which run in the program's context exactly as bsdsocket.library's do in an Amiga task
 * (riptide src/mac/api_mac.c, src/mac/prefs/mac_ipp_private.h). A call that waits (connect,
 * recv, select, a name lookup) calls back the program's yield function meanwhile, which gives
 * the Mac to other programs and to the stack's deferred task; Command-period breaks the wait.
 * MacTCP has no such interface: without Riptide, ln_net_init answers LN_ENONET.
 *
 * Addresses are BSD 4.4 sockaddrs with a length byte (Riptide's rt_sockaddr_in/_in6); the few
 * constants needed are spelled out below rather than included, so Lagoon's types and Riptide's
 * never meet in one file.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../core/ln_net.h"
#include "../core/ln_sys.h"
#include "mac_ipp_private.h"                     /* riptide src/mac/prefs: struct rtmac_api */

short mac_pb(void *pb, long trap);               /* riptide src/mac/app/ostraps.S */
#define TRAP_OPEN    0xA000
#define TRAP_CONTROL 0xA004

/* riptide include/rt/rt_bsd.h, rt_errno.h */
#define AF4         2
#define AF6         28
#define STREAM      1
#define DGRAM       2
#define SOL_SOCK    0xffff
#define SO_REUSE    0x0004
#define SO_BCAST    0x0020
#define SO_ERR      0x1007
#define IPPROTO_IP4 0
#define IPPROTO_TCP6 6
#define IP_ADDMEMB  12
#define TCP_NODEL   0x01
#define FIONBIO_    0x8004667EUL
#define E_INTR      4
#define E_NOMEM     12
#define E_ACCES     13
#define E_PIPE      32
#define E_AGAIN     35
#define E_INPROG    36
#define E_ADDRUSE   48
#define E_ADDRNA    49
#define E_NETUNR    51
#define E_CONNRST   54
#define E_NOBUFS    55
#define E_NOTCONN   57
#define E_TIMEDOUT  60
#define E_CONNREF   61
#define E_HOSTUNR   65
#define E_NOENT     2

struct LnSock { int fd; };

static const struct rtmac_api *api;
static void *cl;

/* the program's part (src/mac/mac_thunks.S, mac_main.c): yield and break with its A5 */
void lm_yield_thunk(void *arg);
int  lm_break_thunk(void *arg);
extern void *lm_a5;

int (*ln_mdns_resolve_hook)(const char *name, LnAddr *out, int max);

int ln_net_init(void)
{
	unsigned char pb[80];
	unsigned char name[6] = { 4, '.', 'I', 'P', 'P', 0 };
	short ref;
	if (cl)
		return LN_OK;
	memset(pb, 0, sizeof pb);
	*(unsigned char **)(pb + 18) = name;
	if (mac_pb(pb, TRAP_OPEN) != 0)
		return LN_ENONET;
	ref = *(short *)(pb + 24);
	memset(pb, 0, sizeof pb);
	*(short *)(pb + 24) = ref;
	*(short *)(pb + 26) = RTMAC_API;
	if (mac_pb(pb, TRAP_CONTROL) != 0)
		return LN_ENONET;                    /* MacTCP, or a Riptide without RTMAC_API */
	api = *(const struct rtmac_api **)(pb + 28);
	if (!api || api->magic != RTMAC_API_MAGIC || api->version < 1)
		return LN_ENONET;
	__asm__ volatile("move.l %%a5,%0" : "=m"(lm_a5));
	cl = api->attach(lm_yield_thunk, lm_break_thunk, NULL);
	return cl ? LN_OK : LN_ENONET;
}

void ln_net_exit(void)
{
	if (cl)
		api->detach(cl);
	cl = NULL;
}

static int map_err(int r)
{
	switch (-r) {
	case E_CONNREF: return LN_ECONNREFUSED;
	case E_TIMEDOUT: return LN_ETIMEDOUT;
	case E_HOSTUNR: case E_NETUNR: return LN_EHOSTUNREACH;
	case E_CONNRST: case E_PIPE: case E_NOTCONN: return LN_ECONNRESET;
	case E_NOMEM: case E_NOBUFS: return LN_ENOMEM;
	case E_INTR: return LN_EBREAK;
	case E_ACCES: return LN_EACCES;
	case E_NOENT: return LN_ENOHOST;
	}
	return LN_EIO;
}

/* sockaddrs: 16 bytes for IPv4, 28 for IPv6, the length first */
static unsigned long to_sa(const LnAddr *a, u8 *sa)
{
	memset(sa, 0, 28);
	if (a->family == 6) {
		sa[0] = 28; sa[1] = AF6;
		sa[2] = (u8)(a->port >> 8); sa[3] = (u8)a->port;
		memcpy(sa + 8, a->a, 16);
		return 28;
	}
	sa[0] = 16; sa[1] = AF4;
	sa[2] = (u8)(a->port >> 8); sa[3] = (u8)a->port;
	memcpy(sa + 4, a->a, 4);
	return 16;
}
static void from_sa(const u8 *sa, LnAddr *a)
{
	memset(a, 0, sizeof(*a));
	a->port = (u16)(sa[2] << 8 | sa[3]);
	if (sa[1] == AF6) {
		a->family = 6;
		memcpy(a->a, sa + 8, 16);
	} else {
		a->family = 4;
		memcpy(a->a, sa + 4, 4);
	}
}

static int parse_v4(const char *s, u8 *out)
{
	int part = 0, n = 0, digits = 0;
	for (;; s++) {
		if (*s >= '0' && *s <= '9') {
			part = part * 10 + (*s - '0');
			if (part > 255 || ++digits > 3) return 0;
		} else if ((*s == '.' || !*s) && digits && n < 4) {
			out[n++] = (u8)part;
			part = digits = 0;
			if (!*s) break;
		} else
			return 0;
	}
	return n == 4;
}

int ln_resolve(const char *host, LnAddr *out, int max)
{
	u8 a[8][16];
	char canon[2];
	int n, i, k = 0;
	if (max <= 0) return LN_EINVAL;
	memset(out, 0, sizeof(*out) * (size_t)max);
	if (parse_v4(host, out[0].a)) {
		out[0].family = 4;
		return 1;
	}
	if (!cl) return LN_ENONET;
	n = api->resolve(cl, host, a, 8, 0, canon, sizeof canon);
	if (n <= 0 && ln_mdns_resolve_hook) {
		size_t l = strlen(host);
		if (l > 6 && !strcmp(host + l - 6, ".local"))
			return ln_mdns_resolve_hook(host, out, max);
	}
	if (n == -E_INTR) return LN_EBREAK;
	if (n <= 0) return LN_ENOHOST;
	for (i = 0; i < n && k < max; i++) {
		static const u8 mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
		if (!memcmp(a[i], mapped, 12)) {
			out[k].family = 4;
			memcpy(out[k].a, a[i] + 12, 4);
		} else {
			out[k].family = 6;
			memcpy(out[k].a, a[i], 16);
		}
		k++;
	}
	return k;
}

void ln_addr_str(const LnAddr *a, char *buf, size_t n)
{
	if (a->family == 6) {
		size_t o = 0;
		int i;
		for (i = 0; i < 16 && o + 6 < n; i += 2)
			o += (size_t)ln_snprintf(buf + o, n - o, i ? ":%x" : "%x", (unsigned)(a->a[i] << 8 | a->a[i + 1]));
	} else
		ln_snprintf(buf, n, "%u.%u.%u.%u", a->a[0], a->a[1], a->a[2], a->a[3]);
}

/* wait until fd is readable (wr 0) or writable; timeout_ms 0: no limit (Command-period still breaks) */
static int wait_fd(int fd, int wr, int timeout_ms)
{
	unsigned long set[2] = { 0, 0 }, sig = 0;
	int r;
	set[fd >> 5] = 1UL << (fd & 31);
	r = api->select(cl, fd + 1, wr ? NULL : set, wr ? set : NULL, NULL, timeout_ms > 0 ? timeout_ms : -1, &sig);
	if (r == 0) return LN_ETIMEDOUT;
	if (r < 0) return map_err(r);
	return LN_OK;
}

static void nonblock(int fd, int on)
{
	unsigned long v = (unsigned long)on;
	api->ioctl(cl, fd, FIONBIO_, &v);
}

static int finish_connect(int fd, const u8 *sa, unsigned long len, int timeout_ms)
{
	int r;
	nonblock(fd, 1);
	r = api->connect(cl, fd, sa, len);
	if (r == -E_INPROG || r == -E_AGAIN) {
		int err = 0;
		unsigned long el = sizeof(err);
		r = wait_fd(fd, 1, timeout_ms);
		if (r == LN_OK) {
			api->getsockopt(cl, fd, SOL_SOCK, SO_ERR, &err, &el);
			r = err ? -err : 0;
		} else
			return r;
	}
	if (r < 0)
		return r == -E_ADDRUSE || r == -E_ADDRNA ? r : map_err(r);
	nonblock(fd, 0);
	{ int one = 1; api->setsockopt(cl, fd, IPPROTO_TCP6, TCP_NODEL, &one, sizeof(one)); }
	return LN_OK;
}

int ln_tcp_connect(const char *host, u16 port, int timeout_ms, LnSock **out)
{
	LnAddr a[8];
	int n = ln_resolve(host, a, 8), i, last = LN_ECONNREFUSED;
	if (n < 0) return n;
	for (i = 0; i < n; i++) {
		u8 sa[28];
		unsigned long len;
		int fd, r;
		a[i].port = port;
		len = to_sa(&a[i], sa);
		fd = api->socket(cl, a[i].family == 6 ? AF6 : AF4, STREAM, 0);
		if (fd < 0) { last = map_err(fd); continue; }
		r = finish_connect(fd, sa, len, timeout_ms);
		if (r != LN_OK) {
			api->close(cl, fd);
			if (r == LN_EBREAK) return r;
			last = r == -E_ADDRUSE || r == -E_ADDRNA ? LN_EIO : r;
			continue;
		}
		*out = ln_alloc(sizeof(LnSock));
		if (!*out) { api->close(cl, fd); return LN_ENOMEM; }
		(*out)->fd = fd;
		return LN_OK;
	}
	return last;
}

int ln_tcp_send(LnSock *s, const void *buf, size_t n, int timeout_ms)
{
	const u8 *p = buf;
	while (n) {
		int r, w = wait_fd(s->fd, 1, timeout_ms);
		if (w) return w;
		r = api->sendto(cl, s->fd, p, n, 0, NULL, 0);
		if (r < 0) { if (r == -E_AGAIN) continue; return map_err(r); }
		p += r; n -= (size_t)r;
	}
	return LN_OK;
}

int ln_tcp_recv_some(LnSock *s, void *buf, size_t n, int timeout_ms)
{
	for (;;) {
		int r, w = wait_fd(s->fd, 0, timeout_ms);
		if (w) return w;
		r = api->recvfrom(cl, s->fd, buf, n, 0, NULL, NULL);
		if (r < 0) { if (r == -E_AGAIN) continue; return map_err(r); }
		return r;
	}
}

int ln_tcp_recv(LnSock *s, void *buf, size_t n, int timeout_ms)
{
	u8 *p = buf;
	while (n) {
		int r = ln_tcp_recv_some(s, p, n, timeout_ms);
		if (r < 0) return r;
		if (r == 0) return LN_ECONNRESET;
		p += r; n -= (size_t)r;
	}
	return LN_OK;
}

int ln_sock_local(LnSock *s, LnAddr *out)
{
	u8 sa[28];
	unsigned long len = sizeof sa;
	int r = api->getsockname(cl, s->fd, sa, &len);
	if (r < 0) return map_err(r);
	from_sa(sa, out);
	return LN_OK;
}

void ln_sock_close(LnSock *s)
{
	if (!s) return;
	if (cl) api->close(cl, s->fd);
	ln_free(s);
}

int ln_udp_open(u16 port, const LnAddr *grp, LnSock **out)
{
	u8 sa[16];
	int fd, one = 1, r;
	if (!cl) return LN_ENONET;
	fd = api->socket(cl, AF4, DGRAM, 0);
	if (fd < 0) return map_err(fd);
	api->setsockopt(cl, fd, SOL_SOCK, SO_REUSE, &one, sizeof(one));
	memset(sa, 0, sizeof sa);
	sa[0] = 16; sa[1] = AF4; sa[2] = (u8)(port >> 8); sa[3] = (u8)port;
	r = api->bind(cl, fd, sa, 16);
	if (r < 0) { api->close(cl, fd); return map_err(r); }
	if (grp) {
		u8 m[8];
		memcpy(m, grp->a, 4);
		memset(m + 4, 0, 4);                 /* INADDR_ANY */
		api->setsockopt(cl, fd, IPPROTO_IP4, IP_ADDMEMB, m, 8);
	}
	*out = ln_alloc(sizeof(LnSock));
	if (!*out) { api->close(cl, fd); return LN_ENOMEM; }
	(*out)->fd = fd;
	return LN_OK;
}

int ln_udp_sendto(LnSock *s, const LnAddr *to, const void *buf, size_t n)
{
	u8 sa[28];
	unsigned long len = to_sa(to, sa);
	int r = api->sendto(cl, s->fd, buf, n, 0, sa, len);
	return r < 0 ? map_err(r) : (int)n;
}

int ln_udp_recvfrom(LnSock *s, LnAddr *from, void *buf, size_t n, int timeout_ms)
{
	u8 sa[28];
	unsigned long len = sizeof sa;
	int r, w = wait_fd(s->fd, 0, timeout_ms);
	if (w) return w;
	r = api->recvfrom(cl, s->fd, buf, n, 0, sa, &len);
	if (r < 0) return map_err(r);
	if (from) from_sa(sa, from);
	return r;
}

int ln_udp_broadcast(LnSock *s, int on)
{
	int r = api->setsockopt(cl, s->fd, SOL_SOCK, SO_BCAST, &on, sizeof(on));
	return r < 0 ? map_err(r) : LN_OK;
}

/* nfs: from a reserved local port, 1023 downwards to 600 */
int ln_tcp_connect_reserved(const char *host, u16 port, int timeout_ms, LnSock **out)
{
	LnAddr a[8];
	int n = ln_resolve(host, a, 8), i, lport, last = LN_EACCES;
	if (n < 0) return n;
	for (i = 0; i < n; i++) {
		a[i].port = port;
		for (lport = 1023; lport >= 600; lport--) {
			u8 sa[28], ls[28];
			unsigned long len, llen;
			LnAddr la;
			int fd, one = 1, r;
			len = to_sa(&a[i], sa);
			memset(&la, 0, sizeof(la));
			la.family = a[i].family;
			la.port = (u16)lport;
			llen = to_sa(&la, ls);
			fd = api->socket(cl, a[i].family == 6 ? AF6 : AF4, STREAM, 0);
			if (fd < 0) return map_err(fd);
			api->setsockopt(cl, fd, SOL_SOCK, SO_REUSE, &one, sizeof(one));
			if (api->bind(cl, fd, ls, llen) < 0) { api->close(cl, fd); continue; }
			r = finish_connect(fd, sa, len, timeout_ms);
			if (r == -E_ADDRUSE || r == -E_ADDRNA) { api->close(cl, fd); continue; }
			if (r != LN_OK) { api->close(cl, fd); last = r; break; }
			*out = ln_alloc(sizeof(LnSock));
			if (!*out) { api->close(cl, fd); return LN_ENOMEM; }
			(*out)->fd = fd;
			return LN_OK;
		}
	}
	return last;
}
