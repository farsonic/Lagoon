/*
 * Lagoon - ln_net.h with bsdsocket.library (AmiTCP API v4: Riptide,
 * Roadshow, Miami, AmiTCP, Genesis). SocketBase belongs to the task that
 * opened it: every process calls ln_net_init() itself. Waits use
 * WaitSelect() so Ctrl-C interrupts them (LN_EBREAK).
 * IPv4 only for now (names, a.b.c.d); ".local" names go through ln_mdns
 * when the stack's resolver does not know them.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <exec/types.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <sys/socket.h>
#include <sys/filio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <proto/bsdsocket.h>
#include <libraries/bsdsocket.h>
#include "../core/ln_net.h"
#include "../core/ln_sys.h"

struct Library *SocketBase = NULL;

struct LnSock { LONG fd; };

/* optional mDNS resolver for *.local (src/core/ln_mdns.c; weak-ish hook) */
int (*ln_mdns_resolve_hook)(const char *name, LnAddr *out, int max) = NULL;

int ln_net_init(void)
{
	if (SocketBase)
		return LN_OK;
	SocketBase = OpenLibrary((STRPTR)"bsdsocket.library", 4);
	return SocketBase ? LN_OK : LN_ENONET;
}

void ln_net_exit(void)
{
	if (SocketBase) {
		CloseLibrary(SocketBase);
		SocketBase = NULL;
	}
}

static int map_errno(LONG e)
{
	switch (e) {
	case 61: return LN_ECONNREFUSED;     /* ECONNREFUSED */
	case 60: return LN_ETIMEDOUT;        /* ETIMEDOUT */
	case 65: case 51: return LN_EHOSTUNREACH;
	case 54: case 32: case 57: return LN_ECONNRESET;
	case 55: case 12: return LN_ENOMEM;
	case 4: return LN_EBREAK;            /* EINTR (Ctrl-C) */
	}
	return LN_EIO;
}

static int parse_ip4(const char *s, u8 *a)
{
	int i;
	for (i = 0; i < 4; i++) {
		int v = 0, d = 0;
		while (*s >= '0' && *s <= '9') { v = v * 10 + (*s++ - '0'); d++; }
		if (!d || v > 255) return 0;
		a[i] = (u8)v;
		if (i < 3 && *s++ != '.') return 0;
	}
	return *s == 0;
}

int ln_resolve(const char *host, LnAddr *out, int max)
{
	struct hostent *he;
	int n = 0;
	if (!SocketBase) return LN_ENONET;
	if (max <= 0) return LN_EINVAL;
	memset(out, 0, sizeof(*out));
	if (parse_ip4(host, out->a)) {
		out->family = 4;
		return 1;
	}
	he = gethostbyname((STRPTR)host);
	if (he && he->h_addrtype == AF_INET) {
		for (; he->h_addr_list[n] && n < max; n++) {
			memset(&out[n], 0, sizeof(out[n]));
			out[n].family = 4;
			memcpy(out[n].a, he->h_addr_list[n], 4);
		}
	}
	if (!n && ln_mdns_resolve_hook) {
		size_t l = strlen(host);
		if (l > 6 && !ln_strcasecmp(host + l - 6, ".local"))
			n = ln_mdns_resolve_hook(host, out, max);
	}
	return n > 0 ? n : LN_ENOHOST;
}

void ln_addr_str(const LnAddr *a, char *buf, size_t n)
{
	if (a->family == 4)
		ln_snprintf(buf, n, "%u.%u.%u.%u", a->a[0], a->a[1], a->a[2], a->a[3]);
	else if (n)
		ln_strlcpy(buf, "(ipv6)", n);
}

/* wait until fd is readable (w = 0) or writable (w = 1) */
static int wait_fd(LONG fd, int w, int timeout_ms)
{
	fd_set fs;
	struct timeval tv;
	ULONG sigs;
	LONG r;
	for (;;) {
		FD_ZERO(&fs);
		FD_SET(fd, &fs);
		sigs = SIGBREAKF_CTRL_C;
		if (timeout_ms > 0) {
			tv.tv_sec = timeout_ms / 1000;
			tv.tv_usec = (timeout_ms % 1000) * 1000;
		}
		r = WaitSelect(fd + 1, w ? NULL : &fs, w ? &fs : NULL, NULL, timeout_ms > 0 ? (void *)&tv : NULL, &sigs);
		if (r > 0) return LN_OK;
		if (r == 0) {
			if (sigs & SIGBREAKF_CTRL_C) return LN_EBREAK;
			return LN_ETIMEDOUT;
		}
		return map_errno(Errno());
	}
}

static void to_sin(const LnAddr *a, struct sockaddr_in *sa)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin_len = sizeof(*sa);
	sa->sin_family = AF_INET;
	sa->sin_port = a->port;            /* big-endian host: htons is a no-op */
	memcpy(&sa->sin_addr, a->a, 4);
}

int ln_tcp_connect(const char *host, u16 port, int timeout_ms, LnSock **out)
{
	LnAddr a[4];
	int n = ln_resolve(host, a, 4), i, last = LN_ECONNREFUSED;
	if (n < 0) return n;
	for (i = 0; i < n; i++) {
		struct sockaddr_in sa;
		LONG fd, one = 1, zero = 0, r;
		a[i].port = port;
		to_sin(&a[i], &sa);
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) { last = map_errno(Errno()); continue; }
		IoctlSocket(fd, FIONBIO, (char *)&one);
		r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
		if (r < 0) {
			LONG e = Errno();
			if (e == 36 || e == 35) {          /* EINPROGRESS / EWOULDBLOCK */
				LONG err = 0, el = sizeof(err);
				r = wait_fd(fd, 1, timeout_ms);
				if (r == LN_OK) {
					getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
					r = err ? map_errno(err) : LN_OK;
				}
			} else
				r = map_errno(e);
		}
		if (r != LN_OK) { CloseSocket(fd); last = (int)r; continue; }
		IoctlSocket(fd, FIONBIO, (char *)&zero);
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
		*out = ln_alloc(sizeof(LnSock));
		if (!*out) { CloseSocket(fd); return LN_ENOMEM; }
		(*out)->fd = fd;
		return LN_OK;
	}
	return last;
}

int ln_tcp_send(LnSock *s, const void *buf, size_t n, int timeout_ms)
{
	const u8 *p = buf;
	while (n) {
		LONG r;
		int w = wait_fd(s->fd, 1, timeout_ms);
		if (w) return w;
		r = send(s->fd, (APTR)p, (LONG)n, 0);
		if (r < 0) {
			LONG e = Errno();
			if (e == 35 || e == 4) continue;
			return map_errno(e);
		}
		p += r; n -= (size_t)r;
	}
	return LN_OK;
}

int ln_tcp_recv_some(LnSock *s, void *buf, size_t n, int timeout_ms)
{
	for (;;) {
		LONG r;
		int w = wait_fd(s->fd, 0, timeout_ms);
		if (w) return w;
		r = recv(s->fd, buf, (LONG)n, 0);
		if (r < 0) {
			LONG e = Errno();
			if (e == 35) continue;
			return map_errno(e);
		}
		return (int)r;
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
	struct sockaddr_in sa;
	LONG len = sizeof(sa);
	if (getsockname(s->fd, (struct sockaddr *)&sa, &len) < 0) return map_errno(Errno());
	memset(out, 0, sizeof(*out));
	out->family = 4;
	memcpy(out->a, &sa.sin_addr, 4);
	out->port = sa.sin_port;
	return LN_OK;
}

void ln_sock_close(LnSock *s)
{
	if (!s) return;
	CloseSocket(s->fd);
	ln_free(s);
}

int ln_udp_open(u16 port, const LnAddr *grp, LnSock **out)
{
	struct sockaddr_in sa;
	LONG fd = socket(AF_INET, SOCK_DGRAM, 0), one = 1;
	if (fd < 0) return map_errno(Errno());
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_len = sizeof(sa);
	sa.sin_family = AF_INET;
	sa.sin_port = port;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { int e = map_errno(Errno()); CloseSocket(fd); return e; }
	if (grp) {
		struct ip_mreq m;
		memcpy(&m.imr_multiaddr, grp->a, 4);
		m.imr_interface.s_addr = INADDR_ANY;
		setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof(m));
	}
	*out = ln_alloc(sizeof(LnSock));
	if (!*out) { CloseSocket(fd); return LN_ENOMEM; }
	(*out)->fd = fd;
	return LN_OK;
}

int ln_udp_sendto(LnSock *s, const LnAddr *to, const void *buf, size_t n)
{
	struct sockaddr_in sa;
	to_sin(to, &sa);
	if (sendto(s->fd, (APTR)buf, (LONG)n, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) return map_errno(Errno());
	return (int)n;
}

int ln_udp_recvfrom(LnSock *s, LnAddr *from, void *buf, size_t n, int timeout_ms)
{
	struct sockaddr_in sa;
	LONG len = sizeof(sa), r;
	int w = wait_fd(s->fd, 0, timeout_ms);
	if (w) return w;
	r = recvfrom(s->fd, buf, (LONG)n, 0, (struct sockaddr *)&sa, &len);
	if (r < 0) return map_errno(Errno());
	if (from) {
		memset(from, 0, sizeof(*from));
		from->family = 4;
		memcpy(from->a, &sa.sin_addr, 4);
		from->port = sa.sin_port;
	}
	return (int)r;
}

int ln_udp_broadcast(LnSock *s, int on)
{
	LONG v = on;
	return setsockopt(s->fd, SOL_SOCKET, SO_BROADCAST, &v, sizeof(v)) < 0 ? map_errno(Errno()) : LN_OK;
}
