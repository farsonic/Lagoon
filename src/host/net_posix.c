/*
 * Lagoon - ln_net.h with BSD sockets on Linux.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "../core/ln_net.h"
#include "../core/ln_sys.h"

struct LnSock { int fd; };

int ln_net_init(void) { return LN_OK; }
void ln_net_exit(void) { }

static int map_errno(int e)
{
	switch (e) {
	case ECONNREFUSED: return LN_ECONNREFUSED;
	case ETIMEDOUT: return LN_ETIMEDOUT;
	case EHOSTUNREACH: case ENETUNREACH: return LN_EHOSTUNREACH;
	case ECONNRESET: case EPIPE: case ENOTCONN: return LN_ECONNRESET;
	case ENOMEM: case ENOBUFS: return LN_ENOMEM;
	}
	return LN_EIO;
}

static void to_sa(const LnAddr *a, struct sockaddr_storage *ss, socklen_t *len)
{
	memset(ss, 0, sizeof(*ss));
	if (a->family == 6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
		s6->sin6_family = AF_INET6;
		memcpy(&s6->sin6_addr, a->a, 16);
		s6->sin6_port = htons(a->port);
		*len = sizeof(*s6);
	} else {
		struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
		s4->sin_family = AF_INET;
		memcpy(&s4->sin_addr, a->a, 4);
		s4->sin_port = htons(a->port);
		*len = sizeof(*s4);
	}
}

static void from_sa(const struct sockaddr *sa, LnAddr *a)
{
	memset(a, 0, sizeof(*a));
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
		a->family = 6;
		memcpy(a->a, &s6->sin6_addr, 16);
		a->port = ntohs(s6->sin6_port);
	} else {
		const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
		a->family = 4;
		memcpy(a->a, &s4->sin_addr, 4);
		a->port = ntohs(s4->sin_port);
	}
}

int ln_resolve(const char *host, LnAddr *out, int max)
{
	struct addrinfo hints, *res, *ai;
	int n = 0;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, NULL, &hints, &res) != 0)
		return LN_ENOHOST;
	for (ai = res; ai && n < max; ai = ai->ai_next)
		from_sa(ai->ai_addr, &out[n++]);
	freeaddrinfo(res);
	return n ? n : LN_ENOHOST;
}

void ln_addr_str(const LnAddr *a, char *buf, size_t n)
{
	if (!inet_ntop(a->family == 6 ? AF_INET6 : AF_INET, a->a, buf, (socklen_t)n) && n)
		buf[0] = 0;
}

static int wait_fd(int fd, int events, int timeout_ms)
{
	struct pollfd p;
	int r;
	p.fd = fd; p.events = (short)events; p.revents = 0;
	do r = poll(&p, 1, timeout_ms > 0 ? timeout_ms : -1); while (r < 0 && errno == EINTR);
	if (r == 0) return LN_ETIMEDOUT;
	if (r < 0) return map_errno(errno);
	return LN_OK;
}

int ln_tcp_connect(const char *host, u16 port, int timeout_ms, LnSock **out)
{
	LnAddr a[8];
	int n = ln_resolve(host, a, 8), i, last = LN_ECONNREFUSED;
	if (n < 0) return n;
	for (i = 0; i < n; i++) {
		struct sockaddr_storage ss;
		socklen_t len;
		int fd, fl, one = 1, r;
		a[i].port = port;
		to_sa(&a[i], &ss, &len);
		fd = socket(ss.ss_family, SOCK_STREAM, 0);
		if (fd < 0) { last = map_errno(errno); continue; }
		fl = fcntl(fd, F_GETFL);
		fcntl(fd, F_SETFL, fl | O_NONBLOCK);
		r = connect(fd, (struct sockaddr *)&ss, len);
		if (r < 0 && errno == EINPROGRESS) {
			int err = 0;
			socklen_t el = sizeof(err);
			r = wait_fd(fd, POLLOUT, timeout_ms);
			if (r == LN_OK) {
				getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
				r = err ? map_errno(err) : LN_OK;
			}
		} else if (r < 0)
			r = map_errno(errno);
		if (r != LN_OK) { close(fd); last = r; continue; }
		fcntl(fd, F_SETFL, fl);
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
		*out = ln_alloc(sizeof(LnSock));
		if (!*out) { close(fd); return LN_ENOMEM; }
		(*out)->fd = fd;
		return LN_OK;
	}
	return last;
}

int ln_tcp_send(LnSock *s, const void *buf, size_t n, int timeout_ms)
{
	const u8 *p = buf;
	while (n) {
		ssize_t r;
		int w = wait_fd(s->fd, POLLOUT, timeout_ms);
		if (w) return w;
		r = send(s->fd, p, n, MSG_NOSIGNAL);
		if (r < 0) { if (errno == EINTR || errno == EAGAIN) continue; return map_errno(errno); }
		p += r; n -= (size_t)r;
	}
	return LN_OK;
}

int ln_tcp_recv_some(LnSock *s, void *buf, size_t n, int timeout_ms)
{
	for (;;) {
		ssize_t r;
		int w = wait_fd(s->fd, POLLIN, timeout_ms);
		if (w) return w;
		r = recv(s->fd, buf, n, 0);
		if (r < 0) { if (errno == EINTR || errno == EAGAIN) continue; return map_errno(errno); }
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
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	if (getsockname(s->fd, (struct sockaddr *)&ss, &len) < 0) return map_errno(errno);
	from_sa((struct sockaddr *)&ss, out);
	return LN_OK;
}

void ln_sock_close(LnSock *s)
{
	if (!s) return;
	close(s->fd);
	ln_free(s);
}

int ln_udp_open(u16 port, const LnAddr *grp, LnSock **out)
{
	struct sockaddr_in sa;
	int fd = socket(AF_INET, SOCK_DGRAM, 0), one = 1;
	if (fd < 0) return map_errno(errno);
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { int e = map_errno(errno); close(fd); return e; }
	if (grp) {
		struct ip_mreq m;
		memcpy(&m.imr_multiaddr, grp->a, 4);
		unsigned char ttl = 255;
		m.imr_interface.s_addr = htonl(INADDR_ANY);
		setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof(m));
		setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));   /* RFC 6762 11 */
	}
	*out = ln_alloc(sizeof(LnSock));
	if (!*out) { close(fd); return LN_ENOMEM; }
	(*out)->fd = fd;
	return LN_OK;
}

int ln_udp_sendto(LnSock *s, const LnAddr *to, const void *buf, size_t n)
{
	struct sockaddr_storage ss;
	socklen_t len;
	to_sa(to, &ss, &len);
	if (sendto(s->fd, buf, n, 0, (struct sockaddr *)&ss, len) < 0) return map_errno(errno);
	return (int)n;
}

int ln_udp_recvfrom(LnSock *s, LnAddr *from, void *buf, size_t n, int timeout_ms)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	ssize_t r;
	int w = wait_fd(s->fd, POLLIN, timeout_ms);
	if (w) return w;
	r = recvfrom(s->fd, buf, n, 0, (struct sockaddr *)&ss, &len);
	if (r < 0) return map_errno(errno);
	if (from) from_sa((struct sockaddr *)&ss, from);
	return (int)r;
}

int ln_udp_broadcast(LnSock *s, int on)
{
	return setsockopt(s->fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0 ? map_errno(errno) : LN_OK;
}

/* ---- nfs: connect from a reserved port (1023 downwards to 600) ---- */
int ln_tcp_connect_reserved(const char *host, u16 port, int timeout_ms, LnSock **out)
{
	LnAddr a[8];
	int n = ln_resolve(host, a, 8), i, lport, last = LN_EACCES;
	if (n < 0) return n;
	for (i = 0; i < n; i++) {
		a[i].port = port;
		for (lport = 1023; lport >= 600; lport--) {
			struct sockaddr_storage ss, ls;
			socklen_t len, llen;
			LnAddr la;
			int fd, fl, one = 1, r;
			to_sa(&a[i], &ss, &len);
			memset(&la, 0, sizeof(la));
			la.family = a[i].family;
			la.port = (u16)lport;
			to_sa(&la, &ls, &llen);
			fd = socket(ss.ss_family, SOCK_STREAM, 0);
			if (fd < 0) return map_errno(errno);
			setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
			if (bind(fd, (struct sockaddr *)&ls, llen) < 0) {
				int e = errno;
				close(fd);
				if (e == EACCES || e == EPERM) return LN_EACCES;
				continue;                    /* port in use */
			}
			fl = fcntl(fd, F_GETFL);
			fcntl(fd, F_SETFL, fl | O_NONBLOCK);
			r = connect(fd, (struct sockaddr *)&ss, len);
			if (r < 0 && errno == EINPROGRESS) {
				int err = 0;
				socklen_t el = sizeof(err);
				r = wait_fd(fd, POLLOUT, timeout_ms);
				if (r == LN_OK) {
					getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
					if (err == EADDRINUSE || err == EADDRNOTAVAIL) { close(fd); continue; }
					r = err ? map_errno(err) : LN_OK;
				}
			} else if (r < 0) {
				if (errno == EADDRINUSE || errno == EADDRNOTAVAIL) { close(fd); continue; }
				r = map_errno(errno);
			}
			if (r != LN_OK) { close(fd); last = r; break; }   /* next address */
			fcntl(fd, F_SETFL, fl);
			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
			*out = ln_alloc(sizeof(LnSock));
			if (!*out) { close(fd); return LN_ENOMEM; }
			(*out)->fd = fd;
			return LN_OK;
		}
	}
	return last;
}

/* ---- server side ---- */
int ln_tcp_listen(u16 port, LnSock **out)
{
	struct sockaddr_in sa;
	int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	if (fd < 0) return map_errno(errno);
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(fd, 8) < 0) {
		int e = errno;
		close(fd);
		return e == EADDRINUSE ? LN_EINUSE : e == EACCES ? LN_EACCES : map_errno(e);
	}
	*out = ln_alloc(sizeof(LnSock));
	if (!*out) { close(fd); return LN_ENOMEM; }
	(*out)->fd = fd;
	return LN_OK;
}

int ln_tcp_accept(LnSock *l, LnSock **out, LnAddr *peer)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	int fd, one = 1;
	do fd = accept(l->fd, (struct sockaddr *)&ss, &len); while (fd < 0 && errno == EINTR);
	if (fd < 0) return map_errno(errno);
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (peer) from_sa((struct sockaddr *)&ss, peer);
	*out = ln_alloc(sizeof(LnSock));
	if (!*out) { close(fd); return LN_ENOMEM; }
	(*out)->fd = fd;
	return LN_OK;
}

int ln_net_poll(LnSock *const *s, int n, u8 *ready, int timeout_ms)
{
	struct pollfd p[80];
	int i, r, k = 0;
	if (n > 80) n = 80;
	for (i = 0; i < n; i++) {
		p[i].fd = s[i] ? s[i]->fd : -1;
		p[i].events = POLLIN;
		p[i].revents = 0;
		ready[i] = 0;
	}
	do r = poll(p, (nfds_t)n, timeout_ms); while (r < 0 && errno == EINTR);
	if (r < 0) return map_errno(errno);
	for (i = 0; i < n; i++)
		if (p[i].revents & (POLLIN | POLLHUP | POLLERR)) { ready[i] = 1; k++; }
	return k;
}

int ln_local_addr(LnAddr *out)
{
	struct sockaddr_in sa;
	socklen_t len = sizeof(sa);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return LN_ENOHOST;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(5353);
	sa.sin_addr.s_addr = htonl(0xe00000fbu);      /* 224.0.0.251: the LAN interface */
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
	    getsockname(fd, (struct sockaddr *)&sa, &len) < 0 || sa.sin_addr.s_addr == 0) {
		close(fd);
		memset(out, 0, sizeof(*out));
		out->family = 4;
		out->a[0] = 127; out->a[3] = 1;
		return LN_OK;
	}
	close(fd);
	from_sa((struct sockaddr *)&sa, out);
	out->port = 0;
	return LN_OK;
}
