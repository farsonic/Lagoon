/*
 * Lagoon - URL parsing (see ln_url.h for the accepted forms).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "ln_url.h"
#include "ln_err.h"

static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* copy [s, e) percent-decoded into out; LN_EINVAL if it does not fit */
static int dec(const char *s, const char *e, char *out, size_t n)
{
	size_t k = 0;
	while (s < e) {
		int c = (u8)*s++;
		if (c == '%' && e - s >= 2 && hexval(s[0]) >= 0 && hexval(s[1]) >= 0) {
			c = hexval(s[0]) * 16 + hexval(s[1]);
			s += 2;
		}
		if (k + 1 >= n)
			return LN_EINVAL;
		out[k++] = (char)c;
	}
	out[k] = 0;
	return LN_OK;
}

static const char *find(const char *s, const char *e, char c)
{
	for (; s < e; s++)
		if (*s == c)
			return s;
	return NULL;
}

int ln_url_parse(const char *str, LnUrl *u)
{
	const char *p = str, *e, *auth_end, *host_s, *host_e, *q;
	size_t i;

	memset(u, 0, sizeof(*u));
	e = strstr(p, "://");
	if (!e || e == p || (size_t)(e - p) >= sizeof(u->scheme))
		return LN_EINVAL;
	for (i = 0; p + i < e; i++) {
		char c = p[i];
		u->scheme[i] = (char)((c >= 'A' && c <= 'Z') ? c + 32 : c);
	}
	if (!strcmp(u->scheme, "cifs"))
		strcpy(u->scheme, "smb");
	p = e + 3;

	/* options */
	q = strchr(p, '?');
	e = q ? q : p + strlen(p);
	if (q && dec(q + 1, q + 1 + strlen(q + 1), u->opts, sizeof(u->opts)))
		return LN_EINVAL;

	/* authority ends at the first '/' */
	auth_end = find(p, e, '/');
	if (!auth_end)
		auth_end = e;
	/* userinfo: last '@' in the authority */
	{
		const char *at = NULL, *t;
		for (t = p; t < auth_end; t++)
			if (*t == '@')
				at = t;
		host_s = p;
		if (at) {
			const char *ui = p, *semi = find(p, at, ';'), *colon;
			if (semi) {
				if (dec(ui, semi, u->domain, sizeof(u->domain)))
					return LN_EINVAL;
				ui = semi + 1;
			}
			colon = find(ui, at, ':');
			if (dec(ui, colon ? colon : at, u->user, sizeof(u->user)))
				return LN_EINVAL;
			if (colon && dec(colon + 1, at, u->password, sizeof(u->password)))
				return LN_EINVAL;
			host_s = at + 1;
		}
	}
	/* host[:port], [v6]:port */
	host_e = auth_end;
	if (*host_s == '[') {
		const char *rb = find(host_s, auth_end, ']');
		if (!rb)
			return LN_EINVAL;
		if (dec(host_s + 1, rb, u->host, sizeof(u->host)))
			return LN_EINVAL;
		host_e = rb + 1;
	} else {
		const char *colon = find(host_s, auth_end, ':');
		if (colon)
			host_e = colon;
		if (dec(host_s, host_e, u->host, sizeof(u->host)))
			return LN_EINVAL;
	}
	if (host_e < auth_end) {
		long port = 0;
		const char *t;
		if (*host_e != ':' || host_e + 1 == auth_end)
			return LN_EINVAL;
		for (t = host_e + 1; t < auth_end; t++) {
			if (*t < '0' || *t > '9')
				return LN_EINVAL;
			port = port * 10 + (*t - '0');
			if (port > 65535)
				return LN_EINVAL;
		}
		u->port = (u16)port;
	}
	if (!u->host[0])
		return LN_EINVAL;

	/* path: share is the first component, except nfs (the whole path) */
	p = auth_end;
	while (p < e && *p == '/')
		p++;
	{
		const char *pe = e;
		while (pe > p && pe[-1] == '/')
			pe--;
		if (!strcmp(u->scheme, "nfs")) {
			if (pe > p) {
				u->share[0] = '/';
				if (dec(p, pe, u->share + 1, sizeof(u->share) - 1))
					return LN_EINVAL;
			}
		} else {
			const char *sl = find(p, pe, '/');
			if (dec(p, sl ? sl : pe, u->share, sizeof(u->share)))
				return LN_EINVAL;
			if (sl) {
				while (sl < pe && *sl == '/')
					sl++;
				if (dec(sl, pe, u->path, sizeof(u->path)))
					return LN_EINVAL;
			}
		}
	}
	return LN_OK;
}

static void enc(char *buf, size_t n, const char *s, const char *keep)
{
	static const char hx[] = "0123456789ABCDEF";
	size_t k = strlen(buf);
	for (; *s && k + 4 < n; s++) {
		u8 c = (u8)*s;
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		    strchr("-._~", c) || (c && strchr(keep, c)))
			buf[k++] = (char)c;
		else {
			buf[k++] = '%'; buf[k++] = hx[c >> 4]; buf[k++] = hx[c & 15];
		}
	}
	buf[k] = 0;
}

void ln_url_format(const LnUrl *u, char *buf, size_t n)
{
	char port[8];
	if (!n)
		return;
	buf[0] = 0;
	ln_strlcat(buf, u->scheme, n);
	ln_strlcat(buf, "://", n);
	if (u->user[0]) {
		if (u->domain[0]) {
			enc(buf, n, u->domain, "");
			ln_strlcat(buf, ";", n);
		}
		enc(buf, n, u->user, "");
		ln_strlcat(buf, "@", n);
	}
	if (strchr(u->host, ':')) {
		ln_strlcat(buf, "[", n);
		ln_strlcat(buf, u->host, n);
		ln_strlcat(buf, "]", n);
	} else
		enc(buf, n, u->host, "");
	if (u->port) {
		ln_snprintf(port, sizeof(port), ":%u", (unsigned)u->port);
		ln_strlcat(buf, port, n);
	}
	if (u->share[0]) {
		if (u->share[0] != '/')
			ln_strlcat(buf, "/", n);
		enc(buf, n, u->share, "/");
	}
	if (u->path[0]) {
		ln_strlcat(buf, "/", n);
		enc(buf, n, u->path, "/");
	}
	if (u->opts[0]) {
		ln_strlcat(buf, "?", n);
		ln_strlcat(buf, u->opts, n);
	}
}

const char *ln_url_opt(const LnUrl *u, const char *key, const char *def, char *buf, size_t n)
{
	const char *p = u->opts;
	size_t kl = strlen(key);
	while (*p) {
		const char *amp = strchr(p, '&');
		size_t l = amp ? (size_t)(amp - p) : strlen(p);
		if (l > kl && !ln_strncasecmp(p, key, kl) && p[kl] == '=') {
			size_t vl = l - kl - 1;
			if (vl >= n)
				vl = n - 1;
			memcpy(buf, p + kl + 1, vl);
			buf[vl] = 0;
			return buf;
		}
		if (l == kl && !ln_strncasecmp(p, key, kl)) {
			ln_strlcpy(buf, "yes", n);
			return buf;
		}
		p += l;
		if (*p == '&')
			p++;
	}
	return def;
}

int ln_url_opt_int(const LnUrl *u, const char *key, int def)
{
	char b[16];
	const char *v = ln_url_opt(u, key, NULL, b, sizeof(b));
	int x = 0, neg = 0;
	if (!v || !*v)
		return def;
	if (*v == '-') { neg = 1; v++; }
	while (*v >= '0' && *v <= '9')
		x = x * 10 + (*v++ - '0');
	return neg ? -x : x;
}
