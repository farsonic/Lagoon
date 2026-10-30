/*
 * Lagoon - string helpers, a small snprintf (the same output with gcc and
 * vbcc, and usable from the handler without the C library's stdio), errors.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdarg.h>
#include "ln_types.h"
#include "ln_err.h"
#include "ln_sys.h"

size_t ln_strlcpy(char *dst, const char *src, size_t n)
{
	size_t l = strlen(src);
	if (n) {
		size_t c = l < n - 1 ? l : n - 1;
		memcpy(dst, src, c);
		dst[c] = 0;
	}
	return l;
}

size_t ln_strlcat(char *dst, const char *src, size_t n)
{
	size_t d = strlen(dst);
	if (d >= n)
		return d + strlen(src);
	return d + ln_strlcpy(dst + d, src, n - d);
}

static int lc(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

int ln_strcasecmp(const char *a, const char *b)
{
	while (*a && lc((u8)*a) == lc((u8)*b)) { a++; b++; }
	return lc((u8)*a) - lc((u8)*b);
}

int ln_strncasecmp(const char *a, const char *b, size_t n)
{
	while (n && *a && lc((u8)*a) == lc((u8)*b)) { a++; b++; n--; }
	return n ? lc((u8)*a) - lc((u8)*b) : 0;
}

char *ln_strdup(const char *s)
{
	size_t l = strlen(s);
	char *p = ln_alloc(l + 1);
	if (p)
		memcpy(p, s, l + 1);
	return p;
}

int ln_memeq_ct(const void *a, const void *b, size_t n)
{
	const u8 *x = a, *y = b;
	u8 d = 0;
	while (n--)
		d |= *x++ ^ *y++;
	return d == 0;
}

void ln_wipe(void *p, size_t n)
{
	volatile u8 *v = p;
	while (n--)
		*v++ = 0;
}

/* ---- formatter: %[-][0][width][.prec][l|ll|z]{d,i,u,x,X,s,c,p,%} ---- */
typedef struct { char *buf; size_t n, len; } Out;

static void put(Out *o, char c)
{
	if (o->len + 1 < o->n)
		o->buf[o->len] = c;
	o->len++;
}

static void pad(Out *o, int k, char c) { while (k-- > 0) put(o, c); }

int ln_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);
int ln_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap)
{
	Out o;
	o.buf = buf; o.n = n; o.len = 0;
	for (; *fmt; fmt++) {
		int left = 0, zero = 0, width = 0, prec = -1, lng = 0;
		char tmp[24];
		const char *s;
		int sl, neg = 0;
		u64 v;
		if (*fmt != '%') { put(&o, *fmt); continue; }
		fmt++;
		for (;; fmt++) {
			if (*fmt == '-') left = 1;
			else if (*fmt == '0') zero = 1;
			else break;
		}
		if (*fmt == '*') { width = va_arg(ap, int); fmt++; if (width < 0) { left = 1; width = -width; } }
		else while (*fmt >= '0' && *fmt <= '9') width = width * 10 + (*fmt++ - '0');
		if (*fmt == '.') {
			fmt++; prec = 0;
			if (*fmt == '*') { prec = va_arg(ap, int); fmt++; }
			else while (*fmt >= '0' && *fmt <= '9') prec = prec * 10 + (*fmt++ - '0');
		}
		while (*fmt == 'l' || *fmt == 'z' || *fmt == 'h') { if (*fmt == 'l') lng++; else if (*fmt == 'z') lng = 1; fmt++; }
		switch (*fmt) {
		case 'd': case 'i':
			{
				s64 x = lng >= 2 ? va_arg(ap, s64) : lng ? (s64)va_arg(ap, long) : (s64)va_arg(ap, int);
				if (x < 0) { neg = 1; v = (u64)(-x); } else v = (u64)x;
			}
			goto num10;
		case 'u':
			v = lng >= 2 ? va_arg(ap, u64) : lng ? (u64)va_arg(ap, unsigned long) : (u64)va_arg(ap, unsigned);
		num10:
			sl = 0;
			do { tmp[sl++] = (char)('0' + (int)(v % 10)); v /= 10; } while (v);
			goto emit;
		case 'x': case 'X': case 'p':
			if (*fmt == 'p') { v = (u64)(size_t)va_arg(ap, void *); }
			else v = lng >= 2 ? va_arg(ap, u64) : lng ? (u64)va_arg(ap, unsigned long) : (u64)va_arg(ap, unsigned);
			sl = 0;
			do { int d = (int)(v & 15); tmp[sl++] = (char)(d < 10 ? '0' + d : (*fmt == 'X' ? 'A' : 'a') + d - 10); v >>= 4; } while (v);
		emit:
			{
				int digits = sl, total;
				if (prec > digits) digits = prec;
				total = digits + neg;
				if (!left && !zero) pad(&o, width - total, ' ');
				if (neg) put(&o, '-');
				if (!left && zero) pad(&o, width - total, '0');
				pad(&o, digits - sl, '0');
				while (sl) put(&o, tmp[--sl]);
				if (left) pad(&o, width - total, ' ');
			}
			break;
		case 's':
			s = va_arg(ap, const char *);
			if (!s) s = "(null)";
			sl = 0;
			while (s[sl] && (prec < 0 || sl < prec)) sl++;
			if (!left) pad(&o, width - sl, ' ');
			{ int i; for (i = 0; i < sl; i++) put(&o, s[i]); }
			if (left) pad(&o, width - sl, ' ');
			break;
		case 'c':
			if (!left) pad(&o, width - 1, ' ');
			put(&o, (char)va_arg(ap, int));
			if (left) pad(&o, width - 1, ' ');
			break;
		case '%': put(&o, '%'); break;
		case 0: fmt--; break;
		default: put(&o, '%'); put(&o, *fmt); break;
		}
	}
	if (n)
		buf[o.len < n ? o.len : n - 1] = 0;
	return (int)o.len;
}

int ln_snprintf(char *buf, size_t n, const char *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap, fmt);
	r = ln_vsnprintf(buf, n, fmt, ap);
	va_end(ap);
	return r;
}

const char *ln_strerror(int err)
{
	switch (err) {
	case LN_OK: return "no error";
	case LN_ENOENT: return "object not found";
	case LN_EEXIST: return "object already exists";
	case LN_ENOTDIR: return "not a directory";
	case LN_EISDIR: return "is a directory";
	case LN_ENOTEMPTY: return "directory not empty";
	case LN_EACCES: return "permission denied";
	case LN_EROFS: return "share is read-only";
	case LN_ENOSPC: return "disk full";
	case LN_EINUSE: return "object in use";
	case LN_EINVAL: return "invalid argument";
	case LN_ENAMETOOLONG: return "name too long";
	case LN_ENOMEM: return "out of memory";
	case LN_EIO: return "I/O error";
	case LN_EPROTO: return "protocol error";
	case LN_ENOTSUP: return "not supported by the server";
	case LN_EAUTH: return "logon failed (user name or password)";
	case LN_ETIMEDOUT: return "timed out";
	case LN_ECONNREFUSED: return "connection refused";
	case LN_ECONNRESET: return "connection lost";
	case LN_EHOSTUNREACH: return "host unreachable";
	case LN_ENOHOST: return "host name not found";
	case LN_EBREAK: return "interrupted";
	case LN_ENOSHARE: return "share not found";
	case LN_ESTALE: return "stale file handle";
	case LN_ECRYPTO: return "signature or decryption check failed";
	case LN_ENONET: return "no TCP/IP stack running (bsdsocket.library)";
	}
	return "unknown error";
}
