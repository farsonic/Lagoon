/*
 * Lagoon - UTF-8 / UTF-16LE / Latin-1 conversion, Latin NFC/NFD and the
 * reversible mapping between remote names and Amiga file names.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "ln_charset.h"
#include "ln_nfc_table.h"

int ln_utf8_decode(const char *s, size_t n, u32 *cp)
{
	const u8 *p = (const u8 *)s;
	u32 c;
	int len, i;
	if (!n) { *cp = 0xFFFD; return 1; }
	c = p[0];
	if (c < 0x80) { *cp = c; return 1; }
	if ((c & 0xE0) == 0xC0) { len = 2; c &= 0x1F; }
	else if ((c & 0xF0) == 0xE0) { len = 3; c &= 0x0F; }
	else if ((c & 0xF8) == 0xF0) { len = 4; c &= 0x07; }
	else { *cp = 0xFFFD; return 1; }
	if ((size_t)len > n) { *cp = 0xFFFD; return 1; }
	for (i = 1; i < len; i++) {
		if ((p[i] & 0xC0) != 0x80) { *cp = 0xFFFD; return i; }
		c = (c << 6) | (p[i] & 0x3F);
	}
	if ((len == 2 && c < 0x80) || (len == 3 && c < 0x800) || (len == 4 && (c < 0x10000 || c > 0x10FFFF)) ||
	    (c >= 0xD800 && c <= 0xDFFF))
		c = 0xFFFD;
	*cp = c;
	return len;
}

int ln_utf8_encode(u32 c, char *o)
{
	if (c < 0x80) { o[0] = (char)c; return 1; }
	if (c < 0x800) { o[0] = (char)(0xC0 | (c >> 6)); o[1] = (char)(0x80 | (c & 0x3F)); return 2; }
	if (c < 0x10000) {
		o[0] = (char)(0xE0 | (c >> 12)); o[1] = (char)(0x80 | ((c >> 6) & 0x3F)); o[2] = (char)(0x80 | (c & 0x3F));
		return 3;
	}
	o[0] = (char)(0xF0 | (c >> 18)); o[1] = (char)(0x80 | ((c >> 12) & 0x3F));
	o[2] = (char)(0x80 | ((c >> 6) & 0x3F)); o[3] = (char)(0x80 | (c & 0x3F));
	return 4;
}

int ln_utf8_to_utf16le(const char *in, size_t inlen, u8 *out, size_t outmax)
{
	size_t i = 0, k = 0;
	while (i < inlen) {
		u32 c;
		i += (size_t)ln_utf8_decode(in + i, inlen - i, &c);
		if (c >= 0x10000) {
			if (k + 4 > outmax) return -1;
			c -= 0x10000;
			ln_put_le16(out + k, (u16)(0xD800 | (c >> 10)));
			ln_put_le16(out + k + 2, (u16)(0xDC00 | (c & 0x3FF)));
			k += 4;
		} else {
			if (k + 2 > outmax) return -1;
			ln_put_le16(out + k, (u16)c);
			k += 2;
		}
	}
	return (int)k;
}

int ln_utf16le_to_utf8(const u8 *in, size_t inbytes, char *out, size_t outmax)
{
	size_t i = 0, k = 0;
	char tmp[4];
	while (i + 1 < inbytes) {
		u32 c = ln_le16(in + i);
		int l;
		i += 2;
		if (c >= 0xD800 && c < 0xDC00 && i + 1 < inbytes) {
			u32 d = ln_le16(in + i);
			if (d >= 0xDC00 && d < 0xE000) {
				c = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00);
				i += 2;
			} else
				c = 0xFFFD;
		} else if (c >= 0xD800 && c < 0xE000)
			c = 0xFFFD;
		l = ln_utf8_encode(c, tmp);
		if (k + (size_t)l + 1 > outmax) return -1;
		memcpy(out + k, tmp, (size_t)l);
		k += (size_t)l;
	}
	if (k + 1 > outmax) return -1;
	out[k] = 0;
	return (int)k;
}

/* ---- Latin NFC / NFD ---- */
static int is_mark(u32 c) { return c >= 0x300 && c < 0x370; }

static u32 compose(u32 base, u32 mark)
{
	size_t i;
	for (i = 0; i < LN_ARRAY_SIZE(ln_nfc_table); i++)
		if (ln_nfc_table[i][1] == base && ln_nfc_table[i][2] == mark)
			return ln_nfc_table[i][0];
	return 0;
}

static int decompose(u32 c, u32 *base, u32 *mark)
{
	size_t lo = 0, hi = LN_ARRAY_SIZE(ln_nfc_table);
	while (lo < hi) {
		size_t mid = (lo + hi) / 2;
		if (ln_nfc_table[mid][0] == c) {
			*base = ln_nfc_table[mid][1];
			*mark = ln_nfc_table[mid][2];
			return 1;
		}
		if (ln_nfc_table[mid][0] < c) lo = mid + 1; else hi = mid;
	}
	return 0;
}

int ln_utf8_nfc(const char *in, char *out, size_t outmax)
{
	size_t n = strlen(in), i = 0, k = 0;
	u32 pend = 0;
	int have = 0;
	char tmp[4];
	while (i < n) {
		u32 c, m;
		i += (size_t)ln_utf8_decode(in + i, n - i, &c);
		if (have && is_mark(c) && (m = compose(pend, c)) != 0) {
			pend = m;
			continue;
		}
		if (have) {
			int l = ln_utf8_encode(pend, tmp);
			if (k + (size_t)l >= outmax) return -1;
			memcpy(out + k, tmp, (size_t)l); k += (size_t)l;
		}
		pend = c; have = 1;
	}
	if (have) {
		int l = ln_utf8_encode(pend, tmp);
		if (k + (size_t)l >= outmax) return -1;
		memcpy(out + k, tmp, (size_t)l); k += (size_t)l;
	}
	if (k >= outmax) return -1;
	out[k] = 0;
	return (int)k;
}

int ln_utf8_nfd(const char *in, char *out, size_t outmax)
{
	size_t n = strlen(in), i = 0, k = 0;
	char tmp[4];
	while (i < n) {
		u32 c, seq[4];
		int ns = 0, j;
		i += (size_t)ln_utf8_decode(in + i, n - i, &c);
		/* decompose repeatedly: marks come out in reverse order */
		while (ns < 3) {
			u32 b, m;
			if (!decompose(c, &b, &m))
				break;
			seq[ns++] = m;
			c = b;
		}
		seq[ns++] = c;
		for (j = ns - 1; j >= 0; j--) {
			int l = ln_utf8_encode(seq[j], tmp);
			if (k + (size_t)l >= outmax) return -1;
			memcpy(out + k, tmp, (size_t)l); k += (size_t)l;
		}
	}
	if (k >= outmax) return -1;
	out[k] = 0;
	return (int)k;
}

/* ---- Amiga names ---- */
static const char hx[] = "0123456789ABCDEF";

int ln_name_to_amiga(const char *utf8, char *out, size_t outmax)
{
	char nfc[512];
	const char *s = utf8;
	size_t n, i = 0, k = 0;
	if (ln_utf8_nfc(utf8, nfc, sizeof(nfc)) >= 0)
		s = nfc;
	n = strlen(s);
	while (i < n) {
		u32 c;
		int l = ln_utf8_decode(s + i, n - i, &c), j;
		if (c >= 0x20 && c <= 0xFF && c != ':' && c != '/' && c != '%' && !(c >= 0x7F && c < 0xA0)) {
			if (k + 1 >= outmax) return -1;
			out[k++] = (char)c;
		} else {
			for (j = 0; j < l; j++) {
				u8 b = (u8)s[i + j];
				if (k + 3 >= outmax) return -1;
				out[k++] = '%'; out[k++] = hx[b >> 4]; out[k++] = hx[b & 15];
			}
		}
		i += (size_t)l;
	}
	out[k] = 0;
	return (int)k;
}

static int hv(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

int ln_name_from_amiga(const char *a, char *out, size_t outmax)
{
	size_t k = 0;
	char tmp[4];
	while (*a) {
		u8 c = (u8)*a;
		if (c == '%' && hv((u8)a[1]) >= 0 && hv((u8)a[2]) >= 0) {
			if (k + 1 >= outmax) return -1;
			out[k++] = (char)(hv((u8)a[1]) * 16 + hv((u8)a[2]));
			a += 3;
			continue;
		}
		{
			int l = ln_utf8_encode(c, tmp);
			if (k + (size_t)l >= outmax) return -1;
			memcpy(out + k, tmp, (size_t)l);
			k += (size_t)l;
		}
		a++;
	}
	out[k] = 0;
	return (int)k;
}

static int lat1_lower(int c)
{
	if ((c >= 'A' && c <= 'Z') || (c >= 0xC0 && c <= 0xDE && c != 0xD7))
		return c + 32;
	return c;
}

int ln_amiga_stricmp(const char *a, const char *b)
{
	while (*a && lat1_lower((u8)*a) == lat1_lower((u8)*b)) { a++; b++; }
	return lat1_lower((u8)*a) - lat1_lower((u8)*b);
}

int ln_latin1_to_utf8(const char *in, char *out, size_t outmax)
{
	size_t k = 0;
	for (; *in; in++) {
		u8 c = (u8)*in;
		if (c < 0x80) {
			if (k + 1 >= outmax) return -1;
			out[k++] = (char)c;
		} else {
			if (k + 2 >= outmax) return -1;
			out[k++] = (char)(0xc0 | (c >> 6));
			out[k++] = (char)(0x80 | (c & 0x3f));
		}
	}
	if (k >= outmax) return -1;
	out[k] = 0;
	return (int)k;
}

int ln_utf8_to_latin1(const char *in, char *out, size_t outmax)
{
	size_t k = 0, n = strlen(in), i = 0;
	while (i < n) {
		u32 cp;
		int used = ln_utf8_decode(in + i, n - i, &cp);
		if (cp > 0xff || cp == 0)
			return -1;
		if (k + 1 >= outmax) return -1;
		out[k++] = (char)cp;
		i += (size_t)used;
	}
	if (k >= outmax) return -1;
	out[k] = 0;
	return (int)k;
}
