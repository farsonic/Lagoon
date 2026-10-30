/*
 * Lagoon - share list file (format in ln_conf.h).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "ln_conf.h"
#include "ln_err.h"

static const u8 hide_key[] = "Lagoon/Amiga";
static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void ln_conf_hide(const char *plain, char *out, size_t n)
{
	size_t l = strlen(plain), i, k = 0;
	u8 t[3];
	if (n < 2) { if (n) out[0] = 0; return; }
	out[k++] = '~';
	for (i = 0; i < l; i += 3) {
		size_t j, m = LN_MIN(3, l - i);
		u32 v;
		for (j = 0; j < 3; j++)
			t[j] = j < m ? (u8)(plain[i + j] ^ hide_key[(i + j) % (sizeof(hide_key) - 1)]) : 0;
		v = ((u32)t[0] << 16) | ((u32)t[1] << 8) | t[2];
		if (k + 5 > n) break;
		out[k++] = b64[(v >> 18) & 63];
		out[k++] = b64[(v >> 12) & 63];
		out[k++] = m > 1 ? b64[(v >> 6) & 63] : '=';
		out[k++] = m > 2 ? b64[v & 63] : '=';
	}
	out[k] = 0;
}

static int b64v(int c)
{
	const char *p = c ? strchr(b64, c) : NULL;
	return p ? (int)(p - b64) : -1;
}

int ln_conf_unhide(const char *h, char *out, size_t n)
{
	size_t k = 0;
	u32 v = 0;
	int bits = 0;
	if (*h != '~')
		return (int)ln_strlcpy(out, h, n) < (int)n ? LN_OK : LN_EINVAL;
	for (h++; *h && *h != '='; h++) {
		int d = b64v((u8)*h);
		if (d < 0) return LN_EINVAL;
		v = (v << 6) | (u32)d;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (k + 1 >= n) return LN_EINVAL;
			out[k] = (char)(((v >> bits) & 0xFF) ^ hide_key[k % (sizeof(hide_key) - 1)]);
			k++;
		}
	}
	out[k] = 0;
	return LN_OK;
}

void ln_conf_init(LnConf *c)
{
	memset(c, 0, sizeof(*c));
	c->loglevel = 0;
}

/* next key=value pair on the line; returns 0 at end of line */
static int pair(const char **pp, char *key, size_t kn, char *val, size_t vn, int *bad)
{
	const char *p = *pp;
	size_t k = 0;
	while (*p == ' ' || *p == '\t') p++;
	if (!*p || *p == '\n' || *p == '\r' || *p == '#') { *pp = p; return 0; }
	while (*p && *p != '=' && *p != ' ' && *p != '\t' && *p != '\n') {
		if (k + 1 < kn) key[k++] = *p;
		p++;
	}
	key[k] = 0;
	k = 0;
	if (*p != '=') { *bad = 1; return 0; }
	p++;
	if (*p == '"') {
		p++;
		while (*p && *p != '"' && *p != '\n') {
			if (*p == '\\' && (p[1] == '"' || p[1] == '\\')) p++;
			if (k + 1 < vn) val[k++] = *p;
			p++;
		}
		if (*p != '"') { *bad = 1; return 0; }
		p++;
	} else {
		while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
			if (k + 1 < vn) val[k++] = *p;
			p++;
		}
	}
	val[k] = 0;
	*pp = p;
	return 1;
}

static int yes(const char *v)
{
	return !ln_strcasecmp(v, "yes") || !ln_strcasecmp(v, "on") || !ln_strcasecmp(v, "true") || !strcmp(v, "1");
}

static void add_extra(char *extra, size_t n, const char *k, const char *v)
{
	if (extra[0]) ln_strlcat(extra, " ", n);
	ln_strlcat(extra, k, n);
	ln_strlcat(extra, "=\"", n);
	ln_strlcat(extra, v, n);
	ln_strlcat(extra, "\"", n);
}

int ln_conf_parse(LnConf *c, const char *text, int *errline)
{
	const char *p = text;
	int line = 0;
	char key[32], val[LN_URL_MAX];
	ln_conf_init(c);
	while (*p) {
		const char *t;
		int bad = 0;
		line++;
		while (*p == ' ' || *p == '\t') p++;
		if (!strncmp(p, "share", 5) && (p[5] == ' ' || p[5] == '\t')) {
			LnShare s;
			memset(&s, 0, sizeof(s));
			p += 5;
			while (pair(&p, key, sizeof(key), val, sizeof(val), &bad)) {
				if (!strcmp(key, "name")) ln_strlcpy(s.name, val, sizeof(s.name));
				else if (!strcmp(key, "url")) ln_strlcpy(s.url, val, sizeof(s.url));
				else if (!strcmp(key, "user")) ln_strlcpy(s.user, val, sizeof(s.user));
				else if (!strcmp(key, "domain")) ln_strlcpy(s.domain, val, sizeof(s.domain));
				else if (!strcmp(key, "pass")) { if (ln_conf_unhide(val, s.password, sizeof(s.password))) bad = 1; }
				else if (!strcmp(key, "volume")) ln_strlcpy(s.volume, val, sizeof(s.volume));
				else if (!strcmp(key, "automount")) s.automount = yes(val);
				else if (!strcmp(key, "readonly")) s.readonly = yes(val);
				else add_extra(s.extra, sizeof(s.extra), key, val);
			}
			if (bad || !s.name[0] || !s.url[0] || c->nshares >= LN_CONF_MAX_SHARES) {
				if (errline) *errline = line;
				return LN_EINVAL;
			}
			c->share[c->nshares++] = s;
		} else if (!strncmp(p, "option", 6) && (p[6] == ' ' || p[6] == '\t')) {
			p += 6;
			while (pair(&p, key, sizeof(key), val, sizeof(val), &bad)) {
				if (!strcmp(key, "loglevel")) c->loglevel = val[0] - '0';
				else add_extra(c->extra, sizeof(c->extra), key, val);
			}
			if (bad) {
				if (errline) *errline = line;
				return LN_EINVAL;
			}
		} else if (*p && *p != '#' && *p != '\n' && *p != '\r') {
			if (errline) *errline = line;
			return LN_EINVAL;
		}
		t = strchr(p, '\n');
		p = t ? t + 1 : p + strlen(p);
	}
	return LN_OK;
}

static void q(char *buf, size_t n, const char *key, const char *v)
{
	ln_strlcat(buf, " ", n);
	ln_strlcat(buf, key, n);
	ln_strlcat(buf, "=\"", n);
	for (; *v; v++) {
		char t[3] = { 0, 0, 0 };
		if (*v == '"' || *v == '\\') { t[0] = '\\'; t[1] = *v; }
		else t[0] = *v;
		ln_strlcat(buf, t, n);
	}
	ln_strlcat(buf, "\"", n);
}

int ln_conf_format(const LnConf *c, char *buf, size_t n)
{
	int i;
	size_t l;
	char tmp[200];
	if (!n) return -1;
	buf[0] = 0;
	ln_strlcat(buf, "# Lagoon shares - edit with LagoonPrefs\n", n);
	if (c->loglevel || c->extra[0]) {
		ln_snprintf(tmp, sizeof(tmp), "option loglevel=%d", c->loglevel);
		ln_strlcat(buf, tmp, n);
		if (c->extra[0]) { ln_strlcat(buf, " ", n); ln_strlcat(buf, c->extra, n); }
		ln_strlcat(buf, "\n", n);
	}
	for (i = 0; i < c->nshares; i++) {
		const LnShare *s = &c->share[i];
		ln_strlcat(buf, "share", n);
		q(buf, n, "name", s->name);
		q(buf, n, "url", s->url);
		if (s->domain[0]) q(buf, n, "domain", s->domain);
		if (s->user[0]) q(buf, n, "user", s->user);
		if (s->password[0]) {
			ln_conf_hide(s->password, tmp, sizeof(tmp));
			q(buf, n, "pass", tmp);
		}
		if (s->volume[0]) q(buf, n, "volume", s->volume);
		ln_strlcat(buf, s->automount ? " automount=yes" : " automount=no", n);
		ln_strlcat(buf, s->readonly ? " readonly=yes" : " readonly=no", n);
		if (s->extra[0]) { ln_strlcat(buf, " ", n); ln_strlcat(buf, s->extra, n); }
		l = ln_strlcat(buf, "\n", n);
		if (l >= n) return -1;
	}
	l = strlen(buf);
	return l + 1 < n ? (int)l : -1;
}

LnShare *ln_conf_find(LnConf *c, const char *name)
{
	int i;
	for (i = 0; i < c->nshares; i++)
		if (!ln_strcasecmp(c->share[i].name, name))
			return &c->share[i];
	return NULL;
}

int ln_conf_put(LnConf *c, const LnShare *s)
{
	LnShare *e = ln_conf_find(c, s->name);
	if (e) { *e = *s; return LN_OK; }
	if (c->nshares >= LN_CONF_MAX_SHARES) return LN_ENOSPC;
	c->share[c->nshares++] = *s;
	return LN_OK;
}

int ln_conf_remove(LnConf *c, const char *name)
{
	LnShare *e = ln_conf_find(c, name);
	int i;
	if (!e) return LN_ENOENT;
	i = (int)(e - c->share);
	memmove(&c->share[i], &c->share[i + 1], (size_t)(c->nshares - i - 1) * sizeof(LnShare));
	c->nshares--;
	return LN_OK;
}
