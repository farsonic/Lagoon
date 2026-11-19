/*
 * Lagoon - share list file (format in ln_conf.h).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "ln_conf.h"
#include "ln_err.h"
#include "ln_hash.h"
#include "ln_charset.h"

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

void ln_conf_server_defaults(LnServerConf *s)
{
	memset(s, 0, sizeof(*s));
	s->netbios = 1;
	s->mdns = 1;
}

void ln_conf_init(LnConf *c)
{
	memset(c, 0, sizeof(*c));
	c->loglevel = 0;
	ln_conf_server_defaults(&c->server);
}

static int hexv(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int unhex16(const char *s, u8 out[16])
{
	int i;
	if (strlen(s) != 32)
		return -1;
	for (i = 0; i < 16; i++) {
		int a = hexv((u8)s[2 * i]), b = hexv((u8)s[2 * i + 1]);
		if (a < 0 || b < 0)
			return -1;
		out[i] = (u8)(a * 16 + b);
	}
	return 0;
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

static long strtol_simple(const char *v)
{
	long n = 0;
	if (!*v) return -1;
	for (; *v; v++) {
		if (*v < '0' || *v > '9' || n > 1000000) return -1;
		n = n * 10 + (*v - '0');
	}
	return n;
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
		} else if (!strncmp(p, "server", 6) && (p[6] == ' ' || p[6] == '\t')) {
			LnServerConf *sv = &c->server;
			p += 6;
			while (pair(&p, key, sizeof(key), val, sizeof(val), &bad)) {
				if (!strcmp(key, "name")) ln_strlcpy(sv->name, val, sizeof(sv->name));
				else if (!strcmp(key, "workgroup")) ln_strlcpy(sv->workgroup, val, sizeof(sv->workgroup));
				else if (!strcmp(key, "comment")) ln_strlcpy(sv->comment, val, sizeof(sv->comment));
				else if (!strcmp(key, "signing")) sv->signing = !ln_strcasecmp(val, "required");
				else if (!strcmp(key, "netbios")) sv->netbios = yes(val);
				else if (!strcmp(key, "mdns")) sv->mdns = yes(val);
				else if (!strcmp(key, "autostart")) sv->autostart = yes(val);
				else if (!strcmp(key, "port")) sv->port = (int)strtol_simple(val);
				else if (!strcmp(key, "log")) ln_strlcpy(sv->log, val, sizeof(sv->log));
				else if (!strcmp(key, "loglevel")) sv->loglevel = val[0] - '0';
				else add_extra(sv->extra, sizeof(sv->extra), key, val);
			}
			if (bad || sv->port < 0 || sv->port > 65535) {
				if (errline) *errline = line;
				return LN_EINVAL;
			}
		} else if (!strncmp(p, "export", 6) && (p[6] == ' ' || p[6] == '\t')) {
			LnExport e;
			memset(&e, 0, sizeof(e));
			p += 6;
			while (pair(&p, key, sizeof(key), val, sizeof(val), &bad)) {
				if (!strcmp(key, "name")) ln_strlcpy(e.name, val, sizeof(e.name));
				else if (!strcmp(key, "path")) ln_strlcpy(e.path, val, sizeof(e.path));
				else if (!strcmp(key, "comment")) ln_strlcpy(e.comment, val, sizeof(e.comment));
				else if (!strcmp(key, "readonly")) e.readonly = yes(val);
				else if (!strcmp(key, "guest")) e.guest = yes(val);
				else if (!strcmp(key, "users")) ln_strlcpy(e.users, val, sizeof(e.users));
				else add_extra(e.extra, sizeof(e.extra), key, val);
			}
			if (bad || !e.name[0] || !e.path[0] || c->nexports >= LN_CONF_MAX_EXPORTS) {
				if (errline) *errline = line;
				return LN_EINVAL;
			}
			c->export_[c->nexports++] = e;
		} else if (!strncmp(p, "user", 4) && (p[4] == ' ' || p[4] == '\t')) {
			LnAccount a;
			int have = 0;
			memset(&a, 0, sizeof(a));
			p += 4;
			while (pair(&p, key, sizeof(key), val, sizeof(val), &bad)) {
				if (!strcmp(key, "name")) ln_strlcpy(a.name, val, sizeof(a.name));
				else if (!strcmp(key, "nthash")) { if (unhex16(val, a.nthash)) bad = 1; else have = 1; }
				else add_extra(a.extra, sizeof(a.extra), key, val);
			}
			if (bad || !a.name[0] || !have || c->nusers >= LN_CONF_MAX_USERS) {
				if (errline) *errline = line;
				return LN_EINVAL;
			}
			c->user[c->nusers++] = a;
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
	{
		const LnServerConf *sv = &c->server;
		LnServerConf def;
		ln_conf_server_defaults(&def);
		if (c->nexports || c->nusers || memcmp(sv, &def, sizeof(def))) {
			ln_strlcat(buf, "server", n);
			if (sv->name[0]) q(buf, n, "name", sv->name);
			if (sv->workgroup[0]) q(buf, n, "workgroup", sv->workgroup);
			if (sv->comment[0]) q(buf, n, "comment", sv->comment);
			ln_strlcat(buf, sv->signing ? " signing=required" : " signing=auto", n);
			ln_strlcat(buf, sv->netbios ? " netbios=yes" : " netbios=no", n);
			ln_strlcat(buf, sv->mdns ? " mdns=yes" : " mdns=no", n);
			ln_strlcat(buf, sv->autostart ? " autostart=yes" : " autostart=no", n);
			if (sv->port) {
				ln_snprintf(tmp, sizeof(tmp), " port=%d", sv->port);
				ln_strlcat(buf, tmp, n);
			}
			if (sv->log[0]) q(buf, n, "log", sv->log);
			if (sv->loglevel) {
				ln_snprintf(tmp, sizeof(tmp), " loglevel=%d", sv->loglevel);
				ln_strlcat(buf, tmp, n);
			}
			if (sv->extra[0]) { ln_strlcat(buf, " ", n); ln_strlcat(buf, sv->extra, n); }
			ln_strlcat(buf, "\n", n);
		}
	}
	for (i = 0; i < c->nexports; i++) {
		const LnExport *e = &c->export_[i];
		ln_strlcat(buf, "export", n);
		q(buf, n, "name", e->name);
		q(buf, n, "path", e->path);
		if (e->comment[0]) q(buf, n, "comment", e->comment);
		ln_strlcat(buf, e->readonly ? " readonly=yes" : " readonly=no", n);
		ln_strlcat(buf, e->guest ? " guest=yes" : " guest=no", n);
		if (e->users[0]) q(buf, n, "users", e->users);
		if (e->extra[0]) { ln_strlcat(buf, " ", n); ln_strlcat(buf, e->extra, n); }
		ln_strlcat(buf, "\n", n);
	}
	for (i = 0; i < c->nusers; i++) {
		const LnAccount *a = &c->user[i];
		int k;
		ln_strlcat(buf, "user", n);
		q(buf, n, "name", a->name);
		for (k = 0; k < 16; k++)
			ln_snprintf(tmp + 2 * k, 3, "%02x", a->nthash[k]);
		q(buf, n, "nthash", tmp);
		if (a->extra[0]) { ln_strlcat(buf, " ", n); ln_strlcat(buf, a->extra, n); }
		ln_strlcat(buf, "\n", n);
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

/* ---- exports and users (the SMB server) ---- */
LnExport *ln_conf_find_export(LnConf *c, const char *name)
{
	int i;
	for (i = 0; i < c->nexports; i++)
		if (!ln_strcasecmp(c->export_[i].name, name))
			return &c->export_[i];
	return NULL;
}

int ln_conf_put_export(LnConf *c, const LnExport *e)
{
	LnExport *o = ln_conf_find_export(c, e->name);
	if (o) { *o = *e; return LN_OK; }
	if (c->nexports >= LN_CONF_MAX_EXPORTS) return LN_ENOSPC;
	c->export_[c->nexports++] = *e;
	return LN_OK;
}

int ln_conf_remove_export(LnConf *c, const char *name)
{
	LnExport *e = ln_conf_find_export(c, name);
	int i;
	if (!e) return LN_ENOENT;
	i = (int)(e - c->export_);
	memmove(&c->export_[i], &c->export_[i + 1], (size_t)(c->nexports - i - 1) * sizeof(LnExport));
	c->nexports--;
	return LN_OK;
}

LnAccount *ln_conf_find_user(LnConf *c, const char *name)
{
	int i;
	for (i = 0; i < c->nusers; i++)
		if (!ln_strcasecmp(c->user[i].name, name))
			return &c->user[i];
	return NULL;
}

void ln_nthash(const char *password, u8 out[16])
{
	u8 b[512];
	int n = ln_utf8_to_utf16le(password, strlen(password), b, sizeof(b));
	ln_md4(b, n < 0 ? 0 : (size_t)n, out);
	ln_wipe(b, sizeof(b));
}

int ln_conf_put_user(LnConf *c, const char *name, const char *password)
{
	LnAccount *a = ln_conf_find_user(c, name);
	if (!name[0]) return LN_EINVAL;
	if (!a) {
		if (c->nusers >= LN_CONF_MAX_USERS) return LN_ENOSPC;
		a = &c->user[c->nusers++];
		memset(a, 0, sizeof(*a));
	}
	ln_strlcpy(a->name, name, sizeof(a->name));
	ln_nthash(password, a->nthash);
	return LN_OK;
}

int ln_conf_remove_user(LnConf *c, const char *name)
{
	LnAccount *a = ln_conf_find_user(c, name);
	int i;
	if (!a) return LN_ENOENT;
	i = (int)(a - c->user);
	memmove(&c->user[i], &c->user[i + 1], (size_t)(c->nusers - i - 1) * sizeof(LnAccount));
	c->nusers--;
	return LN_OK;
}

int ln_conf_user_listed(const char *list, const char *user)
{
	char w[64];
	size_t k;
	while (*list) {
		while (*list == ' ' || *list == ',' || *list == '\t') list++;
		k = 0;
		while (*list && *list != ' ' && *list != ',' && *list != '\t') {
			if (k + 1 < sizeof(w)) w[k++] = *list;
			list++;
		}
		w[k] = 0;
		if (k && !ln_strcasecmp(w, user))
			return 1;
	}
	return 0;
}
