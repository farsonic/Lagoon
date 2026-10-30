/*
 * Lagoon - NetBIOS name service client (RFC 1002 4.2: name query, node
 * status). See ln_netbios.h.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "ln_netbios.h"
#include "ln_mdns.h"             /* ln_dns_get_name */
#include "ln_sys.h"

#define NB_TYPE_NB     0x0020
#define NB_TYPE_NBSTAT 0x0021

static LnAddr target;
static int have_target;

void ln_nb_set_target(const LnAddr *a)
{
	have_target = a != NULL;
	if (a)
		target = *a;
}

void ln_nb_encode(const char *name, u8 suffix, u8 *out)
{
	u8 raw[16];
	int i, wild = !strcmp(name, "*");
	memset(raw, wild ? 0 : ' ', 15);
	for (i = 0; i < 15 && name[i]; i++) {
		char c = name[i];
		raw[i] = (u8)(c >= 'a' && c <= 'z' ? c - 32 : c);
	}
	raw[15] = suffix;
	out[0] = 32;
	for (i = 0; i < 16; i++) {
		out[1 + 2 * i] = (u8)('A' + (raw[i] >> 4));
		out[2 + 2 * i] = (u8)('A' + (raw[i] & 15));
	}
	out[33] = 0;
}

int ln_nb_decode(const u8 *enc, char *name, u8 *suffix)
{
	int i, l;
	u8 raw[16];
	for (i = 0; i < 16; i++) {
		u8 h = (u8)(enc[2 * i] - 'A'), lo = (u8)(enc[2 * i + 1] - 'A');
		if (h > 15 || lo > 15) return LN_EPROTO;
		raw[i] = (u8)((h << 4) | lo);
	}
	*suffix = raw[15];
	for (l = 15; l > 0 && (raw[l - 1] == ' ' || raw[l - 1] == 0); l--)
		;
	memcpy(name, raw, (size_t)l);
	name[l] = 0;
	return LN_OK;
}

static int build(u8 *buf, size_t n, u16 id, u16 flags, const char *name, u8 suffix, u16 type)
{
	if (n < 12 + 34 + 4) return LN_ENOSPC;
	memset(buf, 0, 12);
	ln_put_be16(buf, id);
	ln_put_be16(buf + 2, flags);
	ln_put_be16(buf + 4, 1);
	ln_nb_encode(name, suffix, buf + 12);
	ln_put_be16(buf + 46, type);
	ln_put_be16(buf + 48, 1);
	return 50;
}

int ln_nb_build_query(u8 *buf, size_t n, u16 id, const char *name, u8 suffix, int broadcast)
{
	/* opcode 0 (query), RD, B for broadcast */
	return build(buf, n, id, (u16)(0x0100 | (broadcast ? 0x0010 : 0)), name, suffix, NB_TYPE_NB);
}

int ln_nb_build_status(u8 *buf, size_t n, u16 id)
{
	return build(buf, n, id, 0, "*", 0, NB_TYPE_NBSTAT);
}

/* skip header + questions; offset of the first answer, type in *type, rdata
 * offset/length. Returns LN_OK, 1 if not a usable response, LN_EPROTO */
static int first_answer(const u8 *pkt, size_t len, u16 *type, size_t *rd, u16 *rdlen, char *ename)
{
	size_t off = 12;
	int i, qd;
	char nm[80];
	if (len < 12) return LN_EPROTO;
	if (!(pkt[2] & 0x80) || (pkt[3] & 0x0f) || ln_be16(pkt + 6) < 1) return 1;
	qd = ln_be16(pkt + 4);
	for (i = 0; i < qd; i++) {
		if (ln_dns_get_name(pkt, len, &off, nm, sizeof(nm), NULL, 0)) return LN_EPROTO;
		off += 4;
	}
	if (ln_dns_get_name(pkt, len, &off, nm, sizeof(nm), ename, 33)) return LN_EPROTO;
	if (off + 10 > len) return LN_EPROTO;
	*type = ln_be16(pkt + off);
	*rdlen = ln_be16(pkt + off + 8);
	*rd = off + 10;
	if (*rd + *rdlen > len) return LN_EPROTO;
	return LN_OK;
}

int ln_nb_parse_query(const u8 *pkt, size_t len, u16 id, LnAddr *out, int max)
{
	u16 type, rdlen;
	size_t rd, i;
	char en[33];
	int r, n = 0;
	if (len >= 2 && ln_be16(pkt) != id) return 0;
	r = first_answer(pkt, len, &type, &rd, &rdlen, en);
	if (r) return r < 0 ? r : 0;
	if (type != NB_TYPE_NB || ((pkt[2] >> 3) & 15) != 0) return 0;
	for (i = 0; i + 6 <= rdlen && n < max; i += 6) {
		memset(&out[n], 0, sizeof(out[n]));
		out[n].family = 4;
		memcpy(out[n].a, pkt + rd + i + 2, 4);
		n++;
	}
	return n;
}

int ln_nb_parse_status(const u8 *pkt, size_t len, LnNbHost *h)
{
	u16 type, rdlen;
	size_t rd;
	char en[33];
	int r, i, num;
	r = first_answer(pkt, len, &type, &rd, &rdlen, en);
	if (r) return r < 0 ? r : 1;
	if (type != NB_TYPE_NBSTAT || rdlen < 1) return 1;
	num = pkt[rd];
	if (1 + (size_t)num * 18 > rdlen) return LN_EPROTO;
	h->name[0] = h->group[0] = 0;
	h->server = 0;
	for (i = 0; i < num; i++) {
		const u8 *e = pkt + rd + 1 + i * 18;
		u16 fl = ln_be16(e + 16);
		char nm[16];
		int l;
		u8 suf = e[15];
		memcpy(nm, e, 15);
		for (l = 15; l > 0 && (nm[l - 1] == ' ' || nm[l - 1] == 0); l--)
			;
		nm[l] = 0;
		if (fl & 0x8000) {                       /* group name */
			if (suf == 0x00 && !h->group[0]) ln_strlcpy(h->group, nm, sizeof(h->group));
		} else if (suf == 0x20) {
			ln_strlcpy(h->name, nm, sizeof(h->name));
			h->server = 1;
		} else if (suf == 0x00 && !h->name[0]) {
			ln_strlcpy(h->name, nm, sizeof(h->name));
		}
	}
	return LN_OK;
}

/* ---- network ---- */
static void dest(LnAddr *to)
{
	if (have_target) {
		*to = target;
	} else {
		memset(to, 0, sizeof(*to));
		to->family = 4;
		memset(to->a, 255, 4);
		to->port = LN_NB_PORT;
	}
}

static int find_host(LnNbHost *out, int n, const LnAddr *a)
{
	int i;
	for (i = 0; i < n; i++)
		if (!memcmp(out[i].addr.a, a->a, 4))
			return i;
	return -1;
}

int ln_nb_discover(int timeout_ms, LnNbHost *out, int max)
{
	LnSock *s;
	LnAddr to, from;
	u8 *buf;
	int r, n = 0, len, i;
	u16 id;
	u32 t0;
	int asked[64];
	static const char *const names[] = { "*", "WORKGROUP" };
	if (timeout_ms < 300) timeout_ms = 300;
	r = ln_udp_open(0, NULL, &s);
	if (r != LN_OK) return r;
	ln_udp_broadcast(s, 1);
	buf = ln_alloc(600);
	if (!buf) { ln_sock_close(s); return LN_ENOMEM; }
	memset(asked, 0, sizeof(asked));
	ln_random(&id, sizeof(id));
	id &= 0x7fff;
	dest(&to);
	for (i = 0; i < 2; i++) {
		len = ln_nb_build_query(buf, 600, (u16)(id + i), names[i], 0, !have_target);
		ln_udp_sendto(s, &to, buf, (size_t)len);
	}
	len = ln_nb_build_status(buf, 600, (u16)(id + 2));
	ln_udp_sendto(s, &to, buf, (size_t)len);
	t0 = ln_ms();
	while ((int)(ln_ms() - t0) < timeout_ms) {
		LnAddr ad[8];
		LnNbHost h;
		int k, na, left = timeout_ms - (int)(ln_ms() - t0);
		if (ln_break()) { r = LN_EBREAK; break; }
		r = ln_udp_recvfrom(s, &from, buf, 600, left > 200 ? 200 : (left > 0 ? left : 1));
		if (r == LN_EBREAK) break;
		if (r <= 0) {
			/* ask hosts that answered a name query for their names */
			for (k = 0; k < n && k < 64; k++)
				if (!out[k].name[0] && !asked[k]) {
					LnAddr u = out[k].addr;
					u.port = LN_NB_PORT;
					if (have_target) u = target;     /* tests: the one server */
					len = ln_nb_build_status(buf, 600, (u16)(id + 3 + k));
					ln_udp_sendto(s, &u, buf, (size_t)len);
					asked[k] = 1;
				}
			r = 0;
			continue;
		}
		len = r;
		memset(&h, 0, sizeof(h));
		if (ln_nb_parse_status(buf, (size_t)len, &h) == LN_OK) {
			h.addr = from;
			h.addr.port = 0;
			k = find_host(out, n, &from);
			if (k < 0 && n < max) k = n++;
			if (k >= 0) out[k] = h;
			continue;
		}
		na = 0;
		for (i = 0; i < 2 && na <= 0; i++)
			na = ln_nb_parse_query(buf, (size_t)len, (u16)(id + i), ad, 8);
		for (i = 0; i < na; i++) {
			if (find_host(out, n, &ad[i]) >= 0 || n >= max) continue;
			memset(&out[n], 0, sizeof(out[n]));
			out[n].addr = ad[i];
			out[n].addr.port = 0;
			n++;
		}
	}
	ln_free(buf);
	ln_sock_close(s);
	if (r == LN_EBREAK) return r;
	return n;
}

int ln_nb_resolve(const char *name, LnAddr *out, int max)
{
	LnSock *s;
	LnAddr to;
	u8 buf[600];
	int r, n = 0, tries;
	u16 id;
	if (!name[0] || strlen(name) > 15 || max <= 0) return LN_EINVAL;
	r = ln_udp_open(0, NULL, &s);
	if (r != LN_OK) return r;
	ln_udp_broadcast(s, 1);
	ln_random(&id, sizeof(id));
	id &= 0x7fff;
	dest(&to);
	for (tries = 0; tries < 4 && n <= 0; tries++) {
		u8 suf = (tries & 1) ? 0x00 : 0x20;
		u32 t0 = ln_ms();
		int len = ln_nb_build_query(buf, sizeof(buf), (u16)(id + tries), name, suf, !have_target);
		ln_udp_sendto(s, &to, buf, (size_t)len);
		while (n <= 0 && (int)(ln_ms() - t0) < 500) {
			r = ln_udp_recvfrom(s, NULL, buf, sizeof(buf), 250);
			if (r == LN_EBREAK) { ln_sock_close(s); return r; }
			if (r > 0) n = ln_nb_parse_query(buf, (size_t)r, (u16)(id + tries), out, max);
		}
	}
	ln_sock_close(s);
	return n > 0 ? n : LN_ENOHOST;
}
