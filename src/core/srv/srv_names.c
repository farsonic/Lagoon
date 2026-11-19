/*
 * Lagoon - SMB2 server: being found on the network. NetBIOS name service
 * answers (RFC 1002: name query for our name, node status) so Windows finds
 * \\AMIGA, and an mDNS/DNS-SD responder (RFC 6762/6763: _smb._tcp, our
 * host name.local) so macOS Finder, GNOME and KDE list the Amiga.
 * Packet level only; srv_loop.c owns the sockets.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "srv_int.h"
#include "../ln_netbios.h"
#include "../ln_mdns.h"

/* ---------------------------------------------------------- NetBIOS */

static void nb_name(char *out, const char *in)
{
	int i;
	for (i = 0; i < 15 && in[i]; i++)
		out[i] = (char)(in[i] >= 'a' && in[i] <= 'z' ? in[i] - 32 : in[i]);
	out[i] = 0;
}

int ln_srv_nbns_answer(const LnSrv *s, const LnAddr *me, const u8 *pkt, size_t len, u8 *out, size_t outmax)
{
	char name[17], ours[16], wg[16];
	u8 suffix;
	u16 flags, type;
	size_t k;
	if (len < 12 + 34 + 4 || outmax < 300)
		return 0;
	flags = ln_be16(pkt + 2);
	if ((flags & 0x8000) || ((flags >> 11) & 15) != 0 || ln_be16(pkt + 4) != 1 || pkt[12] != 32)
		return 0;
	if (ln_nb_decode(pkt + 13, name, &suffix) != LN_OK || pkt[45] != 0)
		return 0;
	type = ln_be16(pkt + 46);
	nb_name(ours, s->cfg.name);
	nb_name(wg, s->cfg.domain);
	memset(out, 0, 12);
	ln_put_be16(out, ln_be16(pkt));
	ln_put_be16(out + 6, 1);                       /* one answer, no question */
	memcpy(out + 12, pkt + 12, 34);
	k = 46;
	if (type == 0x20) {
		if (ln_strcasecmp(name, ours) || (suffix != 0x00 && suffix != 0x20))
			return 0;
		ln_put_be16(out + 2, (u16)(0x8400 | (flags & 0x0100)));   /* response, authoritative */
		ln_put_be16(out + k, 0x20);
		ln_put_be16(out + k + 2, 1);
		ln_put_be32(out + k + 4, 300000);
		ln_put_be16(out + k + 8, 6);
		ln_put_be16(out + k + 10, 0);              /* B node, unique */
		memcpy(out + k + 12, me->a, 4);
		return (int)(k + 16);
	}
	if (type == 0x21) {
		static const u8 sfx[3] = { 0x00, 0x20, 0x00 };
		int i;
		size_t rd;
		if (strcmp(name, "*") && strcmp(name, "") && ln_strcasecmp(name, ours))
			return 0;
		ln_put_be16(out + 2, 0x8400);
		ln_put_be16(out + k, 0x21);
		ln_put_be16(out + k + 2, 1);
		ln_put_be32(out + k + 4, 0);
		rd = k + 10;
		out[rd] = 3;
		for (i = 0; i < 3; i++) {
			u8 *e = out + rd + 1 + 18 * i;
			const char *n = i < 2 ? ours : wg;
			size_t l = strlen(n);
			memset(e, ' ', 15);
			memcpy(e, n, l);
			e[15] = sfx[i];
			ln_put_be16(e + 16, (u16)(i < 2 ? 0x0400 : 0x8400));   /* active (+ group) */
		}
		memset(out + rd + 1 + 54, 0, 46);          /* MAC and statistics */
		ln_put_be16(out + k + 8, 1 + 54 + 46);
		return (int)(rd + 1 + 54 + 46);
	}
	return 0;
}

/* ------------------------------------------------------------- mDNS */

typedef struct W {
	u8 *b;
	size_t n, max;
	int bad;
} W;

static void put_rr(W *w, const char *label, const char *name, u16 type, u16 cls, u32 ttl, const u8 *rd, size_t rdl,
                   const char *rdname, const char *rdlabel)
{
	int l;
	size_t at;
	if (w->bad)
		return;
	{
		/* name: optional first label + dotted rest */
		u8 tmp[300];
		size_t o = 0;
		if (label) {
			size_t ll = strlen(label);
			if (ll > 63) ll = 63;
			tmp[o++] = (u8)ll;
			memcpy(tmp + o, label, ll);
			o += ll;
		}
		l = ln_dns_put_name(tmp + o, sizeof(tmp) - o, name);
		if (l < 0 || w->n + o + (size_t)l + 10 > w->max) { w->bad = 1; return; }
		memcpy(w->b + w->n, tmp, o + (size_t)l);
		w->n += o + (size_t)l;
	}
	ln_put_be16(w->b + w->n, type);
	ln_put_be16(w->b + w->n + 2, cls);
	ln_put_be32(w->b + w->n + 4, ttl);
	at = w->n + 8;
	w->n += 10;
	if (rd) {
		if (w->n + rdl > w->max) { w->bad = 1; return; }
		memcpy(w->b + w->n, rd, rdl);
		w->n += rdl;
	}
	if (rdname) {
		size_t o = 0;
		if (rdlabel) {
			size_t ll = strlen(rdlabel);
			if (ll > 63) ll = 63;
			if (w->n + 1 + ll > w->max) { w->bad = 1; return; }
			w->b[w->n++] = (u8)ll;
			memcpy(w->b + w->n, rdlabel, ll);
			w->n += ll;
			o = 1 + ll;
		}
		l = ln_dns_put_name(w->b + w->n, w->max - w->n, rdname);
		if (l < 0) { w->bad = 1; return; }
		w->n += (size_t)l;
		rdl += o + (size_t)l;
	}
	ln_put_be16(w->b + at, (u16)rdl);
}

enum { R_PTR = 1, R_SRV = 2, R_TXT = 4, R_A = 8, R_SVCS = 16 };

static void host_name(const LnSrv *s, char *h, size_t n)
{
	int i;
	ln_snprintf(h, n, "%s.local", s->cfg.name);
	for (i = 0; h[i]; i++)
		if (h[i] >= 'A' && h[i] <= 'Z')
			h[i] += 32;
}

static int records(const LnSrv *s, const LnAddr *me, u16 port, int ans, int add, int unicast, u16 id,
                   const char *qname, u16 qtype, u8 *out, size_t outmax)
{
	W w;
	char host[64];
	u8 rd[16];
	u16 uc = unicast ? 0 : 0x8000;          /* cache-flush for unique records (multicast only) */
	u32 ttl_long = unicast ? 10 : 4500, ttl_short = unicast ? 10 : 120;
	int i, na = 0, nr = 0;
	host_name(s, host, sizeof(host));
	w.b = out; w.n = 12; w.max = outmax; w.bad = 0;
	memset(out, 0, 12);
	ln_put_be16(out, id);
	ln_put_be16(out + 2, 0x8400);
	if (qname) {
		int l = ln_dns_put_name(out + 12, outmax - 16, qname);
		if (l < 0)
			return 0;
		ln_put_be16(out + 12 + l, qtype);
		ln_put_be16(out + 14 + l, 1);
		w.n += (size_t)l + 4;
		ln_put_be16(out + 4, 1);
	}
	for (i = 0; i < 2; i++) {
		int set = i == 0 ? ans : add & ~ans;
		int before = 0;
		if (set & R_SVCS) { put_rr(&w, NULL, "_services._dns-sd._udp.local", LN_DNS_PTR, 1, ttl_long, NULL, 0, "_smb._tcp.local", NULL); before++; }
		if (set & R_PTR) { put_rr(&w, NULL, "_smb._tcp.local", LN_DNS_PTR, 1, ttl_long, NULL, 0, "_smb._tcp.local", s->cfg.name); before++; }
		if (set & R_SRV) {
			memset(rd, 0, 6);
			ln_put_be16(rd + 4, port);
			put_rr(&w, s->cfg.name, "_smb._tcp.local", LN_DNS_SRV, (u16)(1 | uc), ttl_short, rd, 6, host, NULL);
			before++;
		}
		if (set & R_TXT) {
			rd[0] = 0;
			put_rr(&w, s->cfg.name, "_smb._tcp.local", LN_DNS_TXT, (u16)(1 | uc), ttl_long, rd, 1, NULL, NULL);
			before++;
		}
		if (set & R_A) {
			put_rr(&w, NULL, host, LN_DNS_A, (u16)(1 | uc), ttl_short, me->a, 4, NULL, NULL);
			before++;
		}
		if (i == 0) na = before; else nr = before;
	}
	if (w.bad || !na)
		return 0;
	ln_put_be16(out + 6, (u16)na);
	ln_put_be16(out + 10, (u16)nr);
	return (int)w.n;
}

int ln_srv_mdns_announce(const LnSrv *s, const LnAddr *me, u16 port, u8 *out, size_t outmax)
{
	return records(s, me, port, R_PTR | R_SRV | R_TXT | R_A, 0, 0, 0, NULL, 0, out, outmax);
}

int ln_srv_mdns_answer(const LnSrv *s, const LnAddr *me, u16 port, const u8 *pkt, size_t len, int from_5353,
                       u8 *out, size_t outmax, int *unicast)
{
	size_t off = 12;
	char qname[LN_MDNS_NAME];
	u16 qtype = 0;
	int qd, i, ans = 0, add = 0, qu = 0;
	char name[LN_MDNS_NAME], first[64], host[64], inst[128];
	*unicast = 0;
	if (len < 12 || (pkt[2] & 0x80) || (pkt[2] & 0x78))
		return 0;
	host_name(s, host, sizeof(host));
	ln_snprintf(inst, sizeof(inst), "%s._smb._tcp.local", s->cfg.name);
	qd = ln_be16(pkt + 4);
	for (i = 0; i < qd; i++) {
		u16 type, cls;
		if (ln_dns_get_name(pkt, len, &off, name, sizeof(name), first, sizeof(first)) || off + 4 > len)
			return 0;
		type = ln_be16(pkt + off);
		cls = ln_be16(pkt + off + 2);
		off += 4;
		if ((cls & 0x7fff) != 1 && (cls & 0x7fff) != 255)
			continue;
		if (cls & 0x8000)
			qu = 1;
		if (!ln_strcasecmp(name, "_smb._tcp.local") && (type == LN_DNS_PTR || type == LN_DNS_ANY)) {
			ans |= R_PTR;
			add |= R_SRV | R_TXT | R_A;
		} else if (!ln_strcasecmp(name, "_services._dns-sd._udp.local") && (type == LN_DNS_PTR || type == LN_DNS_ANY)) {
			ans |= R_SVCS;
		} else if (!ln_strcasecmp(name, inst)) {
			if (type == LN_DNS_SRV || type == LN_DNS_ANY) { ans |= R_SRV; add |= R_A; }
			if (type == LN_DNS_TXT || type == LN_DNS_ANY) ans |= R_TXT;
		} else if (!ln_strcasecmp(name, host) && (type == LN_DNS_A || type == LN_DNS_ANY)) {
			ans |= R_A;
		} else
			continue;
		if (!qtype) {
			ln_strlcpy(qname, name, sizeof(qname));
			qtype = type;
		}
	}
	if (!ans)
		return 0;
	*unicast = !from_5353 || qu;
	if (!from_5353)
		/* legacy unicast: same id, the question repeated, short TTLs */
		return records(s, me, port, ans, add, 1, ln_be16(pkt), qname, qtype, out, outmax);
	return records(s, me, port, ans, add, 0, 0, NULL, 0, out, outmax);
}
