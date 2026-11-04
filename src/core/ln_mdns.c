/*
 * Lagoon - mDNS / DNS-SD browsing and .local name resolution (RFC 6762,
 * RFC 6763, RFC 1035 message format). See ln_mdns.h.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "ln_mdns.h"
#include "ln_sys.h"

#define MDNS_PORT 5353
#define MAXREC 96

const char *const ln_mdns_file_types[] = { "_smb._tcp", "_afpovertcp._tcp", "_nfs._tcp", NULL };

typedef struct Rec {
	u16  type;
	char name[LN_MDNS_NAME];     /* owner name, dotted */
	char first[64];              /* PTR: first label of the target (instance) */
	char data[LN_MDNS_NAME];     /* PTR / SRV target */
	char txt[256];
	u16  port;
	u8   a[4];
} Rec;

struct LnMdns {
	int nrec;
	Rec rec[MAXREC];
};

static LnAddr server;            /* tests: unicast server instead of the group */
static int have_server;

void ln_mdns_set_server(const LnAddr *a)
{
	have_server = a != NULL;
	if (a)
		server = *a;
}

const char *ln_mdns_scheme(const char *type)
{
	if (!ln_strcasecmp(type, "_smb._tcp")) return "smb";
	if (!ln_strcasecmp(type, "_afpovertcp._tcp")) return "afp";
	if (!ln_strcasecmp(type, "_nfs._tcp")) return "nfs";
	return NULL;
}

const char *ln_mdns_txt(const LnService *s, const char *key, char *buf, size_t n)
{
	const char *p = s->txt;
	size_t kl = strlen(key);
	while (*p) {
		const char *e = strchr(p, '\n');
		size_t l = e ? (size_t)(e - p) : strlen(p);
		if (l > kl && p[kl] == '=' && !ln_strncasecmp(p, key, kl)) {
			size_t vl = LN_MIN(l - kl - 1, n - 1);
			memcpy(buf, p + kl + 1, vl);
			buf[vl] = 0;
			return buf;
		}
		p += l;
		if (*p) p++;
	}
	return NULL;
}

/* ---- DNS names ---- */
int ln_dns_get_name(const u8 *pkt, size_t len, size_t *off, char *out, size_t n, char *first, size_t fn)
{
	size_t p = *off, o = 0;
	int jumped = 0, hops = 0, labels = 0;
	if (n) out[0] = 0;
	if (first && fn) first[0] = 0;
	for (;;) {
		u8 l;
		if (p >= len) return LN_EPROTO;
		l = pkt[p];
		if ((l & 0xc0) == 0xc0) {
			if (p + 1 >= len || ++hops > 32) return LN_EPROTO;
			if (!jumped) *off = p + 2;
			jumped = 1;
			p = ((size_t)(l & 0x3f) << 8) | pkt[p + 1];
			continue;
		}
		if (l & 0xc0) return LN_EPROTO;
		p++;
		if (!l) break;
		if (p + l > len) return LN_EPROTO;
		if (first && labels == 0 && fn) {
			size_t c = LN_MIN((size_t)l, fn - 1);
			memcpy(first, pkt + p, c);
			first[c] = 0;
		}
		if (o + l + 2 > n) return LN_EPROTO;    /* name too long for us */
		if (labels) out[o++] = '.';
		memcpy(out + o, pkt + p, l);
		o += l;
		out[o] = 0;
		labels++;
		p += l;
	}
	if (!jumped) *off = p;
	return LN_OK;
}

/* label (may contain dots, e.g. an instance name; NULL = none) + dotted rest */
static int put_name2(u8 *buf, size_t n, const char *label, const char *rest)
{
	size_t o = 0;
	if (label) {
		size_t l = strlen(label);
		if (l > 63) l = 63;
		if (o + 1 + l > n) return LN_ENOSPC;
		buf[o++] = (u8)l;
		memcpy(buf + o, label, l);
		o += l;
	}
	while (*rest) {
		const char *d = strchr(rest, '.');
		size_t l = d ? (size_t)(d - rest) : strlen(rest);
		if (l > 63 || l == 0) return l ? LN_ENOSPC : LN_EINVAL;
		if (o + 1 + l > n) return LN_ENOSPC;
		buf[o++] = (u8)l;
		memcpy(buf + o, rest, l);
		o += l;
		rest += l;
		if (*rest == '.') rest++;
	}
	if (o + 1 > n) return LN_ENOSPC;
	buf[o++] = 0;
	return (int)o;
}

int ln_dns_put_name(u8 *buf, size_t n, const char *name)
{
	return put_name2(buf, n, NULL, name);
}

/* ---- queries ---- */
static int query_start(u8 *buf, size_t n, u16 id, int nq)
{
	if (n < 12) return LN_ENOSPC;
	memset(buf, 0, 12);
	ln_put_be16(buf, id);
	ln_put_be16(buf + 4, (u16)nq);
	return 12;
}

static int query_add(u8 *buf, size_t n, size_t o, const char *label, const char *name, u16 type, int qu)
{
	int l = put_name2(buf + o, n - o, label, name);
	if (l < 0) return l;
	o += (size_t)l;
	if (o + 4 > n) return LN_ENOSPC;
	ln_put_be16(buf + o, type);
	ln_put_be16(buf + o + 2, (u16)(qu ? 0x8001 : 0x0001));   /* class IN, top bit = QU */
	return (int)(o + 4);
}

int ln_mdns_query(u8 *buf, size_t n, u16 id, const char *const *names, const u16 *types, int nq, int qu)
{
	int o = query_start(buf, n, id, nq), i;
	for (i = 0; i < nq && o > 0; i++)
		o = query_add(buf, n, (size_t)o, NULL, names[i], types[i], qu);
	return o;
}

/* ---- responses ---- */
LnMdns *ln_mdns_new(void)
{
	return ln_alloc(sizeof(LnMdns));
}

void ln_mdns_free(LnMdns *m)
{
	ln_free(m);
}

static Rec *find_rec(LnMdns *m, u16 type, const char *name, const char *data)
{
	int i;
	for (i = 0; i < m->nrec; i++) {
		Rec *r = &m->rec[i];
		if (r->type == type && !ln_strcasecmp(r->name, name) && (!data || !ln_strcasecmp(r->data, data)))
			return r;
	}
	return NULL;
}

int ln_mdns_feed(LnMdns *m, const u8 *pkt, size_t len)
{
	size_t off = 12;
	int qd, total, i, kept = 0;
	char name[LN_MDNS_NAME];
	if (len < 12) return LN_EPROTO;
	if (!(pkt[2] & 0x80)) return 0;              /* a query (ours, looped back) */
	if (pkt[3] & 0x0f) return 0;                 /* rcode != 0 */
	qd = ln_be16(pkt + 4);
	total = ln_be16(pkt + 6) + ln_be16(pkt + 8) + ln_be16(pkt + 10);
	for (i = 0; i < qd; i++) {
		if (ln_dns_get_name(pkt, len, &off, name, sizeof(name), NULL, 0)) return LN_EPROTO;
		off += 4;
	}
	for (i = 0; i < total; i++) {
		Rec r, *old;
		u16 type, rdlen;
		size_t rd;
		memset(&r, 0, sizeof(r));
		if (ln_dns_get_name(pkt, len, &off, r.name, sizeof(r.name), NULL, 0)) return LN_EPROTO;
		if (off + 10 > len) return LN_EPROTO;
		type = ln_be16(pkt + off);
		rdlen = ln_be16(pkt + off + 8);
		rd = off + 10;
		if (rd + rdlen > len) return LN_EPROTO;
		off = rd + rdlen;
		if ((ln_be16(pkt + rd - 8) & 0x7fff) != 1) continue;   /* class IN (top bit = cache flush) */
		if (ln_be32(pkt + rd - 6) == 0) continue;              /* TTL 0 = goodbye */
		r.type = type;
		switch (type) {
		case LN_DNS_A:
			if (rdlen != 4) continue;
			memcpy(r.a, pkt + rd, 4);
			ln_snprintf(r.data, sizeof(r.data), "%u.%u.%u.%u", r.a[0], r.a[1], r.a[2], r.a[3]);
			break;
		case LN_DNS_PTR: {
			size_t p = rd;
			if (ln_dns_get_name(pkt, rd + rdlen, &p, r.data, sizeof(r.data), r.first, sizeof(r.first)))
				continue;
			break;
		}
		case LN_DNS_SRV: {
			size_t p = rd + 6;
			if (rdlen < 7) continue;
			r.port = ln_be16(pkt + rd + 4);
			if (ln_dns_get_name(pkt, rd + rdlen, &p, r.data, sizeof(r.data), NULL, 0)) continue;
			break;
		}
		case LN_DNS_TXT: {
			size_t p = rd, o = 0;
			while (p < rd + rdlen) {
				size_t l = pkt[p++];
				if (p + l > rd + rdlen) break;
				if (l && o + l + 2 <= sizeof(r.txt)) {
					if (o) r.txt[o++] = '\n';
					memcpy(r.txt + o, pkt + p, l);
					o += l;
					r.txt[o] = 0;
				}
				p += l;
			}
			break;
		}
		default:
			continue;
		}
		/* SRV and TXT: one per name (newest wins); PTR and A: one per value */
		old = find_rec(m, type, r.name, type == LN_DNS_PTR || type == LN_DNS_A ? r.data : NULL);
		if (!old) {
			if (m->nrec >= MAXREC) continue;
			old = &m->rec[m->nrec++];
		}
		*old = r;
		kept++;
	}
	return kept;
}

int ln_mdns_addrs(LnMdns *m, const char *host, LnAddr *out, int max)
{
	int i, n = 0;
	for (i = 0; i < m->nrec && n < max; i++) {
		Rec *r = &m->rec[i];
		if (r->type == LN_DNS_A && !ln_strcasecmp(r->name, host)) {
			memset(&out[n], 0, sizeof(out[n]));
			out[n].family = 4;
			memcpy(out[n].a, r->a, 4);
			n++;
		}
	}
	return n;
}

static int in_types(const char *const *types, const char *t)
{
	for (; *types; types++)
		if (!ln_strcasecmp(*types, t))
			return 1;
	return 0;
}

static int svc_cmp(const LnService *a, const LnService *b)
{
	int c = strcmp(a->type, b->type);
	return c ? c : ln_strcasecmp(a->instance, b->instance);
}

int ln_mdns_services(LnMdns *m, const char *const *types, LnService *out, int max)
{
	int i, j, n = 0;
	if (!types) types = ln_mdns_file_types;
	for (i = 0; i < m->nrec && n < max; i++) {
		Rec *p = &m->rec[i], *srv, *txt;
		LnService *s;
		char type[64];
		size_t tl;
		/* PTR "_smb._tcp.local" -> "Instance._smb._tcp.local" */
		if (p->type != LN_DNS_PTR) continue;
		tl = strlen(p->name);
		if (tl < 7 || ln_strcasecmp(p->name + tl - 6, ".local") || tl - 6 >= sizeof(type)) continue;
		memcpy(type, p->name, tl - 6);
		type[tl - 6] = 0;
		if (!in_types(types, type)) continue;
		for (j = 0; j < n; j++)
			if (!ln_strcasecmp(out[j].type, type) && !strcmp(out[j].instance, p->first))
				break;
		if (j < n) continue;
		s = &out[n++];
		memset(s, 0, sizeof(*s));
		ln_strlcpy(s->type, type, sizeof(s->type));
		ln_strlcpy(s->scheme, ln_mdns_scheme(type) ? ln_mdns_scheme(type) : "", sizeof(s->scheme));
		ln_strlcpy(s->instance, p->first, sizeof(s->instance));
		srv = find_rec(m, LN_DNS_SRV, p->data, NULL);
		txt = find_rec(m, LN_DNS_TXT, p->data, NULL);
		if (txt) ln_strlcpy(s->txt, txt->txt, sizeof(s->txt));
		if (srv) {
			ln_strlcpy(s->host, srv->data, sizeof(s->host));
			s->port = srv->port;
			ln_mdns_addrs(m, srv->data, &s->addr, 1);
		}
	}
	/* insertion sort: few entries */
	for (i = 1; i < n; i++) {
		LnService t = out[i];
		for (j = i; j > 0 && svc_cmp(&out[j - 1], &t) > 0; j--)
			out[j] = out[j - 1];
		out[j] = t;
	}
	return n;
}

/* ---- network ---- */
typedef struct Q {
	LnSock *s5353;           /* bound to 5353 (may be NULL) */
	LnSock *seph;            /* ephemeral port (may be NULL) */
	LnAddr  to;
	u8     *buf;
} Q;

#define BUFSZ 1500

static int q_open(Q *q)
{
	LnAddr grp;
	int r;
	memset(q, 0, sizeof(*q));
	memset(&grp, 0, sizeof(grp));
	grp.family = 4;
	grp.a[0] = 224; grp.a[3] = 251;
	if (have_server) {
		q->to = server;
	} else {
		q->to = grp;
		q->to.port = MDNS_PORT;
		/* many stacks let only one program bind 5353: failure is fine */
		if (ln_udp_open(MDNS_PORT, &grp, &q->s5353) != LN_OK)
			q->s5353 = NULL;
	}
	r = ln_udp_open(0, NULL, &q->seph);
	if (r != LN_OK) q->seph = NULL;
	if (!q->s5353 && !q->seph) return r;
	q->buf = ln_alloc(BUFSZ);
	if (!q->buf) {
		ln_sock_close(q->s5353);
		ln_sock_close(q->seph);
		return LN_ENOMEM;
	}
	return LN_OK;
}

static void q_close(Q *q)
{
	ln_sock_close(q->s5353);
	ln_sock_close(q->seph);
	ln_free(q->buf);
}

static void q_send(Q *q, const u8 *pkt, int len)
{
	if (len <= 0) return;
	/* legacy unicast (ephemeral port): the reply comes back to it; from 5353
	 * the QU bit asks for unicast too */
	if (q->seph) ln_udp_sendto(q->seph, &q->to, pkt, (size_t)len);
	if (q->s5353) {
		u8 *p = ln_alloc((size_t)len);
		if (p) {
			size_t o = 12;
			int i, nq = ln_be16(pkt + 4);
			char nm[LN_MDNS_NAME];
			memcpy(p, pkt, (size_t)len);
			ln_put_be16(p, 0);              /* mDNS queries from 5353 have ID 0 */
			for (i = 0; i < nq; i++) {
				if (ln_dns_get_name(p, (size_t)len, &o, nm, sizeof(nm), NULL, 0)) break;
				p[o + 2] |= 0x80;           /* QU */
				o += 4;
			}
			ln_udp_sendto(q->s5353, &q->to, p, (size_t)len);
			ln_free(p);
		}
	}
}

/* receive on both sockets for up to ms; feeds m. Returns early once host
 * (if not NULL) has an address. LN_EBREAK on Ctrl-C */
static int q_collect(Q *q, LnMdns *m, int ms, const char *host)
{
	LnAddr a;
	u32 t0 = ln_ms();
	while ((int)(ln_ms() - t0) < ms) {
		int left = ms - (int)(ln_ms() - t0), slice, k;
		if (ln_break()) return LN_EBREAK;
		slice = left > 100 ? 100 : (left > 0 ? left : 1);
		for (k = 0; k < 2; k++) {
			LnSock *s = k ? q->s5353 : q->seph;
			int r;
			if (!s) continue;
			/* poll the second socket briefly when both are open */
			r = ln_udp_recvfrom(s, NULL, q->buf, BUFSZ, (q->s5353 && q->seph) ? slice / 2 + 1 : slice);
			if (r > 0) {
				ln_mdns_feed(m, q->buf, (size_t)r);
				if (host && ln_mdns_addrs(m, host, &a, 1))
					return LN_OK;
			} else if (r == LN_EBREAK) {
				return r;
			}
		}
	}
	return LN_OK;
}

/* one PTR query per type */
static int browse_query(u8 *pkt, size_t n, const char *const *types, u16 id)
{
	int nq = 0, o;
	for (; types[nq]; nq++)
		;
	o = query_start(pkt, n, id, nq);
	for (nq = 0; types[nq] && o > 0; nq++) {
		char t[64];
		ln_snprintf(t, sizeof(t), "%s.local", types[nq]);
		o = query_add(pkt, n, (size_t)o, NULL, t, LN_DNS_PTR, 0);
	}
	return o;
}

/* follow-up: SRV+TXT for instances without SRV, A for hosts without address */
static int followup_query(LnMdns *m, u8 *pkt, size_t n, u16 id)
{
	int i, nq = 0, o = 12;
	if (query_start(pkt, n, id, 0) < 0) return 0;
	for (i = 0; i < m->nrec && nq < 16; i++) {
		Rec *r = &m->rec[i];
		LnAddr a;
		if (r->type == LN_DNS_PTR && !find_rec(m, LN_DNS_SRV, r->data, NULL)) {
			const char *rest = r->data + strlen(r->first);
			int o2;
			if (*rest == '.') rest++;
			o2 = query_add(pkt, n, (size_t)o, r->first, rest, LN_DNS_SRV, 0);
			if (o2 < 0) break;
			o = o2;
			nq++;
			if (!find_rec(m, LN_DNS_TXT, r->data, NULL)) {
				o2 = query_add(pkt, n, (size_t)o, r->first, rest, LN_DNS_TXT, 0);
				if (o2 < 0) break;
				o = o2;
				nq++;
			}
		} else if (r->type == LN_DNS_SRV && !ln_mdns_addrs(m, r->data, &a, 1)) {
			int o2 = query_add(pkt, n, (size_t)o, NULL, r->data, LN_DNS_A, 0);
			if (o2 < 0) break;
			o = o2;
			nq++;
		}
	}
	ln_put_be16(pkt + 4, (u16)nq);
	return nq ? o : 0;
}

int ln_mdns_browse(const char *const *types, int timeout_ms, LnService *out, int max)
{
	Q q;
	LnMdns *m;
	u8 *pkt;
	int r, len, round = 0;
	u16 id;
	u32 t0;
	if (!types) types = ln_mdns_file_types;
	if (timeout_ms < 300) timeout_ms = 300;
	m = ln_mdns_new();
	pkt = ln_alloc(BUFSZ);
	if (!m || !pkt) { ln_free(pkt); ln_mdns_free(m); return LN_ENOMEM; }
	r = q_open(&q);
	if (r != LN_OK) { ln_free(pkt); ln_mdns_free(m); return r; }
	ln_random(&id, sizeof(id));
	t0 = ln_ms();
	len = browse_query(pkt, BUFSZ, types, id);
	q_send(&q, pkt, len);
	/* RFC 6762 5.2: repeat the question after 1 s, then 2 s; follow up on
	 * incomplete answers in between */
	while ((r = (int)(ln_ms() - t0)) < timeout_ms) {
		int slice = LN_MIN(timeout_ms - r, round < 1 ? 700 : 1000);
		r = q_collect(&q, m, slice, NULL);
		if (r == LN_EBREAK) break;
		round++;
		len = followup_query(m, pkt, BUFSZ, (u16)(id + round));
		if (len > 0)
			q_send(&q, pkt, len);
		if (round == 2 || round == 4) {
			len = browse_query(pkt, BUFSZ, types, (u16)(id + 100 + round));
			q_send(&q, pkt, len);
		}
	}
	q_close(&q);
	ln_free(pkt);
	if (r == LN_EBREAK) { ln_mdns_free(m); return LN_EBREAK; }
	r = ln_mdns_services(m, types, out, max);
	ln_mdns_free(m);
	return r;
}

int ln_mdns_resolve(const char *name, LnAddr *out, int max)
{
	Q q;
	LnMdns *m;
	u8 pkt[300];
	char host[LN_MDNS_NAME];
	int r, len, n = 0, tries;
	u16 id;
	const char *nm[1];
	u16 ty[1];
	ln_strlcpy(host, name, sizeof(host));
	len = (int)strlen(host);
	if (len && host[len - 1] == '.') host[--len] = 0;
	if (max <= 0 || !len) return LN_EINVAL;
	m = ln_mdns_new();
	if (!m) return LN_ENOMEM;
	r = q_open(&q);
	if (r != LN_OK) { ln_mdns_free(m); return r; }
	ln_random(&id, sizeof(id));
	nm[0] = host;
	ty[0] = LN_DNS_A;
	for (tries = 0; tries < 3 && !n; tries++) {
		len = ln_mdns_query(pkt, sizeof(pkt), (u16)(id + tries), nm, ty, 1, 0);
		q_send(&q, pkt, len);
		r = q_collect(&q, m, 400 + tries * 400, host);
		n = ln_mdns_addrs(m, host, out, max);
		if (r == LN_EBREAK) break;
	}
	q_close(&q);
	ln_mdns_free(m);
	if (n > 0) {
		int i;
		for (i = 0; i < n; i++) out[i].port = 0;
		return n;
	}
	return r == LN_EBREAK ? r : LN_ENOHOST;
}
