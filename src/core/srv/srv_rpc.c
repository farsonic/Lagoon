/*
 * Lagoon - SMB2 server: \PIPE\srvsvc on IPC$ (DCE/RPC connection-oriented
 * PDUs, C706; NDR; MS-SRVS): BIND/ALTER_CONTEXT, NetrShareEnum (levels 0,
 * 1, 2), NetrShareGetInfo (0, 1, 2, 501, 1005) and NetrServerGetInfo (100,
 * 101) - what Explorer, Finder and smbclient -L ask for.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "srv_int.h"
#include "../ln_charset.h"

static const u8 srvsvc_uuid[16] = { 0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 };
static const u8 ndr_uuid[16] = { 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 };

#define WERR_OK            0
#define WERR_INVALID_LEVEL 124
#define NERR_NETNAME_NOT_FOUND 2310

/* ---------------------------------------------------------------- NDR */

typedef struct Ndr {
	u8 *b;
	size_t n, cap;
	int err;
	u32 ref;
} Ndr;

static u8 *ndr_room(Ndr *w, size_t k)
{
	if (w->err)
		return NULL;
	if (w->n + k > w->cap) {
		size_t nc = (w->n + k) * 2 + 256;
		u8 *nb = ln_realloc(w->b, w->cap, nc);
		if (!nb || nc > 512 * 1024) {
			w->err = 1;
			return NULL;
		}
		w->b = nb;
		w->cap = nc;
	}
	w->n += k;
	return w->b + w->n - k;
}

static void ndr_align(Ndr *w)
{
	while ((w->n & 3) && ndr_room(w, 1))
		w->b[w->n - 1] = 0;
}

static void ndr32(Ndr *w, u32 v)
{
	u8 *p;
	ndr_align(w);
	if ((p = ndr_room(w, 4)) != NULL)
		ln_put_le32(p, v);
}

static void ndr_ptr(Ndr *w, int present)
{
	ndr32(w, present ? (w->ref += 4) + 0x00020000u : 0);
}

/* conformant varying UTF-16 string with its NUL */
static void ndr_str(Ndr *w, const char *s)
{
	u8 t[600];
	int n = ln_utf8_to_utf16le(s, strlen(s), t, sizeof(t) - 2);
	u8 *p;
	if (n < 0) n = 0;
	t[n] = t[n + 1] = 0;
	n += 2;
	ndr32(w, (u32)n / 2);
	ndr32(w, 0);
	ndr32(w, (u32)n / 2);
	if ((p = ndr_room(w, (size_t)n)) != NULL)
		memcpy(p, t, (size_t)n);
	ndr_align(w);
}

/* skip a conformant varying string in a request; -1 if malformed */
static int skip_str(const u8 *s, size_t n, size_t *o, char *out, size_t max)
{
	u32 cnt;
	*o = (*o + 3) & ~(size_t)3;
	if (*o + 12 > n)
		return -1;
	cnt = ln_le32(s + *o + 8);
	*o += 12;
	if (cnt > 1024 || *o + (size_t)cnt * 2 > n)
		return -1;
	if (out) {
		size_t b = (size_t)cnt * 2;
		if (b >= 2 && !s[*o + b - 2] && !s[*o + b - 1])
			b -= 2;
		srv_utf16_to_utf8(s + *o, b, out, max);
	}
	*o += (size_t)cnt * 2;
	*o = (*o + 3) & ~(size_t)3;
	return 0;
}

/* ---------------------------------------------------------- shares */

typedef struct Sh {
	const char *name, *comment, *path;
	u32 type;
} Sh;

static int share_list(LnSrvConn *c, Sh *out, int max)
{
	int i, n = 0;
	for (i = 0; i < c->srv->nshares && n < max; i++) {
		out[n].name = c->srv->share[i].name;
		out[n].comment = c->srv->share[i].comment;
		out[n].path = c->srv->share[i].path;
		out[n].type = 0;                   /* STYPE_DISKTREE */
		n++;
	}
	if (n < max) {
		out[n].name = "IPC$";
		out[n].comment = "IPC Service";
		out[n].path = "";
		out[n].type = 0x80000003u;         /* STYPE_IPC | STYPE_SPECIAL */
		n++;
	}
	return n;
}

/* fixed part of one SHARE_INFO_<level> (pointers only) */
static void share_fixed(Ndr *w, int level, const Sh *s)
{
	ndr_ptr(w, 1);                                  /* netname */
	if (level == 0)
		return;
	ndr32(w, s->type);
	ndr_ptr(w, 1);                                  /* remark */
	if (level == 2) {
		ndr32(w, 0);                                /* permissions */
		ndr32(w, 0xffffffffu);                      /* max uses */
		ndr32(w, 0);                                /* current uses */
		ndr_ptr(w, 1);                              /* path */
		ndr_ptr(w, 0);                              /* password */
	}
	if (level == 501)
		ndr32(w, 0);                                /* flags: manual caching */
}

static void share_strings(Ndr *w, int level, const Sh *s)
{
	ndr_str(w, s->name);
	if (level == 0)
		return;
	ndr_str(w, s->comment);
	if (level == 2) {
		char p[160];
		ln_snprintf(p, sizeof(p), "%s", s->path[0] ? s->path : "C:\\");
		ndr_str(w, p);
	}
}

static void net_share_enum(LnSrvConn *c, const u8 *s, size_t n, Ndr *w)
{
	size_t o = 0;
	u32 level, resume_ptr;
	Sh sh[LN_SRV_MAX_SHARES + 1];
	int cnt, i;
	if (n < 4)
		goto bad;
	o = 4;
	if (ln_le32(s) && skip_str(s, n, &o, NULL, 0))
		goto bad;
	if (o + 12 > n)
		goto bad;
	level = ln_le32(s + o);
	o += 8;                                         /* level, union switch */
	if (ln_le32(s + o)) {                           /* container pointer */
		o += 4;
		if (o + 8 > n || ln_le32(s + o + 4))        /* EntriesRead, Buffer (must be NULL) */
			goto bad;
		o += 8;
	} else
		o += 4;
	o += 4;                                         /* PreferedMaximumLength */
	resume_ptr = o + 4 <= n ? ln_le32(s + o) : 0;
	cnt = share_list(c, sh, LN_SRV_MAX_SHARES + 1);
	if (level != 0 && level != 1 && level != 2) {
		ndr32(w, level);
		ndr32(w, level);
		ndr_ptr(w, 0);
		ndr32(w, 0);
		ndr_ptr(w, resume_ptr != 0);
		if (resume_ptr) ndr32(w, 0);
		ndr32(w, WERR_INVALID_LEVEL);
		return;
	}
	ndr32(w, level);
	ndr32(w, level);
	ndr_ptr(w, 1);                                  /* container */
	ndr32(w, (u32)cnt);
	ndr_ptr(w, cnt > 0);                            /* Buffer */
	ndr32(w, (u32)cnt);                             /* array size */
	for (i = 0; i < cnt; i++)
		share_fixed(w, (int)level, &sh[i]);
	for (i = 0; i < cnt; i++)
		share_strings(w, (int)level, &sh[i]);
	ndr32(w, (u32)cnt);                             /* TotalEntries */
	ndr_ptr(w, resume_ptr != 0);
	if (resume_ptr) ndr32(w, 0);
	ndr32(w, WERR_OK);
	return;
bad:
	w->err = 2;
}

static void net_share_get_info(LnSrvConn *c, const u8 *s, size_t n, Ndr *w)
{
	size_t o = 4;
	char name[128];
	u32 level;
	Sh sh[LN_SRV_MAX_SHARES + 1];
	int cnt, i;
	if (n < 4 || (ln_le32(s) && skip_str(s, n, &o, NULL, 0)) || skip_str(s, n, &o, name, sizeof(name)) || o + 4 > n) {
		w->err = 2;
		return;
	}
	level = ln_le32(s + o);
	cnt = share_list(c, sh, LN_SRV_MAX_SHARES + 1);
	for (i = 0; i < cnt; i++)
		if (!ln_strcasecmp(sh[i].name, name))
			break;
	ndr32(w, level);
	if (i == cnt || (level != 0 && level != 1 && level != 2 && level != 501 && level != 1005)) {
		ndr_ptr(w, 0);
		ndr32(w, i == cnt ? NERR_NETNAME_NOT_FOUND : WERR_INVALID_LEVEL);
		return;
	}
	ndr_ptr(w, 1);
	if (level == 1005) {
		ndr32(w, 0);                                /* share flags: manual caching */
	} else {
		share_fixed(w, (int)level, &sh[i]);
		share_strings(w, (int)level, &sh[i]);
	}
	ndr32(w, WERR_OK);
}

static void net_server_get_info(LnSrvConn *c, const u8 *s, size_t n, Ndr *w)
{
	size_t o = 4;
	u32 level;
	if (n < 4 || (ln_le32(s) && skip_str(s, n, &o, NULL, 0)) || o + 4 > n) {
		w->err = 2;
		return;
	}
	level = ln_le32(s + o);
	ndr32(w, level);
	if (level != 100 && level != 101) {
		ndr_ptr(w, 0);
		ndr32(w, WERR_INVALID_LEVEL);
		return;
	}
	ndr_ptr(w, 1);
	ndr32(w, 500);                                  /* PLATFORM_ID_NT */
	ndr_ptr(w, 1);
	if (level == 101) {
		ndr32(w, 6);
		ndr32(w, 1);
		ndr32(w, 0x00000003u | 0x00001000u);       /* workstation, server, NT */
		ndr_ptr(w, 1);
	}
	ndr_str(w, c->srv->cfg.name);
	if (level == 101)
		ndr_str(w, c->srv->cfg.comment[0] ? c->srv->cfg.comment : "Amiga");
	ndr32(w, WERR_OK);
}

/* ----------------------------------------------------------- PDUs */

static void pdu_hdr(u8 *p, u8 type, u8 flags, u16 len, u32 call)
{
	p[0] = 5; p[1] = 0; p[2] = type; p[3] = flags;
	p[4] = 0x10; p[5] = 0; p[6] = 0; p[7] = 0;
	ln_put_le16(p + 8, len);
	ln_put_le16(p + 10, 0);
	ln_put_le32(p + 12, call);
}

static int out_add(SrvOpen *o, const u8 *d, size_t n)
{
	u8 *b;
	if (o->poutoff && o->poutoff == o->poutlen) {
		o->poutoff = o->poutlen = 0;
	}
	b = ln_realloc(o->pout, o->poutlen, o->poutlen + n);
	if (!b)
		return LN_ENOMEM;
	o->pout = b;
	memcpy(o->pout + o->poutlen, d, n);
	o->poutlen += n;
	return LN_OK;
}

static int bind_ack(LnSrvConn *c, SrvOpen *o, const u8 *p, size_t n, int alter)
{
	u8 r[512];
	size_t k, i, nctx;
	const u8 *q;
	static const char addr[] = "\\PIPE\\srvsvc";
	u16 max_recv;
	if (n < 28)
		return LN_EPROTO;
	max_recv = ln_le16(p + 18);
	o->max_frag = max_recv >= 1024 && max_recv < 4280 ? max_recv : 4280;
	nctx = p[24];
	memset(r, 0, sizeof(r));
	ln_put_le16(r + 16, 4280);
	ln_put_le16(r + 18, 4280);
	ln_put_le32(r + 20, ln_le32(p + 20) ? ln_le32(p + 20) : 0x12345);
	k = 24;
	if (alter) {
		ln_put_le16(r + k, 0);
		k += 2;
	} else {
		ln_put_le16(r + k, sizeof(addr));
		memcpy(r + k + 2, addr, sizeof(addr));
		k += 2 + sizeof(addr);
	}
	while (k & 3) k++;
	r[k] = (u8)nctx;
	k += 4;
	q = p + 28;
	for (i = 0; i < nctx; i++) {
		size_t nts, j;
		int ok = 0;
		if ((size_t)(q - p) + 24 > n || k + 24 > sizeof(r))
			return LN_EPROTO;
		nts = q[2];
		if ((size_t)(q - p) + 24 + 20 * nts > n)
			return LN_EPROTO;
		if (!memcmp(q + 4, srvsvc_uuid, 16) && ln_le16(q + 20) == 3)
			for (j = 0; j < nts; j++)
				if (!memcmp(q + 24 + 20 * j, ndr_uuid, 16) && ln_le32(q + 24 + 20 * j + 16) == 2)
					ok = 1;
		if (ok) {
			ln_put_le16(r + k, 0);
			ln_put_le16(r + k + 2, 0);
			memcpy(r + k + 4, ndr_uuid, 16);
			ln_put_le32(r + k + 20, 2);
			o->bound = 1;
		} else {
			ln_put_le16(r + k, 2);                  /* provider rejection */
			ln_put_le16(r + k + 2, memcmp(q + 4, srvsvc_uuid, 16) ? 1 : 2);
		}
		k += 24;
		q += 24 + 20 * nts;
	}
	pdu_hdr(r, alter ? 15 : 12, 3, (u16)k, ln_le32(p + 12));
	return out_add(o, r, k);
}

static int fault(SrvOpen *o, u32 call, u32 status)
{
	u8 r[32];
	memset(r, 0, sizeof(r));
	pdu_hdr(r, 3, 3, 32, call);
	ln_put_le32(r + 16, 32);
	ln_put_le32(r + 24, status);
	return out_add(o, r, 32);
}

static int request(LnSrvConn *c, SrvOpen *o, const u8 *p, size_t n)
{
	u32 call = ln_le32(p + 12);
	u16 opnum = ln_le16(p + 22), ctx = ln_le16(p + 20);
	size_t so = (p[3] & 0x80) ? 40 : 24, off, maxstub;
	Ndr w;
	int r = LN_OK;
	if (n < so || !o->bound)
		return fault(o, call, 0x1c010002u);
	if ((p[3] & 3) != 3) {
		LN_LOG(1, "server: %s: fragmented RPC request not supported", c->peer);
		return fault(o, call, 0x1c010002u);
	}
	memset(&w, 0, sizeof(w));
	switch (opnum) {
	case 15: net_share_enum(c, p + so, n - so, &w); break;
	case 16: net_share_get_info(c, p + so, n - so, &w); break;
	case 21: net_server_get_info(c, p + so, n - so, &w); break;
	default:
		LN_LOG(2, "server: %s: srvsvc opnum %u not supported", c->peer, opnum);
		return fault(o, call, 0x1c010002u);   /* nca_s_op_rng_error */
	}
	if (w.err) {
		ln_free(w.b);
		return w.err == 2 ? fault(o, call, 0x1c01000bu) : LN_ENOMEM;   /* nca_s_bad_stub_data */
	}
	/* responses, fragmented to the client's size (stub chunks of 8n bytes) */
	maxstub = ((size_t)o->max_frag - 24) & ~(size_t)7;
	off = 0;
	do {
		size_t k = w.n - off < maxstub ? w.n - off : maxstub;
		u8 h[24];
		u8 fl = (u8)((off == 0 ? 1 : 0) | (off + k == w.n ? 2 : 0));
		pdu_hdr(h, 2, fl, (u16)(24 + k), call);
		ln_put_le32(h + 16, (u32)(w.n - off));
		ln_put_le16(h + 20, ctx);
		h[22] = 0;
		h[23] = 0;
		if ((r = out_add(o, h, 24)) != LN_OK || (r = out_add(o, w.b + off, k)) != LN_OK)
			break;
		off += k;
	} while (off < w.n);
	ln_free(w.b);
	return r;
}

int srv_rpc_input(LnSrvConn *c, SrvOpen *o, const u8 *pdu, size_t n)
{
	while (n >= 16) {
		u16 fl = ln_le16(pdu + 8);
		int r;
		if (pdu[0] != 5 || fl < 16 || fl > n || !(pdu[4] & 0x10))
			return LN_EPROTO;
		switch (pdu[2]) {
		case 11: r = bind_ack(c, o, pdu, fl, 0); break;
		case 14: r = bind_ack(c, o, pdu, fl, 1); break;
		case 0: r = request(c, o, pdu, fl); break;
		default: r = LN_OK; break;     /* auth3, orphaned, shutdown: ignored */
		}
		if (r)
			return r;
		pdu += fl;
		n -= fl;
	}
	return LN_OK;
}
