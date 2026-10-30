/*
 * Lagoon - AFP backend: DSI transport (framing, sessions, tickles,
 * attentions) and the AFP packing/parsing helpers.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "afp_int.h"
#include "../ln_sys.h"
#include "../ln_charset.h"

/* ------------------------------------------------------------ DSI ---- */

void dsi_put_header(u8 h[DSI_HDR], int flags, int cmd, u16 id, u32 code, u32 len)
{
	h[0] = (u8)flags;
	h[1] = (u8)cmd;
	ln_put_be16(h + 2, id);
	ln_put_be32(h + 4, code);
	ln_put_be32(h + 8, len);
	ln_put_be32(h + 12, 0);
}

void dsi_get_header(const u8 h[DSI_HDR], DsiHdr *d)
{
	d->flags = h[0];
	d->cmd = h[1];
	d->id = ln_be16(h + 2);
	d->code = ln_be32(h + 4);
	d->len = ln_be32(h + 8);
}

static int conn_fail(AfpConn *c, int r)
{
	if (c->s) {
		ln_sock_close(c->s);
		c->s = NULL;
	}
	return r == LN_EBREAK ? r : LN_ECONNRESET;
}

static int send_all(AfpConn *c, const void *p, size_t n)
{
	int r = ln_tcp_send(c->s, p, n, c->timeout_ms);
	if (r < 0)
		return conn_fail(c, r);
	c->last_tx = ln_ms();
	return LN_OK;
}

static int recv_all(AfpConn *c, void *p, size_t n)
{
	int r = n ? ln_tcp_recv(c->s, p, n, c->timeout_ms) : 0;
	return r < 0 ? conn_fail(c, r) : LN_OK;
}

/* throw away n bytes of payload */
static int skip(AfpConn *c, u32 n)
{
	u8 tmp[256];
	while (n) {
		u32 k = n > sizeof(tmp) ? (u32)sizeof(tmp) : n;
		int r = recv_all(c, tmp, k);
		if (r)
			return r;
		n -= k;
	}
	return LN_OK;
}

/* a request from the server (header already read): tickle, attention, close */
static int server_request(AfpConn *c, const DsiHdr *h)
{
	u8 hb[DSI_HDR], pl[2];
	int r;
	switch (h->cmd) {
	case DSI_TICKLE:
		/* the server drops clients it has not heard from for a while:
		 * answer with our own tickle when we have been quiet (e.g. while
		 * waiting for a slow reply) */
		if ((r = skip(c, h->len)) != 0)
			return r;
		if ((u32)(ln_ms() - c->last_tx) < 20000)
			return LN_OK;
		dsi_put_header(hb, DSI_REQUEST, DSI_TICKLE, c->reqid++, 0, 0);
		return send_all(c, hb, DSI_HDR);
	case DSI_ATTENTION:
		pl[0] = pl[1] = 0;
		if (h->len >= 2) {
			if ((r = recv_all(c, pl, 2)) != 0 || (r = skip(c, h->len - 2)) != 0)
				return r;
		} else if ((r = skip(c, h->len)) != 0)
			return r;
		c->attention = ln_be16(pl);
		LN_LOG(1, "afp: server attention 0x%04x%s%s (%d min)", (unsigned)c->attention,
		       c->attention & DSIATTN_SHUTDOWN ? " shutdown" : "",
		       c->attention & DSIATTN_MESSAGE ? " message" : "", c->attention & DSIATTN_MINUTES);
		/* attentions are acknowledged with an empty reply */
		dsi_put_header(hb, DSI_REPLY, DSI_ATTENTION, h->id, 0, 0);
		return send_all(c, hb, DSI_HDR);
	case DSI_CLOSESESSION:
		LN_LOG(1, "afp: server closed the session");
		c->closed_by_server = 1;
		return conn_fail(c, LN_ECONNRESET);
	default:
		LN_LOG(1, "afp: unexpected DSI request %d from server", h->cmd);
		return skip(c, h->len);
	}
}

int afp_transact(AfpConn *c, int dsicmd, const u8 *req, size_t reqlen, const void *wdata, size_t wlen,
                 void *reply, size_t rmax, size_t *rlen, s32 *code)
{
	u8 h[DSI_HDR];
	DsiHdr d;
	u16 id;
	int r;
	if (!c->s)
		return LN_ECONNRESET;
	id = c->reqid++;
	dsi_put_header(h, DSI_REQUEST, dsicmd, id, dsicmd == DSI_WRITE ? (u32)reqlen : 0, (u32)(reqlen + wlen));
	if ((r = send_all(c, h, DSI_HDR)) != 0 || (reqlen && (r = send_all(c, req, reqlen)) != 0) ||
	    (wlen && (r = send_all(c, wdata, wlen)) != 0))
		return r;
	for (;;) {
		if ((r = recv_all(c, h, DSI_HDR)) != 0)
			return r;
		dsi_get_header(h, &d);
		if (d.flags == DSI_REQUEST) {
			if ((r = server_request(c, &d)) != 0)
				return r;
			continue;
		}
		if (d.flags != DSI_REPLY || d.id != id || d.cmd != dsicmd) {
			/* a reply to something we gave up on: skip it */
			LN_LOG(2, "afp: stray DSI reply cmd %d id %u (want %u)", d.cmd, d.id, id);
			if ((r = skip(c, d.len)) != 0)
				return r;
			continue;
		}
		break;
	}
	{
		size_t take = d.len < rmax ? d.len : rmax;
		if ((r = recv_all(c, reply, take)) != 0 || (r = skip(c, d.len - (u32)take)) != 0)
			return r;
		if (rlen)
			*rlen = take;
	}
	if (code)
		*code = (s32)d.code;
	return LN_OK;
}

int afp_conn_open(AfpConn *c, const char *host, u16 port, int timeout_ms)
{
	u8 opt[6], rep[64];
	size_t n, i;
	s32 code;
	int r;
	memset(c, 0, sizeof(*c));
	c->timeout_ms = timeout_ms;
	c->reqid = (u16)(ln_ms() & 0x7fff);
	r = ln_tcp_connect(host, port, timeout_ms, &c->s);
	if (r < 0) {
		c->s = NULL;
		return r;
	}
	/* we take attentions of up to 1 KB */
	opt[0] = DSIOPT_ATTNQUANT;
	opt[1] = 4;
	ln_put_be32(opt + 2, 1024);
	r = afp_transact(c, DSI_OPENSESSION, opt, sizeof(opt), NULL, 0, rep, sizeof(rep), &n, &code);
	if (r)
		return r;
	if (code) {
		afp_conn_close(c, 0);
		return code == kFPServerGoingDown || code == kFPNoServer ? LN_ECONNREFUSED : afp_err(code);
	}
	c->quantum = 0x20000;  /* conservative if the server does not say */
	for (i = 0; i + 2 <= n && i + 2 + rep[i + 1] <= n; i += 2 + rep[i + 1])
		if (rep[i] == DSIOPT_SERVQUANT && rep[i + 1] == 4)
			c->quantum = ln_be32(rep + i + 2);
	if (c->quantum < 4096)
		c->quantum = 4096;
	LN_LOG(2, "afp: DSI session open, server quantum %u", c->quantum);
	return LN_OK;
}

void afp_conn_close(AfpConn *c, int polite)
{
	if (c->s && polite) {
		u8 h[DSI_HDR];
		dsi_put_header(h, DSI_REQUEST, DSI_CLOSESESSION, c->reqid++, 0, 0);
		ln_tcp_send(c->s, h, DSI_HDR, 2000);
	}
	if (c->s)
		ln_sock_close(c->s);
	c->s = NULL;
}

int afp_conn_tickle(AfpConn *c)
{
	u8 h[DSI_HDR];
	DsiHdr d;
	int r;
	if (!c->s)
		return LN_ECONNRESET;
	/* drain what arrived while idle: only whole packets, waiting briefly */
	for (;;) {
		r = ln_tcp_recv_some(c->s, h, 1, 1);
		if (r == LN_ETIMEDOUT)
			break;
		if (r <= 0)
			return conn_fail(c, r);
		if ((r = recv_all(c, h + 1, DSI_HDR - 1)) != 0)
			return r;
		dsi_get_header(h, &d);
		if (d.flags == DSI_REQUEST)
			r = server_request(c, &d);
		else
			r = skip(c, d.len);
		if (r)
			return r;
	}
	dsi_put_header(h, DSI_REQUEST, DSI_TICKLE, c->reqid++, 0, 0);
	return send_all(c, h, DSI_HDR);
}

int afp_getstatus(const char *host, u16 port, int timeout_ms, u8 *buf, size_t max, size_t *len)
{
	AfpConn c;
	s32 code;
	int r;
	memset(&c, 0, sizeof(c));
	c.timeout_ms = timeout_ms;
	c.reqid = 1;
	r = ln_tcp_connect(host, port, timeout_ms, &c.s);
	if (r < 0)
		return r;
	r = afp_transact(&c, DSI_GETSTATUS, NULL, 0, NULL, 0, buf, max, len, &code);
	afp_conn_close(&c, 0);
	if (r == LN_ECONNRESET)
		return LN_EPROTO;
	return r ? r : code ? afp_err(code) : LN_OK;
}

/* ------------------------------------------------------- AFP misc ---- */

int afp_err(s32 code)
{
	switch (code) {
	case kFPNoErr: return LN_OK;
	case kFPObjectNotFound: case kFPDirNotFound: case kFPItemNotFound:
	case kFPIDNotFound: return LN_ENOENT;
	case kFPAccessDenied: case kFPCantRename: case kFPCantMove:
	case kFPInsideSharedErr: case kFPInsideTrashErr: case kFPContainsSharedErr: return LN_EACCES;
	case kFPObjectExists: case kFPIDExists: return LN_EEXIST;
	case kFPDirNotEmpty: return LN_ENOTEMPTY;
	case kFPVolLocked: return LN_EROFS;
	case kFPDiskFull: case kFPDiskQuotaExceeded: return LN_ENOSPC;
	case kFPUserNotAuth: case kFPBadUAM: case kFPPwdExpiredErr:
	case kFPPwdNeedsChangeErr: return LN_EAUTH;
	case kFPParamErr: case kFPBitmapErr: case kFPBadIDErr: case kFPSameObjectErr: return LN_EINVAL;
	case kFPObjectLocked: case kFPDenyConflict: case kFPFileBusy: case kFPLockErr:
	case kFPRangeOverlap: case kFPNoMoreLocks: return LN_EINUSE;
	case kFPObjectTypeErr: return LN_ENOTDIR;  /* callers fix up EISDIR where it applies */
	case kFPCallNotSupported: case kFPBadVersNum: case kFPFlatVol: return LN_ENOTSUP;
	case kFPTooManyFilesOpen: return LN_ENOMEM;
	case kFPSessClosed: case kFPServerGoingDown: case kFPNoServer: return LN_ECONNRESET;
	case kFPDiffVolErr: return LN_EINVAL;
	default: return LN_EIO;
	}
}

u32 afp_date_to_unix(u32 d)
{
	s32 s = (s32)d;
	s64 t;
	if (d == AFP_DATE_NONE)
		return 0;
	t = (s64)s + AFP_EPOCH_DELTA;
	if (t < 0)
		t = 0;
	return (u32)t;
}

u32 afp_date_from_unix(u32 t)
{
	return (u32)((s64)t - AFP_EPOCH_DELTA);
}

void afp_b_init(AfpBuf *b, u8 *mem, size_t max)
{
	b->p = mem;
	b->len = 0;
	b->max = max;
	b->err = 0;
}

static u8 *room(AfpBuf *b, size_t n)
{
	u8 *p;
	if (b->err || b->len + n > b->max) {
		b->err = 1;
		return NULL;
	}
	p = b->p + b->len;
	b->len += n;
	return p;
}

void afp_b_u8(AfpBuf *b, unsigned v) { u8 *p = room(b, 1); if (p) *p = (u8)v; }
void afp_b_u16(AfpBuf *b, unsigned v) { u8 *p = room(b, 2); if (p) ln_put_be16(p, (u16)v); }
void afp_b_u32(AfpBuf *b, u32 v) { u8 *p = room(b, 4); if (p) ln_put_be32(p, v); }
void afp_b_u64(AfpBuf *b, u64 v) { u8 *p = room(b, 8); if (p) ln_put_be64(p, v); }
void afp_b_mem(AfpBuf *b, const void *s, size_t n) { u8 *p = room(b, n); if (p && n) memcpy(p, s, n); }

void afp_b_pstr(AfpBuf *b, const char *s)
{
	size_t n = strlen(s);
	if (n > 255) {
		b->err = 1;
		return;
	}
	afp_b_u8(b, (unsigned)n);
	afp_b_mem(b, s, n);
}

void afp_b_pad(AfpBuf *b)
{
	if (b->len & 1)
		afp_b_u8(b, 0);
}

void afp_b_name3(AfpBuf *b, const char *s)
{
	size_t n = strlen(s);
	afp_b_u8(b, AFP_PATH_UTF8);
	afp_b_u16(b, (unsigned)n);
	afp_b_mem(b, s, n);
}

void afp_b_path(AfpBuf *b, const char *path)
{
	u8 *lenp;
	size_t start, i;
	int l;
	afp_b_u8(b, AFP_PATH_UTF8);
	afp_b_u32(b, 0);                     /* text encoding hint */
	lenp = room(b, 2);
	if (!lenp)
		return;
	start = b->len;
	if (b->max - b->len < 2) {
		b->err = 1;
		return;
	}
	l = ln_utf8_nfd(path, (char *)b->p + b->len, b->max - b->len);
	if (l < 0 || (size_t)l > 0xffff) {
		b->err = 1;
		return;
	}
	for (i = 0; i < (size_t)l; i++)
		if (b->p[start + i] == '/')
			b->p[start + i] = 0;
	b->len += (size_t)l;
	ln_put_be16(lenp, (u16)l);
}

/* ---------------------------------------------------- server info ---- */

static void pstr_copy(char *out, size_t max, const u8 *p, size_t n, size_t off)
{
	size_t l;
	out[0] = 0;
	if (off >= n)
		return;
	l = p[off];
	if (off + 1 + l > n)
		l = n - off - 1;
	if (l >= max)
		l = max - 1;
	memcpy(out, p + off + 1, l);
	out[l] = 0;
}

int afp_parse_srvinfo(const u8 *p, size_t n, AfpSrvInfo *si)
{
	size_t off, i, cnt, namelen;
	memset(si, 0, sizeof(*si));
	if (n < 11)
		return LN_EPROTO;
	pstr_copy(si->machine, sizeof(si->machine), p, n, ln_be16(p));
	si->flags = ln_be16(p + 8);
	pstr_copy(si->name, sizeof(si->name), p, n, 10);
	/* versions */
	off = ln_be16(p + 2);
	if (off < n) {
		cnt = p[off++];
		for (i = 0; i < cnt && off < n; i++) {
			char v[32];
			int rank = 0;
			pstr_copy(v, sizeof(v), p, n, off);
			off += 1 + (size_t)p[off];
			if (!strcmp(v, "AFP3.4")) rank = 34;
			else if (!strcmp(v, "AFP3.3")) rank = 33;
			else if (!strcmp(v, "AFP3.2")) rank = 32;
			else if (!strcmp(v, "AFP3.1")) rank = 31;
			else if (!strcmp(v, "AFPX03")) rank = 30;
			if (rank > si->version) {
				si->version = rank;
				ln_strlcpy(si->version_str, v, sizeof(si->version_str));
			}
		}
	}
	/* UAMs */
	off = ln_be16(p + 4);
	if (off < n) {
		cnt = p[off++];
		for (i = 0; i < cnt && off < n; i++) {
			char u[64];
			pstr_copy(u, sizeof(u), p, n, off);
			off += 1 + (size_t)p[off];
			if (!ln_strcasecmp(u, "No User Authent")) si->uams |= UAM_GUEST;
			else if (!ln_strcasecmp(u, "Cleartxt Passwrd")) si->uams |= UAM_CLEARTXT;
			else if (!ln_strcasecmp(u, "DHCAST128")) si->uams |= UAM_DHCAST128;
			else if (!ln_strcasecmp(u, "DHX2")) si->uams |= UAM_DHX2;
		}
	}
	/* the UTF-8 server name: after the Mac Roman name (padded to even)
	 * come the signature, addresses, directory names and UTF-8 name offsets */
	if (si->flags & AFPSRV_UTF8NAME) {
		off = 10 + 1 + (size_t)p[10];
		off += off & 1;
		if (off + 8 <= n) {
			size_t uo = ln_be16(p + off + 6);
			if (uo && uo + 2 <= n) {
				namelen = ln_be16(p + uo);
				if (uo + 2 + namelen <= n && namelen < sizeof(si->name) && namelen) {
					char tmp[128];
					memcpy(tmp, p + uo + 2, namelen);
					tmp[namelen] = 0;
					if (ln_utf8_nfc(tmp, si->name, sizeof(si->name)) < 0)
						ln_strlcpy(si->name, tmp, sizeof(si->name));
				}
			}
		}
	}
	return LN_OK;
}

/* ---------------------------------------------------- parameters ---- */

int afp_parse_params(const u8 *p, size_t n, u16 bitmap, int isdir, AfpParams *o)
{
	size_t off = 0;
	int bit;
	memset(o, 0, sizeof(*o));
	o->isdir = isdir;
	for (bit = 0; bit < 16; bit++) {
		size_t sz;
		if (!(bitmap & (1u << bit)))
			continue;
		switch (bit) {
		case 0: sz = 2; break;
		case 5: sz = 32; break;
		case 6: case 7: sz = 2; break;
		case 9: sz = isdir ? 2 : 4; break;
		case 11: sz = isdir ? 4 : 8; break;
		case 12: sz = isdir ? 4 : 2; break;
		case 13: sz = 6; break;
		case 14: if (isdir) return LN_EPROTO; sz = 8; break;
		case 15: sz = 16; break;
		default: sz = 4; break;     /* 1-4, 8, 10 */
		}
		if (off + sz > n)
			return LN_EPROTO;
		switch (bit) {
		case 0: o->attr = ln_be16(p + off); break;
		case 1: o->pdid = ln_be32(p + off); break;
		case 2: o->cdate = afp_date_to_unix(ln_be32(p + off)); break;
		case 3: o->mdate = afp_date_to_unix(ln_be32(p + off)); break;
		case 8: o->nodeid = ln_be32(p + off); break;
		case 9:
			if (isdir) o->offspring = ln_be16(p + off);
			else if (!(bitmap & FBIT_XDFLEN)) o->size = ln_be32(p + off);
			break;
		case 11: if (!isdir) o->size = ln_be64(p + off); break;
		case 13: {
			size_t no = ln_be16(p + off), l;
			char tmp[256];
			/* at the offset: text encoding hint (4), length (2), name */
			if (no + 6 > n)
				return LN_EPROTO;
			l = ln_be16(p + no + 4);
			if (no + 6 + l > n || l >= sizeof(tmp))
				return LN_EPROTO;
			memcpy(tmp, p + no + 6, l);
			tmp[l] = 0;
			if (ln_utf8_nfc(tmp, o->name, sizeof(o->name)) < 0)
				return LN_ENAMETOOLONG;
			break;
		}
		case 15:
			o->has_unix = 1;
			o->uid = ln_be32(p + off);
			o->gid = ln_be32(p + off + 4);
			o->perms = ln_be32(p + off + 8);
			o->ua = ln_be32(p + off + 12);
			break;
		default: break;
		}
		off += sz;
	}
	return LN_OK;
}
