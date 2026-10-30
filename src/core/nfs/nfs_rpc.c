/*
 * Lagoon - NFS backend: XDR (RFC 4506), ONC RPC client over TCP with record
 * marking and AUTH_SYS (RFC 5531), portmapper GETPORT (RFC 1833), NFSv3
 * status and attribute helpers (RFC 1813). Written from the RFCs.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "nfs_rpc.h"
#include "../ln_sys.h"

/* ------------------------------------------------------------------ XDR */

void xdr_init_enc(NfsXdr *x, u8 *buf, size_t cap)
{
	x->buf = buf; x->cap = cap; x->len = 0; x->pos = 0; x->err = 0;
}

void xdr_init_dec(NfsXdr *x, const u8 *buf, size_t len)
{
	x->buf = (u8 *)buf; x->len = len; x->cap = 0; x->pos = 0; x->err = 0;
}

static int enc_room(NfsXdr *x, size_t n)
{
	if (x->err || n > x->cap - x->pos) { x->err = 1; return 0; }
	return 1;
}

static int dec_room(NfsXdr *x, size_t n)
{
	if (x->err || n > x->len - x->pos) { x->err = 1; return 0; }
	return 1;
}

void xdr_put_u32(NfsXdr *x, u32 v)
{
	if (!enc_room(x, 4)) return;
	ln_put_be32(x->buf + x->pos, v);
	x->pos += 4;
}

void xdr_put_u64(NfsXdr *x, u64 v)
{
	if (!enc_room(x, 8)) return;
	ln_put_be64(x->buf + x->pos, v);
	x->pos += 8;
}

void xdr_put_fixed(NfsXdr *x, const void *p, size_t n)
{
	size_t pad = (4 - (n & 3)) & 3;
	if (!enc_room(x, n + pad)) return;
	if (n) memcpy(x->buf + x->pos, p, n);
	memset(x->buf + x->pos + n, 0, pad);
	x->pos += n + pad;
}

void xdr_put_opaque(NfsXdr *x, const void *p, size_t n)
{
	xdr_put_u32(x, (u32)n);
	xdr_put_fixed(x, p, n);
}

void xdr_put_string(NfsXdr *x, const char *s)
{
	xdr_put_opaque(x, s, strlen(s));
}

void xdr_put_fh(NfsXdr *x, const NfsFh *fh)
{
	xdr_put_opaque(x, fh->data, fh->len);
}

u32 xdr_get_u32(NfsXdr *x)
{
	u32 v;
	if (!dec_room(x, 4)) return 0;
	v = ln_be32(x->buf + x->pos);
	x->pos += 4;
	return v;
}

u64 xdr_get_u64(NfsXdr *x)
{
	u64 v;
	if (!dec_room(x, 8)) return 0;
	v = ln_be64(x->buf + x->pos);
	x->pos += 8;
	return v;
}

void xdr_skip(NfsXdr *x, size_t n)
{
	n = (n + 3) & ~(size_t)3;
	if (!dec_room(x, n)) return;
	x->pos += n;
}

void xdr_get_fixed(NfsXdr *x, void *p, size_t n)
{
	if (!dec_room(x, n)) { memset(p, 0, n); return; }
	memcpy(p, x->buf + x->pos, n);
	xdr_skip(x, n);
}

const u8 *xdr_get_opaque(NfsXdr *x, u32 *len, u32 max)
{
	u32 n = xdr_get_u32(x);
	const u8 *p;
	*len = 0;
	if (x->err) return NULL;
	if (n > max || n > x->len - x->pos) { x->err = 1; return NULL; }
	p = x->buf + x->pos;
	xdr_skip(x, n);
	if (x->err) return NULL;
	*len = n;
	return p;
}

int xdr_get_string(NfsXdr *x, char *out, size_t outmax)
{
	u32 n;
	const u8 *p = xdr_get_opaque(x, &n, 0x7fffffff);
	if (!p) { if (outmax) out[0] = 0; return LN_EPROTO; }
	if (n >= outmax) { if (outmax) out[0] = 0; return LN_ENAMETOOLONG; }
	memcpy(out, p, n);
	out[n] = 0;
	return LN_OK;
}

int xdr_get_fh(NfsXdr *x, NfsFh *fh)
{
	u32 n;
	const u8 *p = xdr_get_opaque(x, &n, NFS_FHMAX);
	if (!p) { fh->len = 0; return LN_EPROTO; }
	fh->len = n;
	memcpy(fh->data, p, n);
	return LN_OK;
}

void xdr_get_fattr(NfsXdr *x, NfsAttr *a)
{
	a->type = xdr_get_u32(x);
	a->mode = xdr_get_u32(x);
	a->nlink = xdr_get_u32(x);
	a->uid = xdr_get_u32(x);
	a->gid = xdr_get_u32(x);
	a->size = xdr_get_u64(x);
	a->used = xdr_get_u64(x);
	xdr_skip(x, 8);                  /* rdev */
	a->fsid = xdr_get_u64(x);
	a->fileid = xdr_get_u64(x);
	a->atime = xdr_get_u32(x); xdr_skip(x, 4);
	a->mtime = xdr_get_u32(x); xdr_skip(x, 4);
	a->ctime = xdr_get_u32(x); xdr_skip(x, 4);
}

int xdr_get_post_attr(NfsXdr *x, NfsAttr *a)
{
	NfsAttr tmp;
	if (!xdr_get_u32(x)) return 0;
	xdr_get_fattr(x, a ? a : &tmp);
	return !x->err;
}

int xdr_get_wcc(NfsXdr *x, NfsAttr *a)
{
	if (xdr_get_u32(x))
		xdr_skip(x, 24);             /* pre_op_attr: size, mtime, ctime */
	return xdr_get_post_attr(x, a);
}

/* ------------------------------------------------------------------ RPC */

const char *rpc_last_error = "";

int rpc_auth_sys(u8 *out, size_t max, u32 stamp, const char *machine, u32 uid, u32 gid,
                 const u32 *gids, int ngids)
{
	NfsXdr x;
	int i;
	size_t ml = strlen(machine);
	if (ml > 255) ml = 255;
	if (ngids > 16) ngids = 16;
	xdr_init_enc(&x, out, max);
	xdr_put_u32(&x, stamp);
	xdr_put_opaque(&x, machine, ml);
	xdr_put_u32(&x, uid);
	xdr_put_u32(&x, gid);
	xdr_put_u32(&x, (u32)ngids);
	for (i = 0; i < ngids; i++)
		xdr_put_u32(&x, gids[i]);
	return x.err ? -1 : (int)x.pos;
}

void rpc_begin_call(NfsXdr *x, u32 xid, u32 prog, u32 vers, u32 proc, const u8 *cred, size_t credlen)
{
	xdr_put_u32(x, 0);               /* record mark, filled by rpc_finish_call */
	xdr_put_u32(x, xid);
	xdr_put_u32(x, 0);               /* CALL */
	xdr_put_u32(x, 2);               /* RPC version */
	xdr_put_u32(x, prog);
	xdr_put_u32(x, vers);
	xdr_put_u32(x, proc);
	if (credlen) {
		xdr_put_u32(x, 1);           /* AUTH_SYS */
		xdr_put_opaque(x, cred, credlen);
	} else {
		xdr_put_u32(x, 0);           /* AUTH_NONE */
		xdr_put_u32(x, 0);
	}
	xdr_put_u32(x, 0);               /* verifier: AUTH_NONE */
	xdr_put_u32(x, 0);
}

size_t rpc_finish_call(NfsXdr *x)
{
	if (x->pos >= 4)
		ln_put_be32(x->buf, 0x80000000u | (u32)(x->pos - 4));
	return x->pos;
}

int rpc_read_record(rpc_read_fn rd, void *ctx, u8 **buf, size_t *cap, size_t *len, size_t max)
{
	size_t total = 0;
	for (;;) {
		u8 h[4];
		u32 fl;
		int last, r = rd(ctx, h, 4);
		if (r) return r;
		fl = ln_be32(h);
		last = (fl & 0x80000000u) != 0;
		fl &= 0x7fffffffu;
		if (fl > max || total + fl > max) {
			rpc_last_error = "reply too large";
			return LN_EPROTO;
		}
		if (total + fl > *cap) {
			size_t nc = *cap ? *cap : 1024;
			u8 *nb;
			while (nc < total + fl) nc *= 2;
			if (nc > max) nc = max;
			nb = ln_realloc(*buf, *cap, nc);
			if (!nb) return LN_ENOMEM;
			*buf = nb;
			*cap = nc;
		}
		if (fl) {
			r = rd(ctx, *buf + total, fl);
			if (r) return r;
		}
		total += fl;
		if (last) break;
	}
	*len = total;
	return LN_OK;
}

int rpc_check_reply(const u8 *p, size_t n, u32 xid, size_t *body)
{
	NfsXdr x;
	u32 st;
	xdr_init_dec(&x, p, n);
	if (xdr_get_u32(&x) != xid) return x.err ? LN_EPROTO : RPC_XID_OTHER;
	if (xdr_get_u32(&x) != 1) { rpc_last_error = "not a reply"; return LN_EPROTO; }
	st = xdr_get_u32(&x);
	if (x.err) return LN_EPROTO;
	if (st == 0) {                   /* MSG_ACCEPTED */
		u32 vl;
		xdr_get_u32(&x);             /* verifier flavor */
		if (!xdr_get_opaque(&x, &vl, 400) && x.err) return LN_EPROTO;
		st = xdr_get_u32(&x);
		if (x.err) return LN_EPROTO;
		switch (st) {
		case 0: *body = x.pos; return LN_OK;
		case 1: rpc_last_error = "program unavailable"; return LN_ENOTSUP;
		case 2: rpc_last_error = "program version mismatch"; return LN_ENOTSUP;
		case 3: rpc_last_error = "procedure unavailable"; return LN_ENOTSUP;
		case 4: rpc_last_error = "garbage arguments"; return LN_EPROTO;
		case 5: rpc_last_error = "server system error"; return LN_EIO;
		}
		rpc_last_error = "unknown accept status";
		return LN_EPROTO;
	}
	if (st == 1) {                   /* MSG_DENIED */
		st = xdr_get_u32(&x);
		if (x.err) return LN_EPROTO;
		if (st == 0) { rpc_last_error = "RPC version mismatch"; return LN_EPROTO; }
		st = xdr_get_u32(&x);
		switch (st) {
		case 1: rpc_last_error = "bad credentials"; break;
		case 2: rpc_last_error = "credentials rejected"; break;
		case 5: rpc_last_error = "authentication too weak (server wants a reserved port?)"; break;
		default: rpc_last_error = "authentication error"; break;
		}
		return LN_EAUTH;
	}
	return LN_EPROTO;
}

static int sock_read(void *ctx, void *buf, size_t n)
{
	NfsRpc *r = ctx;
	return ln_tcp_recv(r->sock, buf, n, r->timeout_ms);
}

int rpc_connect(NfsRpc *r)
{
	int e;
	rpc_disconnect(r);
	if (r->secure) {
		e = ln_tcp_connect_reserved(r->host, r->port, 10000, &r->sock);
		if (e != LN_EACCES)
			return e;
		LN_LOG(1, "nfs: no reserved port available, using an unprivileged one");
	}
	return ln_tcp_connect(r->host, r->port, 10000, &r->sock);
}

void rpc_disconnect(NfsRpc *r)
{
	if (r->sock) {
		ln_sock_close(r->sock);
		r->sock = NULL;
	}
}

int rpc_open(NfsRpc *r, const char *host, u16 port, u32 prog, u32 vers, size_t scap, size_t rmax,
             int secure, int timeout_ms, const u8 *cred, size_t credlen)
{
	memset(r, 0, sizeof(*r));
	ln_strlcpy(r->host, host, sizeof(r->host));
	r->port = port;
	r->prog = prog;
	r->vers = vers;
	r->secure = secure;
	r->timeout_ms = timeout_ms;
	r->rmax = rmax;
	if (credlen > sizeof(r->cred)) return LN_EINVAL;
	if (credlen) memcpy(r->cred, cred, credlen);
	r->credlen = credlen;
	ln_random(&r->xid, sizeof(r->xid));
	r->sbuf = ln_alloc(scap);
	r->scap = scap;
	r->rcap = scap < 4096 ? 4096 : scap;
	if (r->rcap > rmax) r->rcap = rmax;
	r->rbuf = ln_alloc(r->rcap);
	if (!r->sbuf || !r->rbuf) { rpc_close(r); return LN_ENOMEM; }
	return rpc_connect(r);
}

void rpc_close(NfsRpc *r)
{
	rpc_disconnect(r);
	ln_free(r->sbuf);
	ln_free(r->rbuf);
	r->sbuf = r->rbuf = NULL;
}

void rpc_begin(NfsRpc *r, NfsXdr *x, u32 proc)
{
	xdr_init_enc(x, r->sbuf, r->scap);
	rpc_begin_call(x, ++r->xid, r->prog, r->vers, proc, r->cred, r->credlen);
}

/* wait for the reply to the call in sbuf. *rpcerr = 1 if the error came
 * from the RPC layer (the connection itself is fine). */
static int wait_reply(NfsRpc *r, size_t *body, int *rpcerr)
{
	u32 xid = ln_be32(r->sbuf + 4);
	int i, e;
	*rpcerr = 0;
	for (i = 0; i < 32; i++) {
		e = rpc_read_record(sock_read, r, &r->rbuf, &r->rcap, &r->rlen, r->rmax);
		if (e) return e;
		e = rpc_check_reply(r->rbuf, r->rlen, xid, body);
		if (e == RPC_XID_OTHER) continue;    /* late answer to an older call */
		if (e) *rpcerr = 1;
		return e;
	}
	return LN_EPROTO;
}

static int transact(NfsRpc *r, NfsXdr *res)
{
	int attempt, e = LN_ECONNRESET;
	for (attempt = 0; attempt < 2; attempt++) {
		size_t body = 0;
		int rpcerr = 0;
		if (!r->sock) {
			e = rpc_connect(r);
			if (e == LN_EBREAK) return e;
			if (e) continue;
		}
		e = ln_tcp_send(r->sock, r->sbuf, r->slen, r->timeout_ms);
		if (!e) e = wait_reply(r, &body, &rpcerr);
		if (e == LN_OK) {
			xdr_init_dec(res, r->rbuf + body, r->rlen - body);
			return LN_OK;
		}
		if (rpcerr || e == LN_EBREAK || e == LN_ENOMEM) {
			if (e == LN_EAUTH || e == LN_ENOTSUP)
				LN_LOG(1, "nfs: rpc %u/%u: %s", r->prog, r->vers, rpc_last_error);
			return e;
		}
		/* lost connection, timeout or garbled framing: reconnect and
		 * retransmit with the same xid (the server's duplicate request
		 * cache answers non-idempotent calls it already did) */
		LN_LOG(1, "nfs: rpc %u: %s, reconnecting", r->prog, ln_strerror(e));
		rpc_disconnect(r);
	}
	return e == LN_EBREAK ? e : LN_ECONNRESET;
}

int rpc_call(NfsRpc *r, NfsXdr *x, NfsXdr *res)
{
	if (x->err) return LN_EINVAL;    /* request did not fit */
	r->slen = rpc_finish_call(x);
	return transact(r, res);
}

int rpc_recall(NfsRpc *r, NfsXdr *res)
{
	ln_put_be32(r->sbuf + 4, ++r->xid);
	return transact(r, res);
}

int pmap_getport(const char *host, u16 pmport, u32 prog, u32 vers, int timeout_ms, u16 *port)
{
	NfsRpc r;
	NfsXdr x, res;
	int e = rpc_open(&r, host, pmport, PMAP_PROG, PMAP_VERS, 256, 1024, 0, timeout_ms, NULL, 0);
	if (!e) {
		rpc_begin(&r, &x, PMAP_GETPORT);
		xdr_put_u32(&x, prog);
		xdr_put_u32(&x, vers);
		xdr_put_u32(&x, 6);          /* IPPROTO_TCP */
		xdr_put_u32(&x, 0);
		e = rpc_call(&r, &x, &res);
		if (!e) {
			u32 p = xdr_get_u32(&res);
			if (res.err || p > 65535) e = LN_EPROTO;
			else *port = (u16)p;
		}
	}
	rpc_close(&r);
	return e;
}

/* ------------------------------------------------------------------ NFS */

int nfs_stat_to_ln(u32 st)
{
	switch (st) {
	case 0: return LN_OK;
	case 1: return LN_EACCES;        /* PERM */
	case 2: return LN_ENOENT;
	case 5: return LN_EIO;
	case 6: return LN_ENOENT;        /* NXIO */
	case 13: return LN_EACCES;
	case 17: return LN_EEXIST;
	case 18: return LN_EINVAL;       /* XDEV */
	case 19: return LN_ENOENT;       /* NODEV */
	case 20: return LN_ENOTDIR;
	case 21: return LN_EISDIR;
	case 22: return LN_EINVAL;
	case 27: return LN_ENOSPC;       /* FBIG */
	case 28: return LN_ENOSPC;
	case 30: return LN_EROFS;
	case 31: return LN_EIO;          /* MLINK */
	case 63: return LN_ENAMETOOLONG;
	case 66: return LN_ENOTEMPTY;
	case 69: return LN_ENOSPC;       /* DQUOT */
	case 70: return LN_ESTALE;
	case 71: return LN_ENOENT;       /* REMOTE */
	case 10001: return LN_ESTALE;    /* BADHANDLE */
	case 10002: return LN_EIO;       /* NOT_SYNC */
	case 10003: return LN_EIO;       /* BAD_COOKIE */
	case 10004: return LN_ENOTSUP;
	case 10005: return LN_EIO;       /* TOOSMALL */
	case 10006: return LN_EIO;       /* SERVERFAULT */
	case 10007: return LN_ENOTSUP;   /* BADTYPE */
	case 10008: return LN_EINUSE;    /* JUKEBOX (after retries) */
	}
	return LN_EIO;
}

int mnt_stat_to_ln(u32 st)
{
	switch (st) {
	case 0: return LN_OK;
	case 1: case 13: return LN_EACCES;
	case 2: return LN_ENOSHARE;
	case 20: return LN_ENOTDIR;
	case 22: return LN_EINVAL;
	case 63: return LN_ENAMETOOLONG;
	case 10004: return LN_ENOTSUP;
	}
	return LN_EIO;
}

void nfs_attr_to_stat(const NfsAttr *a, u32 uid, u32 gid, const u32 *gids, int ngids, LnStat *st)
{
	u32 bits;
	int i, ingroup = a->gid == gid;
	memset(st, 0, sizeof(*st));
	st->type = a->type == NF3DIR ? LN_T_DIR : a->type == NF3LNK ? LN_T_LINK : LN_T_FILE;
	st->size = a->size;
	st->mtime = a->mtime;
	st->ctime = a->mtime;            /* NFS has no birth time */
	st->mode = a->mode & 07777;
	st->uid = a->uid;
	st->gid = a->gid;
	st->fileid = a->fileid;
	for (i = 0; i < ngids && !ingroup; i++)
		if (a->gid == gids[i]) ingroup = 1;
	if (uid == 0)                    /* root (unless squashed: stat() asks ACCESS) */
		bits = 6 | ((a->mode & 0111) ? 1 : 0);
	else if (a->uid == uid)
		bits = (a->mode >> 6) & 7;
	else if (ingroup)
		bits = (a->mode >> 3) & 7;
	else
		bits = a->mode & 7;
	if (bits & 4) st->prot |= LN_P_READ;
	if (bits & 2) st->prot |= LN_P_WRITE | LN_P_DELETE;
	if (bits & 1) st->prot |= LN_P_EXEC;
}

u32 nfs_access_to_prot(u32 acc, int type)
{
	u32 p = 0;
	if (acc & ACCESS3_READ) p |= LN_P_READ;
	if (acc & ACCESS3_MODIFY) p |= LN_P_WRITE | LN_P_DELETE;
	if (type == LN_T_DIR) {
		if (acc & ACCESS3_LOOKUP) p |= LN_P_EXEC;
		if (acc & (ACCESS3_EXTEND | ACCESS3_DELETE)) p |= LN_P_WRITE | LN_P_DELETE;
	} else if (acc & ACCESS3_EXECUTE)
		p |= LN_P_EXEC;
	return p;
}
