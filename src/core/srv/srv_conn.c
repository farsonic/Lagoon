/*
 * Lagoon - SMB2 server: configuration, one connection's messages (SMB1
 * upgrade, NEGOTIATE with the 3.1.1 contexts and preauth hash, compound
 * requests, credits, signing), dispatch, ECHO and LOGOFF.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "srv_int.h"
#include "../ln_charset.h"
#include "../ln_conf.h"

#define MAX_PIECES 32
#define CREDITS_MAX 512

/* ---------------------------------------------------------------- server */

LnSrv *ln_srv_new(const LnSrvCfg *cfg)
{
	LnSrv *s = ln_alloc(sizeof(LnSrv));
	int i;
	if (!s)
		return NULL;
	s->cfg = *cfg;
	if (!s->cfg.name[0])
		ln_strlcpy(s->cfg.name, "AMIGA", sizeof(s->cfg.name));
	for (i = 0; s->cfg.name[i]; i++)
		if (s->cfg.name[i] >= 'a' && s->cfg.name[i] <= 'z')
			s->cfg.name[i] -= 32;
	if (!s->cfg.domain[0])
		ln_strlcpy(s->cfg.domain, "WORKGROUP", sizeof(s->cfg.domain));
	for (i = 0; s->cfg.domain[i]; i++)
		if (s->cfg.domain[i] >= 'a' && s->cfg.domain[i] <= 'z')
			s->cfg.domain[i] -= 32;
	if (!s->cfg.max_dialect || s->cfg.max_dialect > SMB_D311)
		s->cfg.max_dialect = SMB_D311;
	if (s->cfg.max_io < 4096 || s->cfg.max_io > 65536)
		s->cfg.max_io = 65536;
	if (s->cfg.max_conns <= 0)
		s->cfg.max_conns = 8;
	if (s->cfg.max_opens <= 0)
		s->cfg.max_opens = 64;
	if (s->cfg.name_max <= 0)
		s->cfg.name_max = 255;
	ln_random(s->guid, 16);
	s->start_ft = smb_unix2ft(ln_time_unix());
	return s;
}

void ln_srv_free(LnSrv *s)
{
	if (s) {
		ln_wipe(s->user, sizeof(s->user));
		ln_free(s);
	}
}

const LnSrvCfg *ln_srv_cfg(const LnSrv *s)
{
	return &s->cfg;
}

void ln_srv_set_max_dialect(LnSrv *s, u16 d)
{
	s->cfg.max_dialect = d >= SMB_D202 && d <= SMB_D311 ? d : SMB_D311;
}

int ln_srv_add_share(LnSrv *s, const LnSrvShare *sh)
{
	int i;
	if (!sh->name[0] || !ln_strcasecmp(sh->name, "IPC$"))
		return LN_EINVAL;
	for (i = 0; i < s->nshares; i++)
		if (!ln_strcasecmp(s->share[i].name, sh->name))
			return LN_EEXIST;
	if (s->nshares >= LN_SRV_MAX_SHARES)
		return LN_ENOSPC;
	s->share[s->nshares++] = *sh;
	return LN_OK;
}

int ln_srv_add_user(LnSrv *s, const char *name, const u8 nthash[16])
{
	if (!name[0])
		return LN_EINVAL;
	if (s->nusers >= LN_SRV_MAX_USERS)
		return LN_ENOSPC;
	ln_strlcpy(s->user[s->nusers].name, name, sizeof(s->user[0].name));
	memcpy(s->user[s->nusers].nthash, nthash, 16);
	s->nusers++;
	return LN_OK;
}

int ln_srv_has_guest_share(const LnSrv *s)
{
	int i;
	for (i = 0; i < s->nshares; i++)
		if (s->share[i].guest)
			return 1;
	return 0;
}

/* ------------------------------------------------------------ connection */

LnSrvConn *ln_srv_conn_new(LnSrv *s, const char *peer)
{
	LnSrvConn *c = ln_alloc(sizeof(LnSrvConn));
	if (!c)
		return NULL;
	c->srv = s;
	ln_strlcpy(c->peer, peer ? peer : "?", sizeof(c->peer));
	c->next_sid = 0x0000100000000001ULL ^ ((u64)ln_ms() << 20);
	c->next_fid = 1;
	c->last_ms = ln_ms();
	s->nconns++;
	return c;
}

void srv_session_free(LnSrvConn *c, SrvSession *s)
{
	SrvSession **pp;
	SrvOpen *o, *on;
	for (o = c->opens; o; o = on) {
		SrvTree *t;
		on = o->next;
		for (t = s->trees; t; t = t->next)
			if (o->tree == t)
				break;
		if (t)
			srv_close_open(c, o);
	}
	while (s->trees)
		srv_tree_free(c, s, s->trees);
	for (pp = &c->sessions; *pp; pp = &(*pp)->next)
		if (*pp == s) {
			*pp = s->next;
			break;
		}
	if (s->k) {
		if (s->k->sign_gcm)
			ln_free(s->k->sign_gcm);
		ln_wipe(s->k, sizeof(SmbConn));
		ln_free(s->k);
	}
	if (s->neg) ln_free(s->neg);
	if (s->chal) ln_free(s->chal);
	if (s->mechlist) ln_free(s->mechlist);
	ln_wipe(s, sizeof(*s));
	ln_free(s);
}

void ln_srv_conn_free(LnSrvConn *c)
{
	if (!c)
		return;
	while (c->opens)
		srv_close_open(c, c->opens);
	while (c->sessions)
		srv_session_free(c, c->sessions);
	if (c->srv->nconns > 0)
		c->srv->nconns--;
	ln_free(c->tx);
	ln_free(c);
}

SrvSession *srv_find_session(LnSrvConn *c, u64 id)
{
	SrvSession *s;
	for (s = c->sessions; s; s = s->next)
		if (s->id == id)
			return s;
	return NULL;
}

u32 srv_max_io(const LnSrvConn *c)
{
	return c->dialect == SMB_D202 && c->srv->cfg.max_io > 65536 ? 65536 : c->srv->cfg.max_io;
}

void srv_preauth_add(u8 h[64], const u8 *m, size_t n)
{
	LnSha512 s;
	ln_sha512_init(&s);
	ln_sha512_update(&s, h, 64);
	ln_sha512_update(&s, m, n);
	ln_sha512_final(&s, h);
}

int srv_utf16_to_utf8(const u8 *p, size_t bytes, char *out, size_t max)
{
	int n = ln_utf16le_to_utf8(p, bytes & ~(size_t)1, out, max);
	if (n < 0) {
		if (max) out[0] = 0;
		return -1;
	}
	out[n] = 0;
	return n;
}

/* --------------------------------------------------------- reply buffer */

static int tx_room(LnSrvConn *c, size_t n)
{
	if (c->txlen + n > c->txcap) {
		size_t nc = c->txlen + n + 1024;
		u8 *b;
		if (nc > 256 * 1024)
			return -1;
		b = ln_realloc(c->tx, c->txcap, nc);
		if (!b)
			return -1;
		c->tx = b;
		c->txcap = nc;
	}
	return 0;
}


u8 *srv_body(LnSrvConn *c, size_t n)
{
	u8 *p;
	if (tx_room(c, n))
		return NULL;
	p = c->tx + c->txlen;
	memset(p, 0, n);
	c->txlen += n;
	return p;
}

void srv_set_status(LnSrvConn *c, u32 status)
{
	ln_put_le32(c->tx + c->resp_off + 8, status);
}

void srv_error(LnSrvConn *c, u32 status, const u8 *data, size_t n)
{
	u8 *b;
	c->txlen = c->resp_off + SMB2_HDR;
	srv_set_status(c, status);
	b = srv_body(c, 8 + (n ? n : 1));
	if (!b)
		return;
	ln_put_le16(b, 9);
	ln_put_le32(b + 4, (u32)n);
	if (n)
		memcpy(b + 8, data, n);
}

SrvOpen *srv_find_open(LnSrvConn *c, const u8 *p)
{
	u64 id = ln_le64(p), id2 = ln_le64(p + 8);
	SrvOpen *o;
	if (id == 0xffffffffffffffffULL && id2 == 0xffffffffffffffffULL)
		id = id2 = c->last_fid;
	if (id != id2)
		return NULL;
	for (o = c->opens; o; o = o->next)
		if (o->id == id) {
			/* only the session's own trees */
			SrvTree *t;
			if (!c->sess)
				return NULL;
			for (t = c->sess->trees; t; t = t->next)
				if (t == o->tree)
					return o;
			return NULL;
		}
	return NULL;
}

/* -------------------------------------------------------------- NEGOTIATE */

static const u16 our_dialects[] = { SMB_D311, SMB_D302, SMB_D300, SMB_D210, SMB_D202 };

static u8 *put_ctx(u8 *p, const u8 *base, u16 type, const u8 *data, u16 dlen)
{
	while ((p - base) & 7)
		*p++ = 0;
	ln_put_le16(p, type);
	ln_put_le16(p + 2, dlen);
	ln_put_le32(p + 4, 0);
	memcpy(p + 8, data, dlen);
	return p + 8 + dlen;
}

/* the NEGOTIATE response body for dialect (with 3.1.1 contexts) */
static void negotiate_reply(LnSrvConn *c, u16 dialect, int want_signctx)
{
	u8 *b = srv_body(c, 64 + 96 + 128), *p, *base, d[40];
	size_t bl;
	int nctx = 0;
	u32 caps = 0;
	if (!b)
		return;
	base = b - SMB2_HDR;
	ln_put_le16(b, 65);
	ln_put_le16(b + 2, (u16)(c->srv->cfg.sign_required ? 3 : 1));
	ln_put_le16(b + 4, dialect);
	memcpy(b + 8, c->srv->guid, 16);
	ln_put_le32(b + 24, caps);
	ln_put_le32(b + 28, c->srv->cfg.max_io);
	ln_put_le32(b + 32, c->srv->cfg.max_io);
	ln_put_le32(b + 36, c->srv->cfg.max_io);
	ln_put_le64(b + 40, smb_unix2ft(ln_time_unix()));
	ln_put_le64(b + 48, 0);
	bl = srv_spnego_hint(b + 64);
	ln_put_le16(b + 56, SMB2_HDR + 64);
	ln_put_le16(b + 58, (u16)bl);
	p = b + 64 + bl;
	if (dialect == SMB_D311) {
		while ((p - base) & 7)
			*p++ = 0;
		ln_put_le32(b + 60, (u32)(p - base));
		ln_put_le16(d, 1); ln_put_le16(d + 2, 32); ln_put_le16(d + 4, 1);
		ln_random(d + 6, 32);
		p = put_ctx(p, base, 1, d, 38); nctx++;
		if (want_signctx) {
			ln_put_le16(d, 1); ln_put_le16(d + 2, (u16)c->sign_algo);
			p = put_ctx(p, base, 8, d, 4); nctx++;
		}
		ln_put_le16(b + 6, (u16)nctx);
	}
	c->txlen = (size_t)(p - c->tx);
}

static void srv_negotiate(LnSrvConn *c)
{
	const u8 *b = c->body;
	u16 nd, i, k, dialect = 0;
	int signctx = 0, sha512 = 0;
	if (c->negotiated) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	if (c->blen < 36 || ln_le16(b) != 36 || (nd = ln_le16(b + 2)) == 0 || 36u + 2u * nd > c->blen) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	c->cli_secmode = ln_le16(b + 4);
	c->cli_caps = ln_le32(b + 8);
	memcpy(c->cli_guid, b + 12, 16);
	c->ncli_dialects = 0;
	for (i = 0; i < nd && c->ncli_dialects < 16; i++)
		c->cli_dialects[c->ncli_dialects++] = ln_le16(b + 36 + 2 * i);
	for (k = 0; k < LN_ARRAY_SIZE(our_dialects) && !dialect; k++) {
		if (our_dialects[k] > c->srv->cfg.max_dialect)
			continue;
		for (i = 0; i < nd; i++)
			if (ln_le16(b + 36 + 2 * i) == our_dialects[k]) {
				dialect = our_dialects[k];
				break;
			}
	}
	if (!dialect) {
		LN_LOG(1, "server: %s offers no dialect we speak", c->peer);
		srv_error(c, ST_NOT_SUPPORTED, NULL, 0);
		return;
	}
	c->sign_algo = dialect >= SMB_D300 ? SMB_SIGN_CMAC : SMB_SIGN_HMAC;
	if (dialect == SMB_D311) {
		u32 off = ln_le32(b + 28);
		u16 cnt = ln_le16(b + 32);
		for (i = 0; i < cnt; i++) {
			u16 type, dl;
			const u8 *q;
			off = (off + 7) & ~7u;
			if (off + 8 > c->reqlen)
				break;
			q = c->req + off;
			type = ln_le16(q);
			dl = ln_le16(q + 2);
			if (off + 8 + dl > c->reqlen)
				break;
			q += 8;
			if (type == 1 && dl >= 4) {
				u16 n = ln_le16(q), j;
				for (j = 0; j < n && 4u + 2u * j + 2u <= dl; j++)
					if (ln_le16(q + 4 + 2 * j) == 1)
						sha512 = 1;
			} else if (type == 8 && dl >= 2) {
				u16 n = ln_le16(q), j;
				int best = -1;
				signctx = 1;
				/* the client's order is its preference: GMAC or CMAC */
				for (j = 0; j < n && 2u + 2u * j + 2u <= dl; j++) {
					u16 a = ln_le16(q + 2 + 2 * j);
					if ((a == SMB_SIGN_GMAC || a == SMB_SIGN_CMAC) && best < 0)
						best = a;
				}
				c->sign_algo = best >= 0 ? best : SMB_SIGN_CMAC;
			}
			off += 8 + dl;
		}
		if (!sha512) {
			srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
			return;
		}
		memset(c->preauth, 0, 64);
		srv_preauth_add(c->preauth, c->req, c->reqlen);
	}
	c->dialect = dialect;
	c->negotiated = 1;
	negotiate_reply(c, dialect, signctx);
	if (dialect == SMB_D311)
		srv_preauth_add(c->preauth, c->tx + c->resp_off, c->txlen - c->resp_off);
	LN_LOG(1, "server: %s: dialect %x.%x.%x%s", c->peer, dialect >> 8, (dialect >> 4) & 15, dialect & 15,
	       dialect == SMB_D311 ? (c->sign_algo == SMB_SIGN_GMAC ? ", GMAC signing" : ", CMAC signing") : "");
}

/* an SMB1 NEGOTIATE from a client that also speaks SMB2: answer with an
 * SMB2 NEGOTIATE response (MS-SMB2 3.3.5.3.1) */
static int smb1_negotiate(LnSrvConn *c, const u8 *m, size_t len)
{
	size_t i, bc;
	int two = 0, wild = 0;
	u8 *h;
	if (len < 35 || m[4] != 0x72 || c->negotiated)
		return LN_EPROTO;
	bc = ln_le16(m + 33);
	if (35 + bc > len)
		return LN_EPROTO;
	for (i = 35; i < 35 + bc;) {
		const char *s = (const char *)m + i + 1;
		size_t l = 0;
		if (m[i] != 2)
			break;
		while (i + 1 + l < 35 + bc && s[l]) l++;
		if (l == 9 && !memcmp(s, "SMB 2.002", 9)) two = 1;
		if (l == 9 && !memcmp(s, "SMB 2.???", 9)) wild = 1;
		i += 2 + l;
	}
	if (!two && !wild) {
		LN_LOG(1, "server: %s speaks only SMB1, which Lagoon does not serve", c->peer);
		return LN_ENOTSUP;
	}
	c->txlen = 4;
	c->resp_off = 4;
	h = srv_body(c, SMB2_HDR);
	if (!h)
		return LN_ENOMEM;
	memcpy(h, "\xfeSMB", 4);
	ln_put_le16(h + 4, 64);
	ln_put_le16(h + 14, 1);
	ln_put_le32(h + 16, SMB2_FLAGS_SERVER_TO_REDIR);
	if (wild && (c->srv->cfg.max_dialect > SMB_D202 || !two)) {
		negotiate_reply(c, 0x02ff, 0);
	} else {
		c->dialect = SMB_D202;
		c->negotiated = 1;
		c->sign_algo = SMB_SIGN_HMAC;
		negotiate_reply(c, SMB_D202, 0);
	}
	c->credits = 1;
	return LN_OK;
}

/* ------------------------------------------------------------ dispatch */

static void srv_echo(LnSrvConn *c)
{
	u8 *b = srv_body(c, 4);
	if (b)
		ln_put_le16(b, 4);
}

static void srv_logoff(LnSrvConn *c)
{
	u8 *b = srv_body(c, 4);
	if (b)
		ln_put_le16(b, 4);
}

typedef struct Piece {
	size_t off;
	SrvSession *sign;        /* sign with this session's key, NULL = no */
} Piece;

/* does the command need a session / a tree? */
static int needs_tree(u16 cmd)
{
	switch (cmd) {
	case SMB2_TREE_DISCONNECT: case SMB2_CREATE: case SMB2_CLOSE: case SMB2_FLUSH: case SMB2_READ:
	case SMB2_WRITE: case SMB2_LOCK: case SMB2_IOCTL: case SMB2_QUERY_DIRECTORY: case SMB2_CHANGE_NOTIFY:
	case SMB2_QUERY_INFO: case SMB2_SET_INFO:
		return 1;
	}
	return 0;
}

static SrvTree *find_tree(SrvSession *s, u32 tid)
{
	SrvTree *t;
	for (t = s ? s->trees : NULL; t; t = t->next)
		if (t->id == tid)
			return t;
	return NULL;
}

/* handle one request (header at m, n bytes); returns 0 = no response
 * (CANCEL), 1 = response written; *logoff set to a session to free */
static int one_request(LnSrvConn *c, u8 *m, u32 n, int first, Piece *pc, SrvSession **logoff)
{
	u16 cmd = ln_le16(m + 12), charge, want, grant;
	u32 flags = ln_le32(m + 16);
	u64 sid = ln_le64(m + 40);
	u32 tid = ln_le32(m + 36);
	int related = (flags & SMB2_FLAGS_RELATED) && !first;
	u8 *h;
	SrvSession *sess;
	int verified = 0;

	if (cmd == SMB2_CANCEL)
		return 0;
	c->req = m;
	c->reqlen = n;
	c->body = m + SMB2_HDR;
	c->blen = n - SMB2_HDR;

	/* response header */
	while ((c->txlen - 4) & 7)
		c->tx[c->txlen++] = 0;
	c->resp_off = c->txlen;
	h = srv_body(c, SMB2_HDR);
	if (!h)
		return -1;
	memcpy(h, "\xfeSMB", 4);
	ln_put_le16(h + 4, 64);
	ln_put_le16(h + 6, ln_le16(m + 6));
	ln_put_le16(h + 12, cmd);
	ln_put_le32(h + 16, SMB2_FLAGS_SERVER_TO_REDIR | (related ? SMB2_FLAGS_RELATED : 0));
	memcpy(h + 24, m + 24, 8);              /* MessageId */
	memcpy(h + 32, m + 32, 4);              /* ProcessId (sync) */
	ln_put_le32(h + 36, tid);
	ln_put_le64(h + 40, sid);
	pc->off = c->resp_off;
	pc->sign = NULL;

	/* credits */
	charge = ln_le16(m + 6);
	if (!charge) charge = 1;
	want = ln_le16(m + 18);
	if (!want) want = 1;
	c->credits = c->credits > charge ? c->credits - charge : 0;
	grant = want;
	if (c->credits + grant > CREDITS_MAX)
		grant = (u16)(CREDITS_MAX > c->credits ? CREDITS_MAX - c->credits : 0);
	if (!grant && !c->credits)
		grant = 1;
	c->credits += grant;
	ln_put_le16(h + 14, grant);

	if (!c->negotiated && cmd != SMB2_NEGOTIATE) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return 1;
	}
	if (cmd == SMB2_NEGOTIATE) {
		srv_negotiate(c);
		return 1;
	}

	/* session and tree: related requests inherit them */
	if (related) {
		sess = c->sess;
		if (sid != 0xffffffffffffffffULL && sid && (!sess || sess->id != sid))
			sess = srv_find_session(c, sid);
		if (sess)
			ln_put_le64(h + 40, sess->id);
		if (c->tree && tid == 0xffffffffu)
			ln_put_le32(h + 36, c->tree->id);
	} else {
		sess = sid ? srv_find_session(c, sid) : NULL;
		c->tree = NULL;
		c->last_fid = 0;
		c->last_status = 0;
	}
	c->sess = sess;

	/* signature */
	if (sess && sess->valid && sess->k && (flags & SMB2_FLAGS_SIGNED)) {
		u8 got[16], want_sig[16];
		memcpy(got, m + 48, 16);
		memset(m + 48, 0, 16);
		smb_sign_msg(sess->k, m, n, want_sig);
		memcpy(m + 48, got, 16);
		if (!ln_memeq_ct(got, want_sig, 16)) {
			LN_LOG(0, "server: %s: bad signature on command %u", c->peer, cmd);
			srv_error(c, ST_ACCESS_DENIED, NULL, 0);
			return 1;
		}
		verified = 1;
	}
	if (cmd == SMB2_SESSION_SETUP) {
		srv_session_setup(c);
		/* srv_session_setup sets pc->sign through c->sess when the reply must be signed */
		if (c->sess && c->sess->valid && c->sess->k && ln_le32(c->tx + c->resp_off + 8) == ST_OK)
			pc->sign = c->sess;
		return 1;
	}
	if (sess && sess->valid && sess->k && (verified || sess->sign))
		pc->sign = sess;
	if (cmd == SMB2_ECHO) {
		srv_echo(c);
		return 1;
	}
	if (!sess || !sess->valid) {
		srv_error(c, ST_USER_SESSION_DELETED, NULL, 0);
		return 1;
	}
	if (sess->sign && sess->k && !verified) {
		LN_LOG(1, "server: %s: unsigned request on a signed session", c->peer);
		srv_error(c, ST_ACCESS_DENIED, NULL, 0);
		return 1;
	}
	if (needs_tree(cmd)) {
		SrvTree *t = related && c->tree && (tid == 0xffffffffu || tid == c->tree->id) ? c->tree : find_tree(sess, tid);
		if (!t) {
			srv_error(c, ST_NETWORK_NAME_DELETED, NULL, 0);
			return 1;
		}
		c->tree = t;
	}
	/* a related request after a failed CREATE fails the same way */
	if (related && c->last_status && c->last_status != ST_BUFFER_OVERFLOW && needs_tree(cmd) && cmd != SMB2_CREATE) {
		srv_error(c, c->last_status, NULL, 0);
		return 1;
	}
	switch (cmd) {
	case SMB2_LOGOFF: srv_logoff(c); *logoff = sess; break;
	case SMB2_TREE_CONNECT: srv_tree_connect(c); break;
	case SMB2_TREE_DISCONNECT: srv_tree_disconnect(c); break;
	case SMB2_CREATE: srv_create(c); break;
	case SMB2_CLOSE: srv_close(c); break;
	case SMB2_FLUSH: srv_flush(c); break;
	case SMB2_READ: srv_read(c); break;
	case SMB2_WRITE: srv_write(c); break;
	case SMB2_LOCK: srv_lock(c); break;
	case SMB2_IOCTL: srv_ioctl(c); break;
	case SMB2_QUERY_DIRECTORY: srv_query_directory(c); break;
	case SMB2_QUERY_INFO: srv_query_info(c); break;
	case SMB2_SET_INFO: srv_set_info(c); break;
	case SMB2_CHANGE_NOTIFY: srv_error(c, ST_NOT_SUPPORTED, NULL, 0); break;
	default: srv_error(c, ST_INVALID_PARAMETER, NULL, 0); break;
	}
	return 1;
}

int ln_srv_conn_input(LnSrvConn *c, u8 *msg, size_t len, const u8 **out, size_t *outlen)
{
	Piece pc[MAX_PIECES];
	int np = 0, i;
	size_t off = 0;
	SrvSession *logoff = NULL;

	*out = NULL;
	*outlen = 0;
	c->last_ms = ln_ms();
	if (tx_room(c, 4096))
		return LN_ENOMEM;
	c->txlen = 4;
	if (len >= 4 && !memcmp(msg, "\xffSMB", 4)) {
		int r = smb1_negotiate(c, msg, len);
		if (r)
			return r;
		goto done;
	}
	if (len >= 4 && !memcmp(msg, "\xfdSMB", 4)) {
		LN_LOG(0, "server: %s sent an encrypted message; Lagoon does not encrypt", c->peer);
		return LN_ENOTSUP;
	}
	if (len < SMB2_HDR || memcmp(msg, "\xfeSMB", 4))
		return LN_EPROTO;
	c->sess = NULL;
	c->tree = NULL;
	for (;;) {
		u8 *m = msg + off;
		size_t rest = len - off;
		u32 next, n;
		int r;
		if (rest < SMB2_HDR || memcmp(m, "\xfeSMB", 4) || ln_le16(m + 4) != 64)
			return LN_EPROTO;
		next = ln_le32(m + 20);
		if (next && (next < SMB2_HDR || next > rest || (next & 7)))
			return LN_EPROTO;
		n = next ? next : (u32)rest;
		if (np >= MAX_PIECES)
			return LN_EPROTO;
		r = one_request(c, m, n, off == 0, &pc[np], &logoff);
		if (r < 0)
			return LN_ENOMEM;
		if (r > 0) {
			/* remember a related chain's FileId / failure for the next request */
			u16 cmd = ln_le16(m + 12);
			u32 st = ln_le32(c->tx + pc[np].off + 8);
			if (cmd == SMB2_CREATE) {
				c->last_status = st;
				if (st == ST_OK)
					c->last_fid = ln_le64(c->tx + pc[np].off + SMB2_HDR + 64);
			}
			np++;
		}
		if (!next)
			break;
		off += next;
	}
	/* chain the replies, then sign each */
	for (i = 0; i < np; i++) {
		size_t end = i + 1 < np ? pc[i + 1].off : c->txlen;
		u8 *h = c->tx + pc[i].off;
		ln_put_le32(h + 20, i + 1 < np ? (u32)(end - pc[i].off) : 0);
		if (pc[i].sign) {
			u8 sig[16];
			ln_put_le32(h + 16, ln_le32(h + 16) | SMB2_FLAGS_SIGNED);
			memset(h + 48, 0, 16);
			smb_sign_msg(pc[i].sign->k, h, end - pc[i].off, sig);
			memcpy(h + 48, sig, 16);
		}
	}
	if (logoff)
		srv_session_free(c, logoff);
	if (!np)
		return LN_OK;
done:
	c->tx[0] = 0;
	c->tx[1] = (u8)((c->txlen - 4) >> 16);
	c->tx[2] = (u8)((c->txlen - 4) >> 8);
	c->tx[3] = (u8)(c->txlen - 4);
	*out = c->tx;
	*outlen = c->txlen;
	return LN_OK;
}
