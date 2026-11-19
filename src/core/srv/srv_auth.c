/*
 * Lagoon - SMB2 server SESSION_SETUP: SPNEGO (RFC 4178, MS-SPNG) around
 * NTLMSSP (MS-NLMP): our CHALLENGE, then the client's AUTHENTICATE checked
 * as NTLMv2 against the configured users' NT hashes (with its MIC), the
 * session key (RC4 key exchange), the SPNEGO mechListMIC, the 3.1.1 session
 * preauth hash and the signing keys. Unknown users become guests when a
 * share allows guests (like Samba's "map to guest = bad user"); a known user
 * with a wrong password is refused. NTLMv1 and LM are refused.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "srv_int.h"
#include "../ln_charset.h"
#include "../ln_conf.h"

#define NF_UNICODE      0x00000001u
#define NF_OEM          0x00000002u
#define NF_REQ_TARGET   0x00000004u
#define NF_SIGN         0x00000010u
#define NF_SEAL         0x00000020u
#define NF_NTLM         0x00000200u
#define NF_ANONYMOUS    0x00000800u
#define NF_ALWAYS_SIGN  0x00008000u
#define NF_TARGET_SRV   0x00020000u
#define NF_ESS          0x00080000u
#define NF_TARGET_INFO  0x00800000u
#define NF_VERSION      0x02000000u
#define NF_128          0x20000000u
#define NF_KEY_EXCH     0x40000000u
#define NF_56           0x80000000u

#define MAX_SESSIONS 8

static const u8 ntlm_oid[12] = { 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
static const u8 spnego_oid[8] = { 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
static const u8 ntlm_version[8] = { 10, 0, 0x5a, 0x29, 0, 0, 0, 15 };   /* 10.0.10586, revision 15 */
static const char hint[] = "not_defined_in_RFC4178@please_ignore";

/* ------------------------------------------------------------------ DER */

static size_t der_hlen(size_t len)
{
	return len < 128 ? 2 : len < 256 ? 3 : 4;
}

static size_t der_hdr(u8 *p, u8 tag, size_t len)
{
	p[0] = tag;
	if (len < 128) { p[1] = (u8)len; return 2; }
	if (len < 256) { p[1] = 0x81; p[2] = (u8)len; return 3; }
	p[1] = 0x82; p[2] = (u8)(len >> 8); p[3] = (u8)len;
	return 4;
}

/* one TLV: total size, 0 if malformed */
static size_t der_get(const u8 *p, size_t n, u8 *tag, const u8 **val, size_t *vlen)
{
	size_t h = 2, l;
	if (n < 2)
		return 0;
	*tag = p[0];
	l = p[1];
	if (l & 0x80) {
		int k = l & 0x7f, i;
		if (k < 1 || k > 3 || n < 2 + (size_t)k)
			return 0;
		for (l = 0, i = 0; i < k; i++)
			l = (l << 8) | p[2 + i];
		h += (size_t)k;
	}
	if (h + l > n)
		return 0;
	*val = p + h;
	*vlen = l;
	return h + l;
}

size_t srv_spnego_hint(u8 *out)
{
	/* 60 { oid, a0 { 30 { a0 { 30 { ntlm } }, a3 { 30 { a0 { 1b hint } } } } } } */
	size_t hl = sizeof(hint) - 1;
	size_t l_gs = der_hlen(hl) + hl, l_a0h = der_hlen(l_gs) + l_gs, l_sq3 = der_hlen(l_a0h) + l_a0h;
	size_t l_a3 = der_hlen(l_sq3) + l_sq3;
	size_t l_mt = sizeof(ntlm_oid), l_mts = der_hlen(l_mt) + l_mt, l_a0 = der_hlen(l_mts) + l_mts;
	size_t l_seq = l_a0 + l_a3, l_ini = der_hlen(l_seq) + l_seq, l_ctx = der_hlen(l_ini) + l_ini;
	size_t l_app = sizeof(spnego_oid) + l_ctx;
	u8 *p = out;
	p += der_hdr(p, 0x60, l_app);
	memcpy(p, spnego_oid, sizeof(spnego_oid)); p += sizeof(spnego_oid);
	p += der_hdr(p, 0xa0, l_ini);
	p += der_hdr(p, 0x30, l_seq);
	p += der_hdr(p, 0xa0, l_mts);
	p += der_hdr(p, 0x30, l_mt);
	memcpy(p, ntlm_oid, l_mt); p += l_mt;
	p += der_hdr(p, 0xa3, l_sq3);
	p += der_hdr(p, 0x30, l_a0h);
	p += der_hdr(p, 0xa0, l_gs);
	p += der_hdr(p, 0x1b, hl);
	memcpy(p, hint, hl); p += hl;
	return (size_t)(p - out);
}

/* what a client token carries */
typedef struct Tok {
	int spnego;
	const u8 *mech;          /* NTLMSSP message (or another mechanism's token) */
	size_t mechlen;
	const u8 *mechlist;      /* DER MechTypeList (NegTokenInit) */
	size_t mechlistlen;
	int ntlm_offered;        /* NTLMSSP is in the MechTypeList */
	const u8 *mic;
	size_t miclen;
} Tok;

static int parse_token(const u8 *b, size_t n, Tok *t)
{
	u8 tag;
	const u8 *v, *s;
	size_t vl, sl, k;
	memset(t, 0, sizeof(*t));
	if (n >= 8 && !memcmp(b, "NTLMSSP", 8)) {
		t->mech = b;
		t->mechlen = n;
		t->ntlm_offered = 1;
		return 0;
	}
	t->spnego = 1;
	if (!der_get(b, n, &tag, &v, &vl))
		return -1;
	if (tag == 0x60) {
		/* GSS InitialContextToken: OID, then [0] NegTokenInit */
		if (vl < sizeof(spnego_oid) || memcmp(v, spnego_oid, sizeof(spnego_oid)))
			return -1;
		v += sizeof(spnego_oid);
		vl -= sizeof(spnego_oid);
		if (!der_get(v, vl, &tag, &v, &vl) || tag != 0xa0)
			return -1;
	} else if (tag != 0xa1)
		return -1;
	if (!der_get(v, vl, &tag, &s, &sl) || tag != 0x30)
		return -1;
	while (sl) {
		const u8 *e, *ev;
		size_t el, evl, kk;
		u8 t2;
		k = der_get(s, sl, &tag, &e, &el);
		if (!k)
			return -1;
		if (tag == 0xa0 && der_get(e, el, &t2, &ev, &evl) && t2 == 0x30) {
			/* MechTypeList (in NegTokenResp [0] is negState, an ENUMERATED: skipped here) */
			const u8 *m = ev;
			size_t ml = evl;
			t->mechlist = e;
			t->mechlistlen = el;
			while (ml && (kk = der_get(m, ml, &t2, &ev, &evl)) != 0) {
				if (kk == sizeof(ntlm_oid) && !memcmp(m, ntlm_oid, kk))
					t->ntlm_offered = 1;
				m += kk;
				ml -= kk;
			}
		} else if (tag == 0xa2 && der_get(e, el, &t2, &ev, &evl) && t2 == 0x04) {
			t->mech = ev;
			t->mechlen = evl;
		} else if (tag == 0xa3 && der_get(e, el, &t2, &ev, &evl) && t2 == 0x04) {
			t->mic = ev;
			t->miclen = evl;
		}
		s += k;
		sl -= k;
	}
	return 0;
}

/* NegTokenResp { negState, supportedMech?, responseToken?, mechListMIC? } */
static size_t spnego_resp(u8 *out, int state, int mech, const u8 *tok, size_t tlen, const u8 *mic, size_t mlen)
{
	size_t l_st = 3 + 2, l_mech = mech ? der_hlen(sizeof(ntlm_oid)) + sizeof(ntlm_oid) : 0;
	size_t l_oct = tlen ? der_hlen(tlen) + tlen : 0, l_a2 = tlen ? der_hlen(l_oct) + l_oct : 0;
	size_t l_moct = mlen ? der_hlen(mlen) + mlen : 0, l_a3 = mlen ? der_hlen(l_moct) + l_moct : 0;
	size_t l_seq = l_st + l_mech + l_a2 + l_a3;
	u8 *p = out;
	p += der_hdr(p, 0xa1, der_hlen(l_seq) + l_seq);
	p += der_hdr(p, 0x30, l_seq);
	p += der_hdr(p, 0xa0, 3);
	*p++ = 0x0a; *p++ = 1; *p++ = (u8)state;
	if (mech) {
		p += der_hdr(p, 0xa1, sizeof(ntlm_oid));
		memcpy(p, ntlm_oid, sizeof(ntlm_oid)); p += sizeof(ntlm_oid);
	}
	if (tlen) {
		p += der_hdr(p, 0xa2, l_oct);
		p += der_hdr(p, 0x04, tlen);
		memcpy(p, tok, tlen); p += tlen;
	}
	if (mlen) {
		p += der_hdr(p, 0xa3, l_moct);
		p += der_hdr(p, 0x04, mlen);
		memcpy(p, mic, mlen); p += mlen;
	}
	return (size_t)(p - out);
}

/* ----------------------------------------------------------------- NTLM */

static int to16(const char *s, u8 *out, size_t max)
{
	int n = ln_utf8_to_utf16le(s, strlen(s), out, max);
	return n < 0 ? 0 : n;
}

void srv_ntowfv2(const u8 nthash[16], const char *user, const char *domain, u8 out[16])
{
	u8 b[520];
	char up[130];
	int n, i, k;
	ln_strlcpy(up, user, sizeof(up));
	for (i = 0; up[i]; i++)
		if (up[i] >= 'a' && up[i] <= 'z')
			up[i] -= 32;
	n = to16(up, b, 260);
	/* upper-case Latin-1 letters too (as Windows does) */
	for (k = 0; k + 1 < n; k += 2)
		if (b[k + 1] == 0 && b[k] >= 0xe0 && b[k] != 0xf7 && b[k] != 0xff)
			b[k] -= 32;
	n += to16(domain, b + n, sizeof(b) - (size_t)n);
	ln_hmac_md5(nthash, 16, b, (size_t)n, out);
	ln_wipe(b, sizeof(b));
}

int srv_ntlmv2_check(const u8 nthash[16], const char *user, const char *domain, const u8 srvchal[8],
                     const u8 *ntresp, size_t ntlen, u8 basekey[16])
{
	u8 key[16], proof[16];
	LnHmacMd5 h;
	int ok;
	if (ntlen <= 24 + 16)
		return 0;                    /* NTLMv1 or too short: refused */
	srv_ntowfv2(nthash, user, domain, key);
	ln_hmac_md5_init(&h, key, 16);
	ln_hmac_md5_update(&h, srvchal, 8);
	ln_hmac_md5_update(&h, ntresp + 16, ntlen - 16);
	ln_hmac_md5_final(&h, proof);
	ok = ln_memeq_ct(proof, ntresp, 16);
	if (ok)
		ln_hmac_md5(key, 16, proof, 16, basekey);
	ln_wipe(key, 16);
	ln_wipe(proof, 16);
	return ok;
}

static void derive(const u8 *esk, const char *magic, u8 out[16])
{
	LnMd5 m;
	ln_md5_init(&m);
	ln_md5_update(&m, esk, 16);
	ln_md5_update(&m, magic, strlen(magic) + 1);
	ln_md5_final(&m, out);
}

/* put an AV pair (UTF-16 string value) */
static size_t av_str(u8 *p, u16 id, const char *s)
{
	int n = to16(s, p + 4, 64);
	ln_put_le16(p, id);
	ln_put_le16(p + 2, (u16)n);
	return 4 + (size_t)n;
}

static int make_challenge(LnSrvConn *c, SrvSession *s, u32 cflags)
{
	u8 *m = ln_alloc(512), lower[16];
	size_t pos = 56, ti;
	u32 f;
	int i, n;
	char low[16];
	if (!m)
		return LN_ENOMEM;
	f = NF_UNICODE | NF_NTLM | NF_TARGET_INFO | NF_TARGET_SRV | NF_REQ_TARGET;
	f |= cflags & (NF_SIGN | NF_SEAL | NF_ALWAYS_SIGN | NF_ESS | NF_VERSION | NF_128 | NF_KEY_EXCH | NF_56);
	memcpy(m, "NTLMSSP", 8);
	ln_put_le32(m + 8, 2);
	ln_random(s->srvchal, 8);
	ln_put_le32(m + 20, f);
	memcpy(m + 24, s->srvchal, 8);
	memcpy(m + 48, ntlm_version, 8);
	/* target name = our name */
	n = to16(c->srv->cfg.name, m + pos, 64);
	ln_put_le16(m + 12, (u16)n); ln_put_le16(m + 14, (u16)n); ln_put_le32(m + 16, (u32)pos);
	pos += (size_t)n;
	ti = pos;
	ln_strlcpy(low, c->srv->cfg.name, sizeof(low));
	for (i = 0; low[i]; i++)
		if (low[i] >= 'A' && low[i] <= 'Z')
			low[i] += 32;
	(void)lower;
	pos += av_str(m + pos, 2, c->srv->cfg.name);      /* MsvAvNbDomainName (standalone: our name) */
	pos += av_str(m + pos, 1, c->srv->cfg.name);      /* MsvAvNbComputerName */
	pos += av_str(m + pos, 4, low);                    /* MsvAvDnsDomainName */
	pos += av_str(m + pos, 3, low);                    /* MsvAvDnsComputerName */
	ln_put_le16(m + pos, 7); ln_put_le16(m + pos + 2, 8);
	ln_put_le64(m + pos + 4, smb_unix2ft(ln_time_unix()));
	pos += 12;
	ln_put_le32(m + pos, 0);                           /* MsvAvEOL */
	pos += 4;
	ln_put_le16(m + 40, (u16)(pos - ti)); ln_put_le16(m + 42, (u16)(pos - ti)); ln_put_le32(m + 44, (u32)ti);
	if (s->chal)
		ln_free(s->chal);
	s->chal = m;
	s->challen = pos;
	return LN_OK;
}

/* a security buffer field of an AUTHENTICATE message: NULL if out of bounds */
static const u8 *field(const u8 *m, size_t n, int at, size_t *len)
{
	u16 l = ln_le16(m + at);
	u32 o = ln_le32(m + at + 4);
	*len = l;
	if (!l)
		return m;
	if (o > n || l > n - o)
		return NULL;
	return m + o;
}

static void field_str(const u8 *p, size_t l, int unicode, char *out, size_t max)
{
	if (unicode)
		srv_utf16_to_utf8(p, l, out, max);
	else {
		char t[130];
		size_t k = l < sizeof(t) - 1 ? l : sizeof(t) - 1;
		memcpy(t, p, k);
		t[k] = 0;
		if (ln_latin1_to_utf8(t, out, max) < 0)
			out[0] = 0;
	}
}

enum { AUTH_FAIL = 0, AUTH_USER, AUTH_GUEST, AUTH_ANON };

/* check the AUTHENTICATE message; esk receives the session key for AUTH_USER */
static int check_auth(LnSrvConn *c, SrvSession *s, const u8 *m, size_t n, u8 esk[16], char *who, size_t wn)
{
	size_t lml, ntl, dl, ul, wl, kl;
	const u8 *lm, *nt, *dp, *up, *wp, *ek;
	char user[130], domain[130], ws[64];
	u32 flags;
	int unicode, i, mic = 0;
	u8 basekey[16];
	LnSrv *sv = c->srv;

	if (n < 64 || memcmp(m, "NTLMSSP", 8) || ln_le32(m + 8) != 3)
		return AUTH_FAIL;
	lm = field(m, n, 12, &lml);
	nt = field(m, n, 20, &ntl);
	dp = field(m, n, 28, &dl);
	up = field(m, n, 36, &ul);
	wp = field(m, n, 44, &wl);
	ek = field(m, n, 52, &kl);
	if (!lm || !nt || !dp || !up || !wp || !ek)
		return AUTH_FAIL;
	flags = ln_le32(m + 60);
	unicode = (flags & NF_UNICODE) != 0;
	field_str(up, ul, unicode, user, sizeof(user));
	field_str(dp, dl, unicode, domain, sizeof(domain));
	field_str(wp, wl, unicode, ws, sizeof(ws));

	if (!user[0] && ntl == 0 && (lml == 0 || (lml == 1 && lm[0] == 0))) {
		ln_strlcpy(who, "anonymous", wn);
		return AUTH_ANON;
	}
	ln_snprintf(who, wn, "%s%s%s", domain, domain[0] ? "\\" : "", user);
	for (i = 0; i < sv->nusers; i++)
		if (!ln_strcasecmp(sv->user[i].name, user))
			break;
	if (i == sv->nusers) {
		if (ln_srv_has_guest_share(sv)) {
			LN_LOG(1, "server: %s: unknown user \"%s\" from %s: logged on as guest", c->peer, user, ws);
			return AUTH_GUEST;
		}
		LN_LOG(0, "server: %s: unknown user \"%s\" refused", c->peer, user);
		return AUTH_FAIL;
	}
	if (!srv_ntlmv2_check(sv->user[i].nthash, user, domain, s->srvchal, nt, ntl, basekey)) {
		LN_LOG(0, "server: %s: logon of \"%s\" refused (wrong password%s)", c->peer, user,
		       ntl == 24 ? ", or an NTLMv1-only client" : "");
		return AUTH_FAIL;
	}
	/* the session key: RC4 key exchange */
	if ((flags & NF_KEY_EXCH) && kl == 16) {
		LnRc4 rc;
		ln_rc4_init(&rc, basekey, 16);
		ln_rc4_crypt(&rc, ek, esk, 16);
		ln_wipe(&rc, sizeof(rc));
	} else
		memcpy(esk, basekey, 16);
	ln_wipe(basekey, 16);
	/* MsvAvFlags bit 1 in the NTLMv2 blob: a MIC follows the Version field */
	{
		const u8 *ti = nt + 16 + 28;
		size_t tl = ntl - 16 - 28, k = 0;
		while (k + 4 <= tl) {
			u16 id = ln_le16(ti + k), l = ln_le16(ti + k + 2);
			if (id == 0 || k + 4 + l > tl)
				break;
			if (id == 6 && l == 4 && (ln_le32(ti + k + 4) & 2))
				mic = 1;
			k += 4 + (size_t)l;
		}
	}
	if (mic) {
		u8 *copy, calc[16];
		LnHmacMd5 h;
		int ok;
		if (n < 88 || !s->neg)
			return AUTH_FAIL;
		copy = ln_alloc(n);
		if (!copy)
			return AUTH_FAIL;
		memcpy(copy, m, n);
		memset(copy + 72, 0, 16);
		ln_hmac_md5_init(&h, esk, 16);
		ln_hmac_md5_update(&h, s->neg, s->neglen);
		ln_hmac_md5_update(&h, s->chal, s->challen);
		ln_hmac_md5_update(&h, copy, n);
		ln_hmac_md5_final(&h, calc);
		ok = ln_memeq_ct(calc, m + 72, 16);
		ln_free(copy);
		if (!ok) {
			LN_LOG(0, "server: %s: bad NTLM MIC from \"%s\"", c->peer, user);
			return AUTH_FAIL;
		}
	}
	ln_strlcpy(s->user, user, sizeof(s->user));
	return AUTH_USER;
}

/* ------------------------------------------------------- SESSION_SETUP */

static void reply_blob(LnSrvConn *c, u32 status, u16 sflags, const u8 *blob, size_t bl)
{
	u8 *b = srv_body(c, 8 + bl);
	if (!b)
		return;
	srv_set_status(c, status);
	ln_put_le16(b, 9);
	ln_put_le16(b + 2, sflags);
	ln_put_le16(b + 4, SMB2_HDR + 8);
	ln_put_le16(b + 6, (u16)bl);
	if (bl)
		memcpy(b + 8, blob, bl);
}

static void fail(LnSrvConn *c, SrvSession *s, u32 status)
{
	srv_error(c, status, NULL, 0);
	if (s && !s->valid) {
		if (c->sess == s)
			c->sess = NULL;
		srv_session_free(c, s);
	}
}

void srv_session_setup(LnSrvConn *c)
{
	const u8 *b = c->body;
	u64 sid = ln_le64(c->req + 40);
	SrvSession *s;
	u16 off, len;
	Tok t;
	u8 *out = NULL;
	size_t ol;

	if (c->blen < 24 || ln_le16(b) != 25) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	if (b[2] & 1) {                              /* binding a channel: no multichannel */
		srv_error(c, ST_REQUEST_NOT_ACCEPTED, NULL, 0);
		return;
	}
	if (!sid) {
		int n = 0;
		for (s = c->sessions; s; s = s->next)
			n++;
		if (n >= MAX_SESSIONS) {
			srv_error(c, ST_INSUFFICIENT_RESOURCES, NULL, 0);
			return;
		}
		s = ln_alloc(sizeof(SrvSession));
		if (!s) {
			srv_error(c, ST_INSUFFICIENT_RESOURCES, NULL, 0);
			return;
		}
		s->id = c->next_sid++;
		s->next_tid = 1;
		memcpy(s->preauth, c->preauth, 64);
		s->next = c->sessions;
		c->sessions = s;
	} else if ((s = srv_find_session(c, sid)) == NULL) {
		srv_error(c, ST_USER_SESSION_DELETED, NULL, 0);
		return;
	} else if (s->valid && !s->chal) {
		/* re-authentication of a live session: start over (keeps its trees) */
		memcpy(s->preauth, c->preauth, 64);
	}
	c->sess = s;
	ln_put_le64(c->tx + c->resp_off + 40, s->id);
	if (c->dialect == SMB_D311)
		srv_preauth_add(s->preauth, c->req, c->reqlen);

	off = ln_le16(b + 12);
	len = ln_le16(b + 14);
	if (!len || off < SMB2_HDR + 24 || (u32)off + len > c->reqlen || parse_token(c->req + off, len, &t)) {
		fail(c, s, ST_INVALID_PARAMETER);
		return;
	}
	out = ln_alloc(1024);
	if (!out) {
		fail(c, s, ST_INSUFFICIENT_RESOURCES);
		return;
	}
	if (t.mechlist) {
		if (s->mechlist) ln_free(s->mechlist);
		s->mechlist = ln_alloc(t.mechlistlen);
		if (s->mechlist) {
			memcpy(s->mechlist, t.mechlist, t.mechlistlen);
			s->mechlen = t.mechlistlen;
		}
	}
	s->spnego = t.spnego;

	if (!t.mech || t.mechlen < 12 || memcmp(t.mech, "NTLMSSP", 8)) {
		/* another mechanism first (Kerberos): ask for NTLMSSP */
		if (!t.spnego || !t.ntlm_offered) {
			LN_LOG(1, "server: %s offers no NTLMSSP", c->peer);
			fail(c, s, ST_LOGON_FAILURE);
		} else {
			ol = spnego_resp(out, 1, 1, NULL, 0, NULL, 0);
			reply_blob(c, ST_MORE_PROCESSING, 0, out, ol);
			if (c->dialect == SMB_D311)
				srv_preauth_add(s->preauth, c->tx + c->resp_off, c->txlen - c->resp_off);
		}
		ln_free(out);
		return;
	}
	if (ln_le32(t.mech + 8) == 1) {
		/* NEGOTIATE -> CHALLENGE */
		if (s->neg) ln_free(s->neg);
		s->neg = ln_alloc(t.mechlen);
		if (!s->neg || make_challenge(c, s, ln_le32(t.mech + 12))) {
			ln_free(out);
			fail(c, s, ST_INSUFFICIENT_RESOURCES);
			return;
		}
		memcpy(s->neg, t.mech, t.mechlen);
		s->neglen = t.mechlen;
		if (t.spnego)
			ol = spnego_resp(out, 1, 1, s->chal, s->challen, NULL, 0);
		else {
			memcpy(out, s->chal, s->challen);
			ol = s->challen;
		}
		reply_blob(c, ST_MORE_PROCESSING, 0, out, ol);
		if (c->dialect == SMB_D311)
			srv_preauth_add(s->preauth, c->tx + c->resp_off, c->txlen - c->resp_off);
		ln_free(out);
		return;
	}
	if (ln_le32(t.mech + 8) == 3 && s->chal) {
		u8 esk[16];
		char who[200];
		int r = check_auth(c, s, t.mech, t.mechlen, esk, who, sizeof(who));
		u16 sflags = 0;
		ol = 0;
		if (r == AUTH_FAIL || (r != AUTH_USER && c->srv->cfg.sign_required)) {
			ln_wipe(esk, 16);
			ln_free(out);
			fail(c, s, ST_LOGON_FAILURE);
			return;
		}
		s->guest = r == AUTH_GUEST;
		s->anon = r == AUTH_ANON;
		if (r == AUTH_USER) {
			u16 secmode = b[3];
			s->k = ln_alloc(sizeof(SmbConn));
			if (!s->k) {
				ln_free(out);
				fail(c, s, ST_INSUFFICIENT_RESOURCES);
				return;
			}
			s->k->dialect = c->dialect;
			s->k->cipher = SMB_C_NONE;
			s->k->sign_algo = c->dialect == SMB_D311 ? c->sign_algo : c->dialect >= SMB_D300 ? SMB_SIGN_CMAC : SMB_SIGN_HMAC;
			memcpy(s->k->session_key, esk, 16);
			if (smb_derive_keys(s->k, s->preauth) != LN_OK) {
				ln_wipe(esk, 16);
				ln_free(out);
				fail(c, s, ST_INSUFFICIENT_RESOURCES);
				return;
			}
			s->sign = c->srv->cfg.sign_required || (secmode & 2) || (c->cli_secmode & 2);
			if (t.spnego && (t.mic || s->mechlist)) {
				/* our mechListMIC: server-to-client keys, sequence 0 */
				u8 sk[16], kk[16], mic[16];
				LnRc4 seal;
				derive(esk, "session key to server-to-client signing key magic constant", sk);
				derive(esk, "session key to server-to-client sealing key magic constant", kk);
				ln_rc4_init(&seal, kk, 16);
				ntlm_mac(sk, (ln_le32(t.mech + 60) & NF_KEY_EXCH) ? &seal : NULL, 0,
				         s->mechlist ? s->mechlist : (const u8 *)"", s->mechlist ? s->mechlen : 0, mic);
				ol = spnego_resp(out, 0, 0, NULL, 0, mic, 16);
				ln_wipe(sk, 16); ln_wipe(kk, 16); ln_wipe(&seal, sizeof(seal));
			}
			LN_LOG(1, "server: %s: %s logged on%s", c->peer, who, s->sign ? " (signing)" : "");
		} else {
			sflags = s->anon ? 2 : 1;
			ln_strlcpy(s->user, s->anon ? "" : "guest", sizeof(s->user));
			LN_LOG(1, "server: %s: %s session", c->peer, s->anon ? "anonymous" : "guest");
		}
		ln_wipe(esk, 16);
		if (!ol && t.spnego)
			ol = spnego_resp(out, 0, 0, NULL, 0, NULL, 0);
		s->valid = 1;
		ln_free(s->chal); s->chal = NULL; s->challen = 0;
		ln_free(s->neg); s->neg = NULL; s->neglen = 0;
		reply_blob(c, ST_OK, sflags, out, ol);
		ln_free(out);
		return;
	}
	ln_free(out);
	fail(c, s, ST_LOGON_FAILURE);
}
