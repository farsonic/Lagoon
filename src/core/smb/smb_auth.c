/*
 * Lagoon - SMB SESSION_SETUP: SPNEGO (RFC 4178, MS-SPNG) wrapping NTLMSSP
 * (MS-NLMP) with NTLMv2, MsvAvTimestamp, MIC, RC4 key exchange and the
 * SPNEGO mechListMIC; anonymous and guest logons; the 3.1.1 session
 * preauth hash; SMB key derivation.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "smb_int.h"
#include "../ln_charset.h"

/* NTLMSSP negotiate flags */
#define NF_UNICODE      0x00000001u
#define NF_REQ_TARGET   0x00000004u
#define NF_SIGN         0x00000010u
#define NF_SEAL         0x00000020u
#define NF_NTLM         0x00000200u
#define NF_ANONYMOUS    0x00000800u
#define NF_ALWAYS_SIGN  0x00008000u
#define NF_ESS          0x00080000u
#define NF_VERSION      0x02000000u
#define NF_128          0x20000000u
#define NF_KEY_EXCH     0x40000000u
#define NF_56           0x80000000u
#define NF_CLIENT (NF_UNICODE | NF_REQ_TARGET | NF_SIGN | NF_SEAL | NF_NTLM | NF_ALWAYS_SIGN | NF_ESS | \
                   NF_VERSION | NF_128 | NF_KEY_EXCH | NF_56)

static const u8 ntlm_version[8] = { 10, 0, 0, 0, 0, 0, 0, 15 };   /* 10.0, NTLMSSP revision 15 */
/* DER of the SPNEGO MechTypeList { NTLMSSP }: the mechListMIC covers these bytes */
static const u8 mech_types[14] = { 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
static const u8 spnego_oid[8] = { 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };

/* ----------------------------------------------------------------- NTLM */

static int to16(const char *s, u8 *out, size_t max)
{
	int n = ln_utf8_to_utf16le(s, strlen(s), out, max);
	return n < 0 ? 0 : n;
}

void ntlm_ntowfv2(const char *user, const char *domain, const char *password, u8 out[16])
{
	u8 *b = ln_alloc(1024), nt[16];
	char up[130];
	int n, i;
	if (!b)
		return;
	n = to16(password, b, 512);
	ln_md4(b, (size_t)n, nt);
	/* UPPER(user) (ASCII and Latin-1 letters) + domain */
	ln_strlcpy(up, user, sizeof(up));
	for (i = 0; up[i]; i++)
		if (up[i] >= 'a' && up[i] <= 'z')
			up[i] -= 32;
	n = to16(up, b, 512);
	{
		/* upper-case Latin-1 supplement letters in UTF-16 too */
		int k;
		for (k = 0; k + 1 < n; k += 2)
			if (b[k + 1] == 0 && b[k] >= 0xe0 && b[k] != 0xf7 && b[k] != 0xff)
				b[k] -= 32;
	}
	n += to16(domain, b + n, 1024 - (size_t)n);
	ln_hmac_md5(nt, 16, b, (size_t)n, out);
	ln_wipe(nt, 16);
	ln_wipe(b, 1024);
	ln_free(b);
}

void ntlm_v2_proof(const u8 key[16], const u8 srvchal[8], const u8 *temp, size_t tlen, u8 proof[16], u8 basekey[16])
{
	LnHmacMd5 h;
	ln_hmac_md5_init(&h, key, 16);
	ln_hmac_md5_update(&h, srvchal, 8);
	ln_hmac_md5_update(&h, temp, tlen);
	ln_hmac_md5_final(&h, proof);
	ln_hmac_md5(key, 16, proof, 16, basekey);
}

void ntlm_mac(const u8 signkey[16], LnRc4 *seal, u32 seq, const u8 *msg, size_t n, u8 out[16])
{
	LnHmacMd5 h;
	u8 s[4], d[16];
	ln_put_le32(s, seq);
	ln_hmac_md5_init(&h, signkey, 16);
	ln_hmac_md5_update(&h, s, 4);
	ln_hmac_md5_update(&h, msg, n);
	ln_hmac_md5_final(&h, d);
	ln_put_le32(out, 1);
	if (seal)
		ln_rc4_crypt(seal, d, out + 4, 8);
	else
		memcpy(out + 4, d, 8);
	ln_put_le32(out + 12, seq);
}

static void derive_key(const u8 *esk, const char *magic, u8 out[16])
{
	LnMd5 m;
	ln_md5_init(&m);
	ln_md5_update(&m, esk, 16);
	ln_md5_update(&m, magic, strlen(magic) + 1);
	ln_md5_final(&m, out);
}

typedef struct Ntlm {
	u8  neg[40];
	u8 *chal;
	size_t chal_len;
	u8 *auth;
	size_t auth_len;
	u32 flags;
	int mic;                 /* MIC present: send a mechListMIC */
	u8  esk[16];             /* exported session key */
} Ntlm;

static void ntlm_negotiate(Ntlm *n)
{
	memset(n->neg, 0, 40);
	memcpy(n->neg, "NTLMSSP", 8);
	ln_put_le32(n->neg + 8, 1);
	ln_put_le32(n->neg + 12, NF_CLIENT);
	ln_put_le32(n->neg + 28, 40);            /* empty workstation field points past the header */
	ln_put_le32(n->neg + 20, 40);
	memcpy(n->neg + 32, ntlm_version, 8);
}

/* append a security buffer field (len, maxlen, offset) at hdr and the data at *pos */
static void secbuf(u8 *msg, int field, size_t *pos, const u8 *data, size_t len)
{
	ln_put_le16(msg + field, (u16)len);
	ln_put_le16(msg + field + 2, (u16)len);
	ln_put_le32(msg + field + 4, (u32)*pos);
	if (len)
		memcpy(msg + *pos, data, len);
	*pos += len;
}

/* build AUTHENTICATE from the CHALLENGE in n->chal */
static int ntlm_authenticate(Ntlm *n, const char *user, const char *domain, const char *password,
                             const char *host, int anonymous)
{
	const u8 *ch = n->chal;
	u32 cflags;
	u8 srvchal[8], respkey[16], proof[16], basekey[16], cc[8], ts[8];
	u8 *ti = NULL, *temp = NULL, *buf = NULL;
	size_t tlen = 0, ti_len = 0, pos, i;
	int has_ts = 0, r = LN_ENOMEM;
	u8 dom16[130], user16[130], ws16[64], ekey[16];
	int dl, ul, wl;
	char dombuf[64];

	if (n->chal_len < 32 || memcmp(ch, "NTLMSSP", 8) || ln_le32(ch + 8) != 2)
		return LN_EPROTO;
	cflags = ln_le32(ch + 20);
	memcpy(srvchal, ch + 24, 8);
	if (n->chal_len >= 48) {
		u16 l = ln_le16(ch + 40);
		u32 o = ln_le32(ch + 44);
		if (o + l <= n->chal_len) {
			ti = (u8 *)ch + o;
			ti_len = l;
		}
	}
	/* default domain: the server's NetBIOS domain from the challenge target name */
	if (!domain[0] && !anonymous && !strchr(user, '@')) {
		u16 l = ln_le16(ch + 12);
		u32 o = ln_le32(ch + 16);
		dombuf[0] = 0;
		if (o + l <= n->chal_len && (cflags & NF_UNICODE))
			ln_utf16le_to_utf8(ch + o, l, dombuf, sizeof(dombuf));
		domain = dombuf;
	}
	n->flags = (cflags & NF_CLIENT) | NF_UNICODE;
	if (anonymous)
		n->flags = (n->flags | NF_ANONYMOUS) & ~(NF_KEY_EXCH | NF_SIGN | NF_SEAL);

	dl = anonymous ? 0 : to16(domain, dom16, sizeof(dom16));
	ul = anonymous ? 0 : to16(user, user16, sizeof(user16));
	{
		char ws[16];
		ln_strlcpy(ws, ln_hostname(), sizeof(ws));
		for (i = 0; ws[i]; i++)
			if (ws[i] == '.') ws[i] = 0;
		wl = to16(ws, ws16, sizeof(ws16));
	}

	buf = ln_alloc(4096);
	temp = ln_alloc(2048);
	if (!buf || !temp)
		goto out;
	memset(n->esk, 0, 16);
	n->mic = 0;
	if (!anonymous) {
		/* temp = 01 01 Z(6) time cc Z(4) avpairs' Z(4) */
		size_t k = 0;
		ln_random(cc, 8);
		/* find MsvAvTimestamp */
		for (i = 0; ti && i + 4 <= ti_len;) {
			u16 id = ln_le16(ti + i), l = ln_le16(ti + i + 2);
			if (id == 0 || i + 4 + l > ti_len)
				break;
			if (id == 7 && l == 8) {
				memcpy(ts, ti + i + 4, 8);
				has_ts = 1;
			}
			i += 4 + (size_t)l;
		}
		if (!has_ts)
			ln_put_le64(ts, smb_unix2ft(ln_time_unix()));
		temp[0] = 1; temp[1] = 1;
		memcpy(temp + 8, ts, 8);
		memcpy(temp + 16, cc, 8);
		k = 28;
		/* copy the server's AV pairs except EOL and flags */
		for (i = 0; ti && i + 4 <= ti_len;) {
			u16 id = ln_le16(ti + i), l = ln_le16(ti + i + 2);
			if (id == 0 || i + 4 + l > ti_len || k + 4 + l > 1700)
				break;
			if (id != 6 && id != 9 && id != 10) {
				memcpy(temp + k, ti + i, 4 + (size_t)l);
				k += 4 + (size_t)l;
			}
			i += 4 + (size_t)l;
		}
		if (has_ts) {
			ln_put_le16(temp + k, 6); ln_put_le16(temp + k + 2, 4); ln_put_le32(temp + k + 4, 2);
			k += 8;
			n->mic = 1;
		}
		/* channel bindings: none (all zero), and the SPN of the target */
		ln_put_le16(temp + k, 10); ln_put_le16(temp + k + 2, 16); memset(temp + k + 4, 0, 16);
		k += 20;
		{
			char spn[160];
			int sl;
			ln_snprintf(spn, sizeof(spn), "cifs/%s", host);
			sl = to16(spn, temp + k + 4, 300);
			ln_put_le16(temp + k, 9); ln_put_le16(temp + k + 2, (u16)sl);
			k += 4 + (size_t)sl;
		}
		memset(temp + k, 0, 8);              /* MsvAvEOL + Z(4) */
		k += 8;
		tlen = k;
		ntlm_ntowfv2(user, domain, password, respkey);
		ntlm_v2_proof(respkey, srvchal, temp, tlen, proof, basekey);
		if (n->flags & NF_KEY_EXCH) {
			LnRc4 rc;
			ln_random(n->esk, 16);
			ln_rc4_init(&rc, basekey, 16);
			ln_rc4_crypt(&rc, n->esk, ekey, 16);
			ln_wipe(&rc, sizeof(rc));
		} else
			memcpy(n->esk, basekey, 16);
	}

	/* AUTHENTICATE_MESSAGE: 88-byte header (with MIC), then the payload */
	memset(buf, 0, 88);
	memcpy(buf, "NTLMSSP", 8);
	ln_put_le32(buf + 8, 3);
	pos = 88;
	if (anonymous) {
		u8 z = 0;
		secbuf(buf, 12, &pos, &z, 1);
		secbuf(buf, 20, &pos, NULL, 0);
	} else if (has_ts) {
		u8 z[24];
		memset(z, 0, 24);
		secbuf(buf, 12, &pos, z, 24);         /* LMv2 is all zero when a timestamp is present */
		secbuf(buf, 20, &pos, proof, 16);
		pos -= 16;
		memcpy(buf + pos + 16, temp, tlen);
		ln_put_le16(buf + 20, (u16)(16 + tlen)); ln_put_le16(buf + 22, (u16)(16 + tlen));
		pos += 16 + tlen;
	} else {
		/* LMv2 = HMAC_MD5(key, srvchal | cc) | cc */
		u8 lm[24];
		LnHmacMd5 h;
		ln_hmac_md5_init(&h, respkey, 16);
		ln_hmac_md5_update(&h, srvchal, 8);
		ln_hmac_md5_update(&h, cc, 8);
		ln_hmac_md5_final(&h, lm);
		memcpy(lm + 16, cc, 8);
		secbuf(buf, 12, &pos, lm, 24);
		secbuf(buf, 20, &pos, proof, 16);
		pos -= 16;
		memcpy(buf + pos + 16, temp, tlen);
		ln_put_le16(buf + 20, (u16)(16 + tlen)); ln_put_le16(buf + 22, (u16)(16 + tlen));
		pos += 16 + tlen;
	}
	secbuf(buf, 28, &pos, dom16, (size_t)dl);
	secbuf(buf, 36, &pos, user16, (size_t)ul);
	secbuf(buf, 44, &pos, ws16, (size_t)wl);
	secbuf(buf, 52, &pos, ekey, (n->flags & NF_KEY_EXCH) ? 16 : 0);
	ln_put_le32(buf + 60, n->flags);
	memcpy(buf + 64, ntlm_version, 8);
	if (n->mic) {
		LnHmacMd5 h;
		ln_hmac_md5_init(&h, n->esk, 16);
		ln_hmac_md5_update(&h, n->neg, 40);
		ln_hmac_md5_update(&h, n->chal, n->chal_len);
		ln_hmac_md5_update(&h, buf, pos);
		ln_hmac_md5_final(&h, buf + 72);
	}
	n->auth = buf;
	n->auth_len = pos;
	buf = NULL;
	r = LN_OK;
out:
	ln_wipe(respkey, 16);
	ln_wipe(basekey, 16);
	ln_wipe(ekey, 16);
	if (temp) { ln_wipe(temp, 2048); ln_free(temp); }
	if (buf) ln_free(buf);
	return r;
}

/* --------------------------------------------------------------- SPNEGO */

static size_t der_hdr(u8 *p, u8 tag, size_t len)
{
	p[0] = tag;
	if (len < 128) { p[1] = (u8)len; return 2; }
	if (len < 256) { p[1] = 0x81; p[2] = (u8)len; return 3; }
	p[1] = 0x82; p[2] = (u8)(len >> 8); p[3] = (u8)len;
	return 4;
}

static size_t der_hlen(size_t len)
{
	return len < 128 ? 2 : len < 256 ? 3 : 4;
}

/* parse one TLV: returns header+value size, 0 on error */
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

/* GSS InitialContextToken with a NegTokenInit carrying the NTLM NEGOTIATE */
static size_t spnego_init(u8 *out, const u8 *tok, size_t tlen)
{
	size_t l_oct = der_hlen(tlen) + tlen;
	size_t l_a2 = der_hlen(l_oct) + l_oct;
	size_t l_a0 = der_hlen(sizeof(mech_types)) + sizeof(mech_types);
	size_t l_seq = l_a0 + l_a2;
	size_t l_ini = der_hlen(l_seq) + l_seq;
	size_t l_app = sizeof(spnego_oid) + der_hlen(l_ini) + l_ini;
	u8 *p = out;
	p += der_hdr(p, 0x60, l_app);
	memcpy(p, spnego_oid, sizeof(spnego_oid)); p += sizeof(spnego_oid);
	p += der_hdr(p, 0xa0, l_seq + der_hlen(l_seq));
	p += der_hdr(p, 0x30, l_seq);
	p += der_hdr(p, 0xa0, sizeof(mech_types));
	memcpy(p, mech_types, sizeof(mech_types)); p += sizeof(mech_types);
	p += der_hdr(p, 0xa2, l_oct);
	p += der_hdr(p, 0x04, tlen);
	memcpy(p, tok, tlen); p += tlen;
	return (size_t)(p - out);
}

/* NegTokenResp { responseToken, mechListMIC (optional) } */
static size_t spnego_resp(u8 *out, const u8 *tok, size_t tlen, const u8 *mic, size_t mlen)
{
	size_t l_oct = der_hlen(tlen) + tlen, l_a2 = der_hlen(l_oct) + l_oct;
	size_t l_moct = mlen ? der_hlen(mlen) + mlen : 0, l_a3 = mlen ? der_hlen(l_moct) + l_moct : 0;
	size_t l_seq = l_a2 + l_a3;
	u8 *p = out;
	p += der_hdr(p, 0xa1, der_hlen(l_seq) + l_seq);
	p += der_hdr(p, 0x30, l_seq);
	p += der_hdr(p, 0xa2, l_oct);
	p += der_hdr(p, 0x04, tlen);
	memcpy(p, tok, tlen); p += tlen;
	if (mlen) {
		p += der_hdr(p, 0xa3, l_moct);
		p += der_hdr(p, 0x04, mlen);
		memcpy(p, mic, mlen); p += mlen;
	}
	return (size_t)(p - out);
}

/* find the responseToken (or a raw NTLMSSP blob); negstate set if present */
static int spnego_parse(const u8 *b, size_t n, const u8 **tok, size_t *tlen, int *negstate)
{
	u8 tag;
	const u8 *v, *s;
	size_t vl, sl, k;
	*tok = NULL; *tlen = 0; *negstate = -1;
	if (n >= 8 && !memcmp(b, "NTLMSSP", 8)) {
		*tok = b; *tlen = n;
		return 0;
	}
	if (!der_get(b, n, &tag, &v, &vl) || tag != 0xa1)
		return -1;
	if (!der_get(v, vl, &tag, &s, &sl) || tag != 0x30)
		return -1;
	while (sl) {
		const u8 *e, *ev;
		size_t el, evl;
		u8 t2;
		k = der_get(s, sl, &tag, &e, &el);
		if (!k)
			return -1;
		if (tag == 0xa0 && der_get(e, el, &t2, &ev, &evl) && t2 == 0x0a && evl == 1)
			*negstate = ev[0];
		else if (tag == 0xa2 && der_get(e, el, &t2, &ev, &evl) && t2 == 0x04) {
			*tok = ev; *tlen = evl;
		}
		s += k; sl -= k;
	}
	return 0;
}

/* ------------------------------------------------------- SESSION_SETUP */

static void preauth_add(u8 h[64], const u8 *m, size_t n)
{
	LnSha512 s;
	ln_sha512_init(&s);
	ln_sha512_update(&s, h, 64);
	ln_sha512_update(&s, m, n);
	ln_sha512_final(&s, h);
}

static int setup_req(SmbConn *c, const u8 *blob, size_t blen)
{
	u8 *b = smb_body(c, 24 + blen);
	if (!b)
		return LN_ENOMEM;
	ln_put_le16(b, 25);
	b[3] = (u8)(c->sign ? 3 : 1);
	ln_put_le32(b + 4, 0x01);                /* DFS capable (we never use DFS referrals) */
	ln_put_le16(b + 12, SMB2_HDR + 24);
	ln_put_le16(b + 14, (u16)blen);
	memcpy(b + 24, blob, blen);
	return smb_call(c, SMB2_SESSION_SETUP, 24 + blen, 0);
}

static int setup_once(SmbConn *c, const char *user, const char *domain, const char *password,
                      const char *host, int anonymous)
{
	Ntlm n;
	u8 *blob = ln_alloc(4096), sp[64];
	const u8 *tok;
	size_t tl, bl;
	int r, ns;
	if (!blob)
		return LN_ENOMEM;
	memset(&n, 0, sizeof(n));
	memcpy(sp, c->preauth, 64);
	c->sid = 0;
	c->keys = 0;
	ntlm_negotiate(&n);
	bl = spnego_init(blob, n.neg, 40);
	r = setup_req(c, blob, bl);
	if (r)
		goto out;
	if (c->dialect == SMB_D311) {
		preauth_add(sp, c->tx + SMB_TX_OFF, c->reqlen);
		if (c->status == ST_MORE_PROCESSING)
			preauth_add(sp, c->msg, c->msglen);
	}
	if (c->status != ST_MORE_PROCESSING) {
		LN_LOG(0, "smb: SESSION_SETUP: %s", smb_status_name(c->status));
		r = c->status ? smb_err(c->status) : LN_EPROTO;
		goto out;
	}
	c->sid = ln_le64(c->msg + 40);
	{
		u16 off = ln_le16(c->body + 4), len = ln_le16(c->body + 6);
		if (c->blen < 8 || off < SMB2_HDR + 8 || off + len > c->msglen ||
		    spnego_parse(c->msg + off, len, &tok, &tl, &ns) || !tok) {
			r = LN_EPROTO;
			goto out;
		}
		n.chal = ln_alloc(tl);
		if (!n.chal) { r = LN_ENOMEM; goto out; }
		memcpy(n.chal, tok, tl);
		n.chal_len = tl;
	}
	r = ntlm_authenticate(&n, user, domain, password, host, anonymous);
	if (r)
		goto out;
	if (n.mic) {
		u8 sk[16], kk[16], mic[16];
		LnRc4 seal;
		derive_key(n.esk, "session key to client-to-server signing key magic constant", sk);
		derive_key(n.esk, "session key to client-to-server sealing key magic constant", kk);
		ln_rc4_init(&seal, kk, 16);
		ntlm_mac(sk, (n.flags & NF_KEY_EXCH) ? &seal : NULL, 0, mech_types, sizeof(mech_types), mic);
		bl = spnego_resp(blob, n.auth, n.auth_len, mic, 16);
		ln_wipe(sk, 16); ln_wipe(kk, 16); ln_wipe(&seal, sizeof(seal));
	} else
		bl = spnego_resp(blob, n.auth, n.auth_len, NULL, 0);
	r = setup_req(c, blob, bl);
	if (r)
		goto out;
	if (c->dialect == SMB_D311) {
		preauth_add(sp, c->tx + SMB_TX_OFF, c->reqlen);
		if (c->status == ST_MORE_PROCESSING)
			preauth_add(sp, c->msg, c->msglen);
	}
	if (c->status != ST_OK) {
		LN_LOG(anonymous ? 1 : 0, "smb: logon as \"%s\" failed: %s", anonymous ? "(anonymous)" : user,
		       smb_status_name(c->status));
		r = smb_err(c->status);
		if (r == LN_EACCES || r == LN_EINVAL)
			r = LN_EAUTH;
		goto out;
	}
	c->session_flags = c->blen >= 4 ? ln_le16(c->body + 2) : 0;
	if (anonymous)
		c->session_flags |= 2;
	if (c->session_flags & 3) {
		LN_LOG(1, "smb: logged on as %s", (c->session_flags & 2) ? "anonymous" : "guest");
		c->keys = 0;
		r = LN_OK;
		goto out;
	}
	memcpy(c->session_key, n.esk, 16);
	r = smb_derive_keys(c, sp);
	if (r)
		goto out;
	if (ln_le32(c->msg + 16) & SMB2_FLAGS_SIGNED) {
		if ((r = smb_verify(c)) != 0) {
			LN_LOG(0, "smb: the server's SESSION_SETUP signature is wrong (wrong password on a "
			          "share-level server, or a man in the middle)");
			goto out;
		}
	} else if (c->dialect == SMB_D311 || c->sign) {
		LN_LOG(0, "smb: SESSION_SETUP reply is not signed");
		r = LN_ECRYPTO;
		goto out;
	}
	LN_LOG(1, "smb: logged on as %s%s%s", domain[0] ? domain : "", domain[0] ? "\\" : "", user);
	r = LN_OK;
out:
	ln_wipe(n.esk, 16);
	if (n.chal) ln_free(n.chal);
	if (n.auth) { ln_wipe(n.auth, n.auth_len); ln_free(n.auth); }
	ln_free(blob);
	return r;
}

int smb_session_setup(SmbConn *c, const LnCreds *cr, const char *host, int sign_required)
{
	char user[64], domain[64];
	const char *bs;
	int r;
	ln_strlcpy(user, cr->user, sizeof(user));
	ln_strlcpy(domain, cr->domain, sizeof(domain));
	/* DOMAIN\user */
	if ((bs = strchr(cr->user, '\\')) != NULL) {
		size_t l = (size_t)(bs - cr->user);
		if (l < sizeof(domain)) {
			memcpy(domain, cr->user, l);
			domain[l] = 0;
		}
		ln_strlcpy(user, bs + 1, sizeof(user));
	}
	if (!user[0]) {
		r = setup_once(c, "", "", "", host, 1);
		if (r == LN_EAUTH && !c->dead) {
			LN_LOG(1, "smb: anonymous logon refused, trying guest");
			r = setup_once(c, "guest", "", "", host, 0);
		}
	} else
		r = setup_once(c, user, domain, cr->password, host, 0);
	if (r == LN_OK && (c->session_flags & 3)) {
		if (sign_required) {
			LN_LOG(0, "smb: signing was required but guest/anonymous sessions cannot sign");
			return LN_EAUTH;
		}
		c->sign = 0;
		c->encrypt = 0;
	}
	/* 3.1.1: non-guest sessions always sign (MS-SMB2 3.2.5.3.1; servers insist) */
	if (r == LN_OK && c->keys && c->dialect == SMB_D311)
		c->sign = 1;
	if (r == LN_OK && (c->session_flags & 4)) {
		if (c->cipher == SMB_C_NONE) {
			LN_LOG(0, "smb: the server requires encryption but no cipher was agreed");
			return LN_ENOTSUP;
		}
		c->encrypt = 1;
	}
	return r;
}
