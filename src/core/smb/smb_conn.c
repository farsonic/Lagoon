/*
 * Lagoon - SMB 2/3 transport: direct TCP framing, NEGOTIATE (with the
 * 3.1.1 negotiate contexts and preauth integrity hash), credits and
 * message ids, signing (HMAC-SHA256, AES-CMAC, AES-GMAC), encryption
 * (TRANSFORM_HEADER with AES-CCM / AES-GCM), key derivation. MS-SMB2.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "smb_int.h"
#include "../ln_sys.h"
#include "../ln_charset.h"

#define RX_MAX (16u * 1024 * 1024)

/* ------------------------------------------------------------ helpers */

u32 smb_ft2unix(u64 ft)
{
	const u64 epoch = 116444736000000000ULL;   /* 1970-01-01 in FILETIME */
	if (ft <= epoch)
		return 0;
	ft = (ft - epoch) / 10000000UL;
	return ft > 0xffffffffULL ? 0xffffffffu : (u32)ft;
}

u64 smb_unix2ft(u32 t)
{
	return (u64)t * 10000000UL + 116444736000000000ULL;
}

int smb_path16(const char *prefix, const char *path, u8 *out, size_t max)
{
	char *tmp;
	int n, i;
	while (*prefix == '/')
		prefix++;
	while (*path == '/')
		path++;
	tmp = ln_alloc(1024);
	if (!tmp)
		return LN_ENOMEM;
	if (ln_path_join(tmp, 1024, prefix, path)) {
		ln_free(tmp);
		return LN_ENAMETOOLONG;
	}
	n = (int)strlen(tmp);
	while (n > 0 && tmp[n - 1] == '/')
		tmp[--n] = 0;
	n = ln_utf8_to_utf16le(tmp, (size_t)n, out, max);
	ln_free(tmp);
	if (n < 0)
		return LN_ENAMETOOLONG;
	for (i = 0; i + 1 < n; i += 2)
		if (out[i] == '/' && out[i + 1] == 0)
			out[i] = '\\';
	return n;
}

void smb_kdf(const u8 *key, size_t klen, const void *label, size_t llen, const void *ctx, size_t clen,
             u8 *out, int outbits)
{
	LnHmacSha256 h;
	u8 b[4], z = 0, d[32];
	ln_hmac_sha256_init(&h, key, klen);
	ln_put_be32(b, 1);
	ln_hmac_sha256_update(&h, b, 4);
	ln_hmac_sha256_update(&h, label, llen);
	ln_hmac_sha256_update(&h, &z, 1);
	ln_hmac_sha256_update(&h, ctx, clen);
	ln_put_be32(b, (u32)outbits);
	ln_hmac_sha256_update(&h, b, 4);
	ln_hmac_sha256_final(&h, d);
	memcpy(out, d, (size_t)outbits / 8);
	ln_wipe(d, sizeof(d));
}

/* ----------------------------------------------------------- transport */

int smb_connect(SmbConn *c, const char *host, u16 port)
{
	int r;
	if (!c->timeout_ms)
		c->timeout_ms = 30000;
	c->txcap = 65536 + 512;
	c->rxcap = 65536 + 512;
	c->tx = ln_alloc(c->txcap);
	c->rx = ln_alloc(c->rxcap);
	if (!c->tx || !c->rx)
		return LN_ENOMEM;
	c->credits = 1;
	c->next_mid = 0;
	c->dead = 0;
	ln_random(c->cli_guid, 16);
	ln_random(c->nonce_salt, 4);
	r = ln_tcp_connect(host, port, c->timeout_ms < 15000 ? c->timeout_ms : 15000, &c->sock);
	if (r < 0) {
		LN_LOG(1, "smb: connect %s:%u: %s", host, port, ln_strerror(r));
		c->sock = NULL;
	}
	return r;
}

static void free_keys(SmbConn *c)
{
	if (c->sign_gcm) { ln_wipe(c->sign_gcm, sizeof(LnGcm)); ln_free(c->sign_gcm); }
	if (c->enc_gcm) { ln_wipe(c->enc_gcm, sizeof(LnGcm)); ln_free(c->enc_gcm); }
	if (c->dec_gcm) { ln_wipe(c->dec_gcm, sizeof(LnGcm)); ln_free(c->dec_gcm); }
	if (c->enc_aes) { ln_wipe(c->enc_aes, sizeof(LnAes)); ln_free(c->enc_aes); }
	if (c->dec_aes) { ln_wipe(c->dec_aes, sizeof(LnAes)); ln_free(c->dec_aes); }
	c->sign_gcm = c->enc_gcm = c->dec_gcm = NULL;
	c->enc_aes = c->dec_aes = NULL;
	ln_wipe(&c->sign_aes, sizeof(c->sign_aes));
	ln_wipe(c->session_key, 16);
	ln_wipe(c->sign_key, 16);
	c->keys = 0;
}

void smb_disconnect(SmbConn *c)
{
	if (c->sock)
		ln_sock_close(c->sock);
	c->sock = NULL;
	free_keys(c);
	if (c->tx) ln_free(c->tx);
	if (c->rx) ln_free(c->rx);
	c->tx = c->rx = NULL;
	c->msg = c->body = NULL;
	c->txcap = c->rxcap = 0;
	c->sid = 0;
	c->tid = 0;
	c->dead = 1;
}

u8 *smb_body(SmbConn *c, size_t n)
{
	size_t need = SMB_TX_OFF + SMB2_HDR + n + 16;
	if (need > c->txcap) {
		u8 *t = ln_realloc(c->tx, c->txcap, need);
		if (!t)
			return NULL;
		c->tx = t;
		c->txcap = need;
	}
	memset(c->tx + SMB_TX_OFF + SMB2_HDR, 0, n);
	return c->tx + SMB_TX_OFF + SMB2_HDR;
}

u32 smb_io_limit(SmbConn *c, u32 server_max, u32 cap)
{
	u32 l = LN_MIN(server_max, cap);
	if (!c->large_mtu)
		l = LN_MIN(l, 65536u);
	else if (c->credits < 512 && l > c->credits * 65536u)
		l = LN_MAX(c->credits, 1u) * 65536u;
	return l ? l : 4096;
}

void smb_sign_msg(SmbConn *c, const u8 *m, size_t len, u8 sig[16])
{
	u8 d[32];
	switch (c->sign_algo) {
	case SMB_SIGN_HMAC:
		ln_hmac_sha256(c->sign_key, 16, m, len, d);
		memcpy(sig, d, 16);
		break;
	case SMB_SIGN_CMAC:
		ln_aes_cmac(&c->sign_aes, m, len, sig);
		break;
	default: {
		u8 iv[12];
		u32 comp = (ln_le32(m + 16) & SMB2_FLAGS_SERVER_TO_REDIR) ? 1 : 0;
		if (ln_le16(m + 12) == SMB2_CANCEL)
			comp |= 2;
		memcpy(iv, m + 24, 8);
		ln_put_le32(iv + 8, comp);
		ln_gmac(c->sign_gcm, iv, m, len, sig);
	}
	}
}

int smb_verify(SmbConn *c)
{
	u8 got[16], want[16];
	if (c->msglen < SMB2_HDR)
		return LN_EPROTO;
	memcpy(got, c->msg + 48, 16);
	memset(c->msg + 48, 0, 16);
	smb_sign_msg(c, c->msg, c->msglen, want);
	memcpy(c->msg + 48, got, 16);
	if (!ln_memeq_ct(got, want, 16)) {
		LN_LOG(0, "smb: bad signature on reply to command %u (mid %llu)", ln_le16(c->msg + 12),
		       (unsigned long long)ln_le64(c->msg + 24));
		return LN_ECRYPTO;
	}
	return LN_OK;
}

int smb_derive_keys(SmbConn *c, const u8 *preauth)
{
	int klen = (c->cipher == SMB_C_CCM256 || c->cipher == SMB_C_GCM256) ? 32 : 16;
	u8 ek[32], dk[32];
	if (c->sign_gcm) { ln_free(c->sign_gcm); c->sign_gcm = NULL; }
	if (c->dialect < SMB_D300) {
		memcpy(c->sign_key, c->session_key, 16);
		c->sign_algo = SMB_SIGN_HMAC;
		c->keys = 1;
		return LN_OK;
	}
	if (c->dialect == SMB_D311) {
		smb_kdf(c->session_key, 16, "SMBSigningKey", 14, preauth, 64, c->sign_key, 128);
		smb_kdf(c->session_key, 16, "SMBC2SCipherKey", 16, preauth, 64, ek, klen * 8);
		smb_kdf(c->session_key, 16, "SMBS2CCipherKey", 16, preauth, 64, dk, klen * 8);
	} else {
		smb_kdf(c->session_key, 16, "SMB2AESCMAC", 12, "SmbSign", 8, c->sign_key, 128);
		smb_kdf(c->session_key, 16, "SMB2AESCCM", 11, "ServerIn ", 10, ek, 128);
		smb_kdf(c->session_key, 16, "SMB2AESCCM", 11, "ServerOut", 10, dk, 128);
	}
	if (c->sign_algo == SMB_SIGN_GMAC) {
		c->sign_gcm = ln_alloc(sizeof(LnGcm));
		if (!c->sign_gcm)
			return LN_ENOMEM;
		ln_gcm_setkey(c->sign_gcm, c->sign_key, 16);
	} else {
		c->sign_algo = SMB_SIGN_CMAC;
		ln_aes_setkey(&c->sign_aes, c->sign_key, 16);
	}
	if (c->cipher == SMB_C_GCM128 || c->cipher == SMB_C_GCM256) {
		c->enc_gcm = ln_alloc(sizeof(LnGcm));
		c->dec_gcm = ln_alloc(sizeof(LnGcm));
		if (!c->enc_gcm || !c->dec_gcm)
			return LN_ENOMEM;
		ln_gcm_setkey(c->enc_gcm, ek, klen);
		ln_gcm_setkey(c->dec_gcm, dk, klen);
	} else if (c->cipher == SMB_C_CCM128 || c->cipher == SMB_C_CCM256) {
		c->enc_aes = ln_alloc(sizeof(LnAes));
		c->dec_aes = ln_alloc(sizeof(LnAes));
		if (!c->enc_aes || !c->dec_aes)
			return LN_ENOMEM;
		ln_aes_setkey(c->enc_aes, ek, klen);
		ln_aes_setkey(c->dec_aes, dk, klen);
	}
	ln_wipe(ek, sizeof(ek));
	ln_wipe(dk, sizeof(dk));
	c->keys = 1;
	return LN_OK;
}

static int can_encrypt(SmbConn *c)
{
	return c->enc_gcm || c->enc_aes;
}

/* read one NetBIOS session frame into c->rx; *len = payload length */
static int recv_frame(SmbConn *c, u32 *len, int timeout)
{
	u8 h[4];
	int r;
	for (;;) {
		r = ln_tcp_recv(c->sock, h, 4, timeout);
		if (r < 0)
			return r;
		*len = ((u32)h[1] << 16) | ((u32)h[2] << 8) | h[3];
		if (h[0] == 0)
			break;
		/* 0x85 keep-alive or junk: skip its payload */
		while (*len) {
			u8 junk[64];
			u32 k = LN_MIN(*len, (u32)sizeof(junk));
			if ((r = ln_tcp_recv(c->sock, junk, k, timeout)) < 0)
				return r;
			*len -= k;
		}
	}
	if (*len > RX_MAX)
		return LN_EPROTO;
	if (*len + 16 > c->rxcap) {
		u8 *n = ln_realloc(c->rx, c->rxcap, *len + 512);
		if (!n)
			return LN_ENOMEM;
		c->rx = n;
		c->rxcap = *len + 512;
		c->msg = c->body = NULL;
	}
	return ln_tcp_recv(c->sock, c->rx, *len, timeout);
}

static void make_nonce(SmbConn *c, u8 nonce[16])
{
	memset(nonce, 0, 16);
	c->nonce_ctr++;
	if (c->enc_gcm) {
		memcpy(nonce, c->nonce_salt, 4);
		ln_put_le64(nonce + 4, c->nonce_ctr);
	} else {
		memcpy(nonce, c->nonce_salt, 3);
		ln_put_le64(nonce + 3, c->nonce_ctr);
	}
}

static int conn_fail(SmbConn *c, int err)
{
	c->dead = 1;
	if (c->sock)
		ln_sock_close(c->sock);
	c->sock = NULL;
	return err;
}

int smb_call(SmbConn *c, u16 cmd, size_t blen, u32 resp_bytes)
{
	u8 *h = c->tx + SMB_TX_OFF;
	u32 len = (u32)(SMB2_HDR + blen), charge = 1, n;
	u64 mid;
	int r, enc, timeout = c->timeout_ms;

	if (c->dead || !c->sock)
		return LN_ECONNRESET;
	if (c->large_mtu) {
		u32 m = LN_MAX((u32)blen, resp_bytes);
		charge = m > 65536 ? (m - 1) / 65536 + 1 : 1;
	}
	mid = c->next_mid;
	memset(h, 0, SMB2_HDR);
	h[0] = 0xfe; h[1] = 'S'; h[2] = 'M'; h[3] = 'B';
	ln_put_le16(h + 4, SMB2_HDR);
	ln_put_le16(h + 6, (u16)(c->dialect >= SMB_D210 ? charge : 0));
	ln_put_le16(h + 12, cmd);
	ln_put_le16(h + 14, (u16)(charge + (c->credits < 256 ? 64 : 0)));
	ln_put_le64(h + 24, mid);
	ln_put_le32(h + 32, 0xfeff);
	ln_put_le32(h + 36, c->tid);
	ln_put_le64(h + 40, c->sid);
	c->next_mid += charge;
	c->credits = c->credits > charge ? c->credits - charge : 0;
	c->reqlen = len;

	enc = c->encrypt && c->keys && can_encrypt(c) && cmd != SMB2_NEGOTIATE && cmd != SMB2_SESSION_SETUP;
	if (!enc && (c->sign || c->force_sign) && c->keys && cmd != SMB2_NEGOTIATE && cmd != SMB2_SESSION_SETUP) {
		ln_put_le32(h + 16, SMB2_FLAGS_SIGNED);
		smb_sign_msg(c, h, len, h + 48);
	}
	if (LN_LOG_ON(3))
		ln_log(3, "smb: -> cmd %u mid %llu len %u%s", cmd, (unsigned long long)mid, len, enc ? " enc" : "");
	if (enc) {
		u8 *tf = c->tx + 4;
		memset(tf, 0, SMB2_TF_HDR);
		tf[0] = 0xfd; tf[1] = 'S'; tf[2] = 'M'; tf[3] = 'B';
		make_nonce(c, tf + 20);
		ln_put_le32(tf + 36, len);
		ln_put_le16(tf + 42, 1);
		ln_put_le64(tf + 44, c->sid);
		if (c->enc_gcm)
			ln_gcm_encrypt(c->enc_gcm, tf + 20, tf + 20, 32, h, len, tf + 4);
		else
			ln_aes_ccm_encrypt(c->enc_aes, tf + 20, 11, tf + 20, 32, h, len, tf + 4, 16);
		len += SMB2_TF_HDR;
		c->tx[0] = 0;
		c->tx[1] = (u8)(len >> 16); c->tx[2] = (u8)(len >> 8); c->tx[3] = (u8)len;
		r = ln_tcp_send(c->sock, c->tx, len + 4, timeout);
	} else {
		u8 *nb = h - 4;
		nb[0] = 0;
		nb[1] = (u8)(len >> 16); nb[2] = (u8)(len >> 8); nb[3] = (u8)len;
		r = ln_tcp_send(c->sock, nb, len + 4, timeout);
	}
	if (r < 0) {
		LN_LOG(1, "smb: send: %s", ln_strerror(r));
		return conn_fail(c, r == LN_EBREAK ? r : LN_ECONNRESET);
	}

	for (;;) {
		u8 *p;
		u32 flags, st;
		u64 rmid;
		c->was_encrypted = 0;
		r = recv_frame(c, &n, timeout);
		if (r < 0) {
			if (cmd == SMB2_NEGOTIATE && r == LN_ECONNRESET) {
				LN_LOG(0, "smb: the server closed the connection on NEGOTIATE: it may only speak SMB1, "
				          "which Lagoon does not support (enable SMB2/3 on the server)");
				return conn_fail(c, LN_ENOTSUP);
			}
			LN_LOG(1, "smb: receive: %s", r == LN_ETIMEDOUT ? "timed out" : ln_strerror(r));
			return conn_fail(c, r == LN_EBREAK || r == LN_ENOMEM ? r : LN_ECONNRESET);
		}
		p = c->rx;
		if (n >= 4 && p[0] == 0xfd && p[1] == 'S' && p[2] == 'M' && p[3] == 'B') {
			u32 olen;
			int bad;
			if (n < SMB2_TF_HDR || !c->keys || !can_encrypt(c))
				return conn_fail(c, LN_EPROTO);
			olen = ln_le32(p + 36);
			if (olen > n - SMB2_TF_HDR || ln_le64(p + 44) != c->sid)
				return conn_fail(c, LN_EPROTO);
			if (c->dec_gcm)
				bad = ln_gcm_decrypt(c->dec_gcm, p + 20, p + 20, 32, p + SMB2_TF_HDR, olen, p + 4);
			else
				bad = ln_aes_ccm_decrypt(c->dec_aes, p + 20, 11, p + 20, 32, p + SMB2_TF_HDR, olen, p + 4, 16);
			if (bad) {
				LN_LOG(0, "smb: decryption failed (bad key or tampered reply)");
				return conn_fail(c, LN_ECRYPTO);
			}
			p += SMB2_TF_HDR;
			n = olen;
			c->was_encrypted = 1;
		}
		if (n >= 4 && p[0] == 0xff && p[1] == 'S' && p[2] == 'M' && p[3] == 'B') {
			LN_LOG(0, "smb: the server answered with SMB1, which Lagoon does not support "
			          "(enable SMB2/3 on the server)");
			return conn_fail(c, LN_ENOTSUP);
		}
		if (n < SMB2_HDR || p[0] != 0xfe || p[1] != 'S' || p[2] != 'M' || p[3] != 'B') {
			LN_LOG(0, "smb: malformed reply (%u bytes)", n);
			return conn_fail(c, LN_EPROTO);
		}
		if (ln_le32(p + 20) && ln_le32(p + 20) < n)
			n = ln_le32(p + 20);                /* compounded reply: we only use the first */
		flags = ln_le32(p + 16);
		st = ln_le32(p + 8);
		rmid = ln_le64(p + 24);
		c->credits += ln_le16(p + 14);
		if (LN_LOG_ON(3))
			ln_log(3, "smb: <- cmd %u mid %llu status 0x%08x len %u credits %u", ln_le16(p + 12),
			       (unsigned long long)rmid, st, n, c->credits);
		if (rmid == 0xffffffffffffffffULL)
			continue;                           /* oplock/lease break notification: we hold none */
		if (rmid != mid) {
			LN_LOG(1, "smb: ignoring reply for mid %llu (want %llu)", (unsigned long long)rmid,
			       (unsigned long long)mid);
			continue;
		}
		if (st == ST_PENDING && (flags & SMB2_FLAGS_ASYNC_COMMAND)) {
			timeout = 0;                        /* the server is working on it: wait (Ctrl-C breaks) */
			continue;
		}
		c->msg = p;
		c->msglen = n;
		c->status = st;
		c->body = p + SMB2_HDR;
		c->blen = n - SMB2_HDR;
		break;
	}
	if (c->encrypt && c->keys && can_encrypt(c) && !c->was_encrypted && cmd != SMB2_NEGOTIATE &&
	    cmd != SMB2_SESSION_SETUP && c->status == ST_OK) {
		LN_LOG(0, "smb: unencrypted reply on an encrypted session");
		return conn_fail(c, LN_ECRYPTO);
	}
	if ((c->sign || c->force_sign) && c->keys && !c->was_encrypted && cmd != SMB2_NEGOTIATE && cmd != SMB2_SESSION_SETUP) {
		if (ln_le32(c->msg + 16) & SMB2_FLAGS_SIGNED) {
			if (smb_verify(c))
				return conn_fail(c, LN_ECRYPTO);
		} else if (c->status == ST_OK) {
			LN_LOG(0, "smb: unsigned reply on a signed session");
			return conn_fail(c, LN_ECRYPTO);
		}
	}
	return LN_OK;
}

/* ---------------------------------------------------------- negotiate */

static const u16 all_dialects[] = { SMB_D202, SMB_D210, SMB_D300, SMB_D302, SMB_D311 };

static u8 *put_ctx(u8 *p, u8 *base, u16 type, const u8 *data, u16 dlen)
{
	while ((p - base) & 7)
		*p++ = 0;
	ln_put_le16(p, type);
	ln_put_le16(p + 2, dlen);
	ln_put_le32(p + 4, 0);
	memcpy(p + 8, data, dlen);
	return p + 8 + dlen;
}

int smb_negotiate(SmbConn *c)
{
	u8 *b, *p, d[48];
	int nd = 0, i, r, has311 = 0, nctx = 0;
	u16 secmode, ctxcount;
	u32 ctxoff;

	b = smb_body(c, 512);
	if (!b)
		return LN_ENOMEM;
	for (i = 0; i < (int)LN_ARRAY_SIZE(all_dialects); i++)
		if (all_dialects[i] <= c->max_dialect) {
			ln_put_le16(b + 36 + 2 * nd, all_dialects[i]);
			nd++;
			if (all_dialects[i] == SMB_D311)
				has311 = 1;
		}
	ln_put_le16(b, 36);
	ln_put_le16(b + 2, (u16)nd);
	ln_put_le16(b + 4, (u16)(c->sign ? 3 : 1));     /* signing enabled (+ required) */
	ln_put_le32(b + 8, 0x04 | (c->offer_encrypt ? 0x40 : 0)); /* LARGE_MTU, ENCRYPTION */
	memcpy(b + 12, c->cli_guid, 16);
	p = b + 36 + 2 * nd;
	if (has311) {
		u8 *base = b - SMB2_HDR;            /* offsets count from the SMB2 header */
		/* preauth integrity: SHA-512 + 32-byte salt */
		ln_put_le16(d, 1); ln_put_le16(d + 2, 32); ln_put_le16(d + 4, 1);
		ln_random(d + 6, 32);
		while ((p - base) & 7)
			*p++ = 0;
		ln_put_le32(b + 28, (u32)(p - base));
		p = put_ctx(p, base, 1, d, 38); nctx++;
		if (c->offer_encrypt) {
			/* encryption: GCM is cheaper than CCM (one AES per block) */
			if (c->cipher_only) {
				ln_put_le16(d, 1);
				ln_put_le16(d + 2, c->cipher_only);
				p = put_ctx(p, base, 2, d, 4);
			} else {
				ln_put_le16(d, 4);
				ln_put_le16(d + 2, SMB_C_GCM128); ln_put_le16(d + 4, SMB_C_CCM128);
				ln_put_le16(d + 6, SMB_C_GCM256); ln_put_le16(d + 8, SMB_C_CCM256);
				p = put_ctx(p, base, 2, d, 10);
			}
			nctx++;
		}
		/* signing capabilities */
		if (c->want_gmac) {
			ln_put_le16(d, 2); ln_put_le16(d + 2, SMB_SIGN_GMAC); ln_put_le16(d + 4, SMB_SIGN_CMAC);
			p = put_ctx(p, base, 8, d, 6);
		} else {
			ln_put_le16(d, 1); ln_put_le16(d + 2, SMB_SIGN_CMAC);
			p = put_ctx(p, base, 8, d, 4);
		}
		nctx++;
		ln_put_le16(b + 32, (u16)nctx);
	}
	r = smb_call(c, SMB2_NEGOTIATE, (size_t)(p - b), 0);
	if (r)
		return r;
	if (has311) {
		/* H = SHA512(0 | request), H = SHA512(H | reply) */
		LnSha512 s;
		memset(c->preauth, 0, 64);
		ln_sha512_init(&s); ln_sha512_update(&s, c->preauth, 64);
		ln_sha512_update(&s, c->tx + SMB_TX_OFF, c->reqlen); ln_sha512_final(&s, c->preauth);
		ln_sha512_init(&s); ln_sha512_update(&s, c->preauth, 64);
		ln_sha512_update(&s, c->msg, c->msglen); ln_sha512_final(&s, c->preauth);
	}
	if (c->status != ST_OK) {
		LN_LOG(0, "smb: NEGOTIATE failed: %s", smb_status_name(c->status));
		return smb_err(c->status);
	}
	b = c->body;
	if (c->blen < 64 || ln_le16(b) != 65)
		return LN_EPROTO;
	secmode = ln_le16(b + 2);
	c->dialect = ln_le16(b + 4);
	ctxcount = ln_le16(b + 6);
	memcpy(c->srv_guid, b + 8, 16);
	c->srv_caps = ln_le32(b + 24);
	c->max_trans = ln_le32(b + 28);
	c->max_read = ln_le32(b + 32);
	c->max_write = ln_le32(b + 36);
	ctxoff = ln_le32(b + 60);
	c->srv_secmode = secmode;
	for (i = 0; i < nd; i++)
		if (ln_le16(c->tx + SMB_TX_OFF + SMB2_HDR + 36 + 2 * i) == c->dialect)
			break;
	if (i == nd) {
		LN_LOG(0, "smb: server chose dialect 0x%04x which we did not offer", c->dialect);
		return LN_ENOTSUP;
	}
	if (c->max_read < 4096) c->max_read = 65536;
	if (c->max_write < 4096) c->max_write = 65536;
	if (c->max_trans < 4096) c->max_trans = 65536;
	c->large_mtu = c->dialect >= SMB_D210 && (c->srv_caps & 0x04);
	c->sign_algo = c->dialect >= SMB_D300 ? SMB_SIGN_CMAC : SMB_SIGN_HMAC;
	c->cipher = SMB_C_NONE;
	if (c->dialect == SMB_D300 || c->dialect == SMB_D302)
		c->cipher = (c->srv_caps & 0x40) ? SMB_C_CCM128 : SMB_C_NONE;
	if (c->dialect == SMB_D311) {
		/* walk the reply's negotiate contexts */
		u32 off = ctxoff;
		for (i = 0; i < ctxcount; i++) {
			u16 type, dl;
			const u8 *q;
			off = (off + 7) & ~7u;
			if (off + 8 > c->msglen)
				return LN_EPROTO;
			q = c->msg + off;
			type = ln_le16(q);
			dl = ln_le16(q + 2);
			if (off + 8 + dl > c->msglen)
				return LN_EPROTO;
			q += 8;
			if (type == 1) {
				if (dl < 6 || ln_le16(q) != 1 || ln_le16(q + 4) != 1)
					return LN_EPROTO;
			} else if (type == 2) {
				if (dl >= 4 && ln_le16(q) == 1)
					c->cipher = ln_le16(q + 2);
				if (c->cipher > SMB_C_GCM256)
					c->cipher = SMB_C_NONE;
			} else if (type == 8) {
				if (dl >= 4 && ln_le16(q) == 1 && ln_le16(q + 2) <= SMB_SIGN_GMAC)
					c->sign_algo = ln_le16(q + 2);
				if (c->sign_algo == SMB_SIGN_HMAC)
					c->sign_algo = SMB_SIGN_CMAC;
			}
			off += 8 + dl;
		}
	}
	LN_LOG(1, "smb: dialect %x.%x.%x, max read %u write %u, signing %s%s, cipher %u", c->dialect >> 8,
	       (c->dialect >> 4) & 15, c->dialect & 15, c->max_read, c->max_write,
	       (secmode & 2) ? "required" : "enabled",
	       c->sign_algo == SMB_SIGN_GMAC ? " (GMAC)" : c->sign_algo == SMB_SIGN_CMAC ? " (CMAC)" : " (HMAC)",
	       c->cipher);
	return LN_OK;
}
