/*
 * Lagoon - AFP login methods, client side math:
 *   DHX2:      Diffie-Hellman with the server's prime p (512..4096 bits) and
 *              generator g, key K = MD5(Mb^Ra mod p), CAST-128 CBC with the
 *              IVs "LWallace" (client->server) and "CJalbert" (server->client),
 *              nonces incremented as 128-bit numbers, a 256-byte password.
 *   DHCAST128: the same idea with a fixed 128-bit prime and g = 7, K is the
 *              shared secret itself, a 64-byte password.
 * The protocol exchange itself is in afp_ops.c (login()).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "afp_int.h"
#include "../ln_hash.h"
#include "../ln_sys.h"

static const u8 iv_c2s[8] = { 'L', 'W', 'a', 'l', 'l', 'a', 'c', 'e' };
static const u8 iv_s2c[8] = { 'C', 'J', 'a', 'l', 'b', 'e', 'r', 't' };

static const u8 dhcast_p[16] = {
	0xba, 0x28, 0x73, 0xdf, 0xb0, 0x60, 0x57, 0xd4, 0x3f, 0x20, 0x24, 0x74, 0x4c, 0xee, 0xe7, 0x5b
};

void afp_nonce_inc(u8 n[16])
{
	int i;
	for (i = 15; i >= 0; i--)
		if (++n[i])
			break;
}

/* 1 < y < p - 1 (rejects degenerate public keys) */
static int pubkey_ok(const u8 *y, const u8 *p, size_t len)
{
	u8 pm1[512];
	size_t i;
	int two = 0;
	memcpy(pm1, p, len);
	pm1[len - 1] &= 0xfe;              /* p - 1 (p is odd) */
	for (i = 0; i + 1 < len && !y[i]; i++)
		;
	if (i + 1 == len && y[i] < 2)
		two = 1;
	return !two && ln_bn_cmp(y, len, pm1, len) < 0;
}

int afp_dhx2_reply1(AfpDhx *x, const u8 *rep, size_t n, const u8 *ra, size_t ralen)
{
	u8 g[4], *ks;
	size_t len;
	int r;
	if (n < 8)
		return LN_EPROTO;
	x->id = ln_be16(rep);
	memcpy(g, rep + 2, 4);
	len = ln_be16(rep + 6);
	if (len < 16 || len > sizeof(x->p) || n < 8 + 2 * len || !(rep[8 + len - 1] & 1))
		return LN_EPROTO;
	x->plen = len;
	memcpy(x->p, rep + 8, len);
	if (!pubkey_ok(rep + 8 + len, x->p, len))
		return LN_EPROTO;
	/* Ma = g^Ra mod p, shared = Mb^Ra mod p, K = MD5(shared, len bytes) */
	r = ln_bn_modexp(x->ma, g, 4, ra, ralen, x->p, len);
	if (r)
		return r;
	ks = ln_alloc(len);
	if (!ks)
		return LN_ENOMEM;
	r = ln_bn_modexp(ks, rep + 8 + len, len, ra, ralen, x->p, len);
	if (!r)
		ln_md5(ks, len, x->key);
	ln_wipe(ks, len);
	ln_free(ks);
	return r;
}

size_t afp_dhx2_cont1(AfpDhx *x, u8 *out)
{
	LnCast128 c;
	memcpy(out, x->ma, x->plen);
	memcpy(out + x->plen, x->cnonce, 16);
	ln_cast128_setkey(&c, x->key, 16);
	ln_cast128_cbc_encrypt(&c, iv_c2s, out + x->plen, 16);
	ln_wipe(&c, sizeof(c));
	return x->plen + 16;
}

int afp_dhx2_reply2(AfpDhx *x, const u8 *rep, size_t n)
{
	LnCast128 c;
	u8 buf[32], want[16];
	int ok;
	if (n < 2 + 32)
		return LN_EPROTO;
	x->id = ln_be16(rep);
	memcpy(buf, rep + 2, 32);
	ln_cast128_setkey(&c, x->key, 16);
	ln_cast128_cbc_decrypt(&c, iv_s2c, buf, 32);
	ln_wipe(&c, sizeof(c));
	memcpy(want, x->cnonce, 16);
	afp_nonce_inc(want);
	ok = ln_memeq_ct(buf, want, 16);
	memcpy(x->snonce, buf + 16, 16);
	ln_wipe(buf, sizeof(buf));
	/* a server that does not know K cannot produce clientNonce+1 */
	return ok ? LN_OK : LN_EAUTH;
}

size_t afp_dhx2_cont2(AfpDhx *x, const char *password, u8 *out)
{
	LnCast128 c;
	size_t pl = strlen(password);
	memcpy(out, x->snonce, 16);
	afp_nonce_inc(out);
	memset(out + 16, 0, 256);
	memcpy(out + 16, password, pl > 256 ? 256 : pl);
	ln_cast128_setkey(&c, x->key, 16);
	ln_cast128_cbc_encrypt(&c, iv_c2s, out, 16 + 256);
	ln_wipe(&c, sizeof(c));
	return 16 + 256;
}

void afp_dhcast_ma(AfpDhx *x, const u8 *ra, size_t ralen)
{
	static const u8 g = 7;
	x->plen = 16;
	memcpy(x->p, dhcast_p, 16);
	ln_bn_modexp(x->ma, &g, 1, ra, ralen, x->p, 16);
}

int afp_dhcast_reply(AfpDhx *x, const u8 *rep, size_t n, const u8 *ra, size_t ralen)
{
	LnCast128 c;
	u8 buf[32];
	int r;
	if (n < 2 + 16 + 32)
		return LN_EPROTO;
	x->id = ln_be16(rep);
	if (!pubkey_ok(rep + 2, x->p, 16))
		return LN_EPROTO;
	r = ln_bn_modexp(x->key, rep + 2, 16, ra, ralen, x->p, 16);
	if (r)
		return r;
	memcpy(buf, rep + 18, 32);
	ln_cast128_setkey(&c, x->key, 16);
	ln_cast128_cbc_decrypt(&c, iv_s2c, buf, 32);
	ln_wipe(&c, sizeof(c));
	/* serverNonce, then a 16-byte signature (zeros, not checked: the
	 * server proves nothing here; the password goes encrypted anyway) */
	memcpy(x->snonce, buf, 16);
	ln_wipe(buf, sizeof(buf));
	return LN_OK;
}

size_t afp_dhcast_cont(AfpDhx *x, const char *password, u8 *out)
{
	LnCast128 c;
	size_t pl = strlen(password);
	memcpy(out, x->snonce, 16);
	afp_nonce_inc(out);
	memset(out + 16, 0, 64);
	memcpy(out + 16, password, pl > 64 ? 64 : pl);
	ln_cast128_setkey(&c, x->key, 16);
	ln_cast128_cbc_encrypt(&c, iv_c2s, out, 16 + 64);
	ln_wipe(&c, sizeof(c));
	return 16 + 64;
}
