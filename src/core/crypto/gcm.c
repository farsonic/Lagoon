/*
 * Lagoon - AES-GCM and GMAC (NIST SP 800-38D), used for SMB 3.1.1
 * encryption and AES-GMAC signing. GHASH uses a 16-entry (4-bit) table
 * per key and 32-bit words only, which suits the 68020. Written from the
 * spec; the reduction table holds the constant products of the 4 bits
 * shifted out with the GCM polynomial.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../ln_cipher.h"

static const u16 red4[16] = {
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

int ln_gcm_setkey(LnGcm *g, const u8 *key, int keylen)
{
	u8 h[16];
	u32 v[4];
	int i, j;
	if (ln_aes_setkey(&g->aes, key, keylen))
		return -1;
	memset(h, 0, 16);
	ln_aes_encrypt(&g->aes, h, h);
	for (i = 0; i < 4; i++)
		v[i] = ln_be32(h + 4 * i);
	/* m[8] = H, m[4] = H*x, m[2] = H*x^2, m[1] = H*x^3 (bit-reflected order) */
	memset(g->m, 0, sizeof(g->m));
	for (i = 8; i; i >>= 1) {
		u32 lsb = v[3] & 1;
		memcpy(g->m[i], v, sizeof(v));
		v[3] = (v[3] >> 1) | (v[2] << 31);
		v[2] = (v[2] >> 1) | (v[1] << 31);
		v[1] = (v[1] >> 1) | (v[0] << 31);
		v[0] = (v[0] >> 1) ^ (lsb ? 0xe1000000u : 0);
	}
	for (i = 2; i < 16; i <<= 1)
		for (j = 1; j < i; j++) {
			int k;
			for (k = 0; k < 4; k++)
				g->m[i + j][k] = g->m[i][k] ^ g->m[j][k];
		}
	ln_wipe(h, 16);
	return 0;
}

/* y = (y ^ blk) * H */
static void ghash_blk(const LnGcm *g, u32 y[4], const u8 *blk, size_t n)
{
	u8 x[16];
	u32 z0 = 0, z1 = 0, z2 = 0, z3 = 0;
	int i;
	memset(x, 0, 16);
	memcpy(x, blk, n);
	for (i = 0; i < 4; i++)
		ln_put_be32(x + 4 * i, ln_be32(x + 4 * i) ^ y[i]);
	for (i = 15; i >= 0; i--) {
		int nib, half;
		for (half = 0; half < 2; half++) {
			const u32 *m;
			u32 rem;
			nib = half ? x[i] >> 4 : x[i] & 15;
			if (i != 15 || half) {
				rem = z3 & 15;
				z3 = (z3 >> 4) | (z2 << 28);
				z2 = (z2 >> 4) | (z1 << 28);
				z1 = (z1 >> 4) | (z0 << 28);
				z0 = (z0 >> 4) ^ ((u32)red4[rem] << 16);
			}
			m = g->m[nib];
			z0 ^= m[0]; z1 ^= m[1]; z2 ^= m[2]; z3 ^= m[3];
		}
	}
	y[0] = z0; y[1] = z1; y[2] = z2; y[3] = z3;
}

static void ghash(const LnGcm *g, u32 y[4], const u8 *p, size_t n)
{
	size_t m;
	for (; n; p += m, n -= m) {
		m = LN_MIN(n, 16);
		ghash_blk(g, y, p, m);
	}
}

static void ctr32(const LnGcm *g, u8 ctr[16], u8 *data, size_t n)
{
	u8 ks[16];
	size_t m, i;
	for (; n; data += m, n -= m) {
		ln_put_be32(ctr + 12, ln_be32(ctr + 12) + 1);
		ln_aes_encrypt(&g->aes, ctr, ks);
		m = LN_MIN(n, 16);
		for (i = 0; i < m; i++)
			data[i] ^= ks[i];
	}
}

static void gtag(const LnGcm *g, const u8 iv[12], const u8 *aad, size_t alen, const u8 *c, size_t n, u8 tag[16])
{
	u32 y[4];
	u8 lens[16], j0[16];
	int i;
	memset(y, 0, sizeof(y));
	ghash(g, y, aad, alen);
	ghash(g, y, c, n);
	ln_put_be32(lens, (u32)((u64)alen >> 29));
	ln_put_be32(lens + 4, (u32)(alen << 3));
	ln_put_be32(lens + 8, (u32)((u64)n >> 29));
	ln_put_be32(lens + 12, (u32)(n << 3));
	ghash_blk(g, y, lens, 16);
	memcpy(j0, iv, 12);
	ln_put_be32(j0 + 12, 1);
	ln_aes_encrypt(&g->aes, j0, j0);
	for (i = 0; i < 4; i++)
		ln_put_be32(tag + 4 * i, y[i] ^ ln_be32(j0 + 4 * i));
}

void ln_gcm_encrypt(const LnGcm *g, const u8 iv[12], const u8 *aad, size_t alen, u8 *data, size_t n, u8 tag[16])
{
	u8 ctr[16];
	memcpy(ctr, iv, 12);
	ln_put_be32(ctr + 12, 1);
	ctr32(g, ctr, data, n);
	gtag(g, iv, aad, alen, data, n, tag);
}

int ln_gcm_decrypt(const LnGcm *g, const u8 iv[12], const u8 *aad, size_t alen, u8 *data, size_t n, const u8 tag[16])
{
	u8 ctr[16], t[16];
	gtag(g, iv, aad, alen, data, n, t);
	if (!ln_memeq_ct(t, tag, 16))
		return -1;
	memcpy(ctr, iv, 12);
	ln_put_be32(ctr + 12, 1);
	ctr32(g, ctr, data, n);
	return 0;
}

void ln_gmac(const LnGcm *g, const u8 iv[12], const void *msg, size_t n, u8 tag[16])
{
	gtag(g, iv, msg, n, NULL, 0, tag);
}
