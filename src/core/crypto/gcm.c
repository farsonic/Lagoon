/*
 * Lagoon - AES-GCM and GMAC (NIST SP 800-38D), used for SMB 3.1.1
 * encryption and AES-GMAC signing. GHASH uses a 256-entry (8-bit) table
 * per key (4 KB) and 32-bit words only: half the work of a 4-bit table on
 * the 68020, where GMAC signing of every message is the main cost. Written from the
 * spec; the reduction table holds the constant products of the 8 bits
 * shifted out with the GCM polynomial.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../ln_cipher.h"

/* red8[r]: what the 8 bits r shifted out of Z (Z * x^8) fold back into its top 16 bits */
static const u16 red8[256] = {
	0x0000, 0x01c2, 0x0384, 0x0246, 0x0708, 0x06ca, 0x048c, 0x054e,
	0x0e10, 0x0fd2, 0x0d94, 0x0c56, 0x0918, 0x08da, 0x0a9c, 0x0b5e,
	0x1c20, 0x1de2, 0x1fa4, 0x1e66, 0x1b28, 0x1aea, 0x18ac, 0x196e,
	0x1230, 0x13f2, 0x11b4, 0x1076, 0x1538, 0x14fa, 0x16bc, 0x177e,
	0x3840, 0x3982, 0x3bc4, 0x3a06, 0x3f48, 0x3e8a, 0x3ccc, 0x3d0e,
	0x3650, 0x3792, 0x35d4, 0x3416, 0x3158, 0x309a, 0x32dc, 0x331e,
	0x2460, 0x25a2, 0x27e4, 0x2626, 0x2368, 0x22aa, 0x20ec, 0x212e,
	0x2a70, 0x2bb2, 0x29f4, 0x2836, 0x2d78, 0x2cba, 0x2efc, 0x2f3e,
	0x7080, 0x7142, 0x7304, 0x72c6, 0x7788, 0x764a, 0x740c, 0x75ce,
	0x7e90, 0x7f52, 0x7d14, 0x7cd6, 0x7998, 0x785a, 0x7a1c, 0x7bde,
	0x6ca0, 0x6d62, 0x6f24, 0x6ee6, 0x6ba8, 0x6a6a, 0x682c, 0x69ee,
	0x62b0, 0x6372, 0x6134, 0x60f6, 0x65b8, 0x647a, 0x663c, 0x67fe,
	0x48c0, 0x4902, 0x4b44, 0x4a86, 0x4fc8, 0x4e0a, 0x4c4c, 0x4d8e,
	0x46d0, 0x4712, 0x4554, 0x4496, 0x41d8, 0x401a, 0x425c, 0x439e,
	0x54e0, 0x5522, 0x5764, 0x56a6, 0x53e8, 0x522a, 0x506c, 0x51ae,
	0x5af0, 0x5b32, 0x5974, 0x58b6, 0x5df8, 0x5c3a, 0x5e7c, 0x5fbe,
	0xe100, 0xe0c2, 0xe284, 0xe346, 0xe608, 0xe7ca, 0xe58c, 0xe44e,
	0xef10, 0xeed2, 0xec94, 0xed56, 0xe818, 0xe9da, 0xeb9c, 0xea5e,
	0xfd20, 0xfce2, 0xfea4, 0xff66, 0xfa28, 0xfbea, 0xf9ac, 0xf86e,
	0xf330, 0xf2f2, 0xf0b4, 0xf176, 0xf438, 0xf5fa, 0xf7bc, 0xf67e,
	0xd940, 0xd882, 0xdac4, 0xdb06, 0xde48, 0xdf8a, 0xddcc, 0xdc0e,
	0xd750, 0xd692, 0xd4d4, 0xd516, 0xd058, 0xd19a, 0xd3dc, 0xd21e,
	0xc560, 0xc4a2, 0xc6e4, 0xc726, 0xc268, 0xc3aa, 0xc1ec, 0xc02e,
	0xcb70, 0xcab2, 0xc8f4, 0xc936, 0xcc78, 0xcdba, 0xcffc, 0xce3e,
	0x9180, 0x9042, 0x9204, 0x93c6, 0x9688, 0x974a, 0x950c, 0x94ce,
	0x9f90, 0x9e52, 0x9c14, 0x9dd6, 0x9898, 0x995a, 0x9b1c, 0x9ade,
	0x8da0, 0x8c62, 0x8e24, 0x8fe6, 0x8aa8, 0x8b6a, 0x892c, 0x88ee,
	0x83b0, 0x8272, 0x8034, 0x81f6, 0x84b8, 0x857a, 0x873c, 0x86fe,
	0xa9c0, 0xa802, 0xaa44, 0xab86, 0xaec8, 0xaf0a, 0xad4c, 0xac8e,
	0xa7d0, 0xa612, 0xa454, 0xa596, 0xa0d8, 0xa11a, 0xa35c, 0xa29e,
	0xb5e0, 0xb422, 0xb664, 0xb7a6, 0xb2e8, 0xb32a, 0xb16c, 0xb0ae,
	0xbbf0, 0xba32, 0xb874, 0xb9b6, 0xbcf8, 0xbd3a, 0xbf7c, 0xbebe,
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
	/* m[128] = H, m[64] = H*x, ... m[1] = H*x^7 (bit-reflected order), then all sums */
	memset(g->m, 0, sizeof(g->m));
	for (i = 128; i; i >>= 1) {
		u32 lsb = v[3] & 1;
		memcpy(g->m[i], v, sizeof(v));
		v[3] = (v[3] >> 1) | (v[2] << 31);
		v[2] = (v[2] >> 1) | (v[1] << 31);
		v[1] = (v[1] >> 1) | (v[0] << 31);
		v[0] = (v[0] >> 1) ^ (lsb ? 0xe1000000u : 0);
	}
	for (i = 2; i < 256; i <<= 1)
		for (j = 1; j < i; j++) {
			int k;
			for (k = 0; k < 4; k++)
				g->m[i + j][k] = g->m[i][k] ^ g->m[j][k];
		}
	ln_wipe(h, 16);
	return 0;
}

/* y = (y ^ blk) * H, one byte (8-bit table) at a time, Horner from the last byte */
static void ghash_blk(const LnGcm *g, u32 y[4], const u8 *blk, size_t n)
{
	u8 x[16];
	u32 z0, z1, z2, z3, rem;
	const u32 *m;
	int i;
	memset(x, 0, 16);
	memcpy(x, blk, n);
	for (i = 0; i < 4; i++)
		ln_put_be32(x + 4 * i, ln_be32(x + 4 * i) ^ y[i]);
	m = g->m[x[15]];
	z0 = m[0]; z1 = m[1]; z2 = m[2]; z3 = m[3];
	for (i = 14; i >= 0; i--) {
		rem = z3 & 255;
		z3 = (z3 >> 8) | (z2 << 24);
		z2 = (z2 >> 8) | (z1 << 24);
		z1 = (z1 >> 8) | (z0 << 24);
		z0 = (z0 >> 8) ^ ((u32)red8[rem] << 16);
		m = g->m[x[i]];
		z0 ^= m[0]; z1 ^= m[1]; z2 ^= m[2]; z3 ^= m[3];
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
