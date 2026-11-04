/*
 * Lagoon - AES-GCM and GMAC (NIST SP 800-38D), used for SMB 3.1.1
 * encryption and AES-GMAC signing. GHASH uses a 256-entry (8-bit) table
 * per key (4 KB) and 32-bit words only (Shoup's method with 8-bit digits:
 * 16 steps of a byte shift, one reduction lookup and one table row per
 * block, against 32 steps with 4-bit shifts for the 4-bit table, which
 * costs more on a 68k: byte shifts are cheap move.b/ror there). Written
 * from the spec; the reduction table holds the constant products of the
 * 8 bits shifted out with the GCM polynomial. The Amiga build takes
 * ln_ghash_blocks from ghash68k.s.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../ln_cipher.h"

/* red8[r]: what the 8 bits r shifted out of Z (Z * x^8) fold back into its
 * top word: the GCM polynomial products, already shifted into bits 16..31.
 * Shared with ghash68k.s. */
const u32 ln_gcm_red8[256] = {
	0x00000000u, 0x01c20000u, 0x03840000u, 0x02460000u, 0x07080000u, 0x06ca0000u, 0x048c0000u, 0x054e0000u,
	0x0e100000u, 0x0fd20000u, 0x0d940000u, 0x0c560000u, 0x09180000u, 0x08da0000u, 0x0a9c0000u, 0x0b5e0000u,
	0x1c200000u, 0x1de20000u, 0x1fa40000u, 0x1e660000u, 0x1b280000u, 0x1aea0000u, 0x18ac0000u, 0x196e0000u,
	0x12300000u, 0x13f20000u, 0x11b40000u, 0x10760000u, 0x15380000u, 0x14fa0000u, 0x16bc0000u, 0x177e0000u,
	0x38400000u, 0x39820000u, 0x3bc40000u, 0x3a060000u, 0x3f480000u, 0x3e8a0000u, 0x3ccc0000u, 0x3d0e0000u,
	0x36500000u, 0x37920000u, 0x35d40000u, 0x34160000u, 0x31580000u, 0x309a0000u, 0x32dc0000u, 0x331e0000u,
	0x24600000u, 0x25a20000u, 0x27e40000u, 0x26260000u, 0x23680000u, 0x22aa0000u, 0x20ec0000u, 0x212e0000u,
	0x2a700000u, 0x2bb20000u, 0x29f40000u, 0x28360000u, 0x2d780000u, 0x2cba0000u, 0x2efc0000u, 0x2f3e0000u,
	0x70800000u, 0x71420000u, 0x73040000u, 0x72c60000u, 0x77880000u, 0x764a0000u, 0x740c0000u, 0x75ce0000u,
	0x7e900000u, 0x7f520000u, 0x7d140000u, 0x7cd60000u, 0x79980000u, 0x785a0000u, 0x7a1c0000u, 0x7bde0000u,
	0x6ca00000u, 0x6d620000u, 0x6f240000u, 0x6ee60000u, 0x6ba80000u, 0x6a6a0000u, 0x682c0000u, 0x69ee0000u,
	0x62b00000u, 0x63720000u, 0x61340000u, 0x60f60000u, 0x65b80000u, 0x647a0000u, 0x663c0000u, 0x67fe0000u,
	0x48c00000u, 0x49020000u, 0x4b440000u, 0x4a860000u, 0x4fc80000u, 0x4e0a0000u, 0x4c4c0000u, 0x4d8e0000u,
	0x46d00000u, 0x47120000u, 0x45540000u, 0x44960000u, 0x41d80000u, 0x401a0000u, 0x425c0000u, 0x439e0000u,
	0x54e00000u, 0x55220000u, 0x57640000u, 0x56a60000u, 0x53e80000u, 0x522a0000u, 0x506c0000u, 0x51ae0000u,
	0x5af00000u, 0x5b320000u, 0x59740000u, 0x58b60000u, 0x5df80000u, 0x5c3a0000u, 0x5e7c0000u, 0x5fbe0000u,
	0xe1000000u, 0xe0c20000u, 0xe2840000u, 0xe3460000u, 0xe6080000u, 0xe7ca0000u, 0xe58c0000u, 0xe44e0000u,
	0xef100000u, 0xeed20000u, 0xec940000u, 0xed560000u, 0xe8180000u, 0xe9da0000u, 0xeb9c0000u, 0xea5e0000u,
	0xfd200000u, 0xfce20000u, 0xfea40000u, 0xff660000u, 0xfa280000u, 0xfbea0000u, 0xf9ac0000u, 0xf86e0000u,
	0xf3300000u, 0xf2f20000u, 0xf0b40000u, 0xf1760000u, 0xf4380000u, 0xf5fa0000u, 0xf7bc0000u, 0xf67e0000u,
	0xd9400000u, 0xd8820000u, 0xdac40000u, 0xdb060000u, 0xde480000u, 0xdf8a0000u, 0xddcc0000u, 0xdc0e0000u,
	0xd7500000u, 0xd6920000u, 0xd4d40000u, 0xd5160000u, 0xd0580000u, 0xd19a0000u, 0xd3dc0000u, 0xd21e0000u,
	0xc5600000u, 0xc4a20000u, 0xc6e40000u, 0xc7260000u, 0xc2680000u, 0xc3aa0000u, 0xc1ec0000u, 0xc02e0000u,
	0xcb700000u, 0xcab20000u, 0xc8f40000u, 0xc9360000u, 0xcc780000u, 0xcdba0000u, 0xcffc0000u, 0xce3e0000u,
	0x91800000u, 0x90420000u, 0x92040000u, 0x93c60000u, 0x96880000u, 0x974a0000u, 0x950c0000u, 0x94ce0000u,
	0x9f900000u, 0x9e520000u, 0x9c140000u, 0x9dd60000u, 0x98980000u, 0x995a0000u, 0x9b1c0000u, 0x9ade0000u,
	0x8da00000u, 0x8c620000u, 0x8e240000u, 0x8fe60000u, 0x8aa80000u, 0x8b6a0000u, 0x892c0000u, 0x88ee0000u,
	0x83b00000u, 0x82720000u, 0x80340000u, 0x81f60000u, 0x84b80000u, 0x857a0000u, 0x873c0000u, 0x86fe0000u,
	0xa9c00000u, 0xa8020000u, 0xaa440000u, 0xab860000u, 0xaec80000u, 0xaf0a0000u, 0xad4c0000u, 0xac8e0000u,
	0xa7d00000u, 0xa6120000u, 0xa4540000u, 0xa5960000u, 0xa0d80000u, 0xa11a0000u, 0xa35c0000u, 0xa29e0000u,
	0xb5e00000u, 0xb4220000u, 0xb6640000u, 0xb7a60000u, 0xb2e80000u, 0xb32a0000u, 0xb16c0000u, 0xb0ae0000u,
	0xbbf00000u, 0xba320000u, 0xb8740000u, 0xb9b60000u, 0xbcf80000u, 0xbd3a0000u, 0xbf7c0000u, 0xbebe0000u,
};

/* y = (y ^ block) * H for nblk whole blocks (C here, ghash68k.s on the Amiga) */
void ln_ghash_blocks(const LnGcm *g, u32 y[4], const u8 *p, size_t nblk);

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
	/* row 128 = H, 64 = H*x, ... 1 = H*x^7 (bit-reflected order), then all sums */
	memset(g->mh, 0, sizeof(g->mh));
	memset(g->ml, 0, sizeof(g->ml));
	for (i = 128; i; i >>= 1) {
		u32 lsb = v[3] & 1;
		g->mh[i][0] = v[0]; g->mh[i][1] = v[1]; g->ml[i][0] = v[2]; g->ml[i][1] = v[3];
		v[3] = (v[3] >> 1) | (v[2] << 31);
		v[2] = (v[2] >> 1) | (v[1] << 31);
		v[1] = (v[1] >> 1) | (v[0] << 31);
		v[0] = (v[0] >> 1) ^ (lsb ? 0xe1000000u : 0);
	}
	for (i = 2; i < 256; i <<= 1)
		for (j = 1; j < i; j++) {
			g->mh[i + j][0] = g->mh[i][0] ^ g->mh[j][0];
			g->mh[i + j][1] = g->mh[i][1] ^ g->mh[j][1];
			g->ml[i + j][0] = g->ml[i][0] ^ g->ml[j][0];
			g->ml[i + j][1] = g->ml[i][1] ^ g->ml[j][1];
		}
	ln_wipe(v, sizeof(v));
	ln_wipe(h, 16);
	return 0;
}

#ifndef LN_CRYPTO_ASM
/* one byte (8-bit table) at a time, Horner from the last byte */
void ln_ghash_blocks(const LnGcm *g, u32 y[4], const u8 *p, size_t nblk)
{
	u8 x[16];
	u32 z0 = y[0], z1 = y[1], z2 = y[2], z3 = y[3], rem;
	int i;
	for (; nblk; nblk--, p += 16) {
		ln_put_be32(x, ln_be32(p) ^ z0);
		ln_put_be32(x + 4, ln_be32(p + 4) ^ z1);
		ln_put_be32(x + 8, ln_be32(p + 8) ^ z2);
		ln_put_be32(x + 12, ln_be32(p + 12) ^ z3);
		z0 = g->mh[x[15]][0]; z1 = g->mh[x[15]][1]; z2 = g->ml[x[15]][0]; z3 = g->ml[x[15]][1];
		for (i = 14; i >= 0; i--) {
			rem = z3 & 255;
			z3 = (z3 >> 8) | (z2 << 24);
			z2 = (z2 >> 8) | (z1 << 24);
			z1 = (z1 >> 8) | (z0 << 24);
			z0 = (z0 >> 8) ^ ln_gcm_red8[rem];
			z0 ^= g->mh[x[i]][0]; z1 ^= g->mh[x[i]][1];
			z2 ^= g->ml[x[i]][0]; z3 ^= g->ml[x[i]][1];
		}
	}
	y[0] = z0; y[1] = z1; y[2] = z2; y[3] = z3;
}
#endif

/* whole blocks in one call, a partial tail zero padded */
static void ghash(const LnGcm *g, u32 y[4], const u8 *p, size_t n)
{
	u8 x[16];
	ln_ghash_blocks(g, y, p, n / 16);
	if (n & 15) {
		memset(x, 0, 16);
		memcpy(x, p + (n & ~(size_t)15), n & 15);
		ln_ghash_blocks(g, y, x, 1);
	}
}

static void ctr32(const LnGcm *g, u8 ctr[16], u8 *data, size_t n)
{
	u8 ks[16];
	size_t i, m = n & 15;
	ln_aes_ctr32(&g->aes, ctr, data, n / 16);
	if (m) {
		data += n - m;
		memset(ks, 0, 16);
		memcpy(ks, data, m);
		ln_aes_ctr32(&g->aes, ctr, ks, 1);
		for (i = 0; i < m; i++)
			data[i] = ks[i];
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
	ln_ghash_blocks(g, y, lens, 1);
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
