/*
 * Lagoon - AES-CCM (NIST SP 800-38C, RFC 3610), used for SMB 3.x
 * encryption (11-byte nonce, 16-byte tag). Written from the spec.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../ln_cipher.h"

static void xorblk(u8 *x, const u8 *p, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		x[i] ^= p[i];
}

/* CBC-MAC of B0 | encoded AAD | data into x */
static void ccm_mac(const LnAes *a, const u8 *nonce, int nlen, const u8 *aad, size_t alen,
                    const u8 *data, size_t n, int tlen, u8 x[16])
{
	int L = 15 - nlen, i;
	u8 b[16];
	size_t k, m;
	b[0] = (u8)((alen ? 0x40 : 0) | (((tlen - 2) / 2) << 3) | (L - 1));
	memcpy(b + 1, nonce, (size_t)nlen);
	for (i = 0, k = n; i < L; i++, k >>= 8)
		b[15 - i] = (u8)k;
	ln_aes_encrypt(a, b, x);
	if (alen) {
		/* length prefix (2 bytes; 6 for >= 0xff00) then the AAD, zero padded */
		memset(b, 0, 16);
		if (alen < 0xff00) {
			ln_put_be16(b, (u16)alen);
			k = 2;
		} else {
			b[0] = 0xff; b[1] = 0xfe;
			ln_put_be32(b + 2, (u32)alen);
			k = 6;
		}
		m = LN_MIN(alen, 16 - k);
		memcpy(b + k, aad, m);
		xorblk(x, b, 16);
		ln_aes_encrypt(a, x, x);
		for (aad += m, alen -= m; alen; aad += m, alen -= m) {
			m = LN_MIN(alen, 16);
			xorblk(x, aad, m);
			ln_aes_encrypt(a, x, x);
		}
	}
	for (; n; data += m, n -= m) {
		m = LN_MIN(n, 16);
		xorblk(x, data, m);
		ln_aes_encrypt(a, x, x);
	}
}

/* CTR keystream: counter block i (0 encrypts the tag) */
static void ccm_ctr(const LnAes *a, const u8 *nonce, int nlen, u8 *data, size_t n, u8 s0[16])
{
	int L = 15 - nlen, i;
	u8 ctr[16], ks[16];
	u32 c = 0;
	size_t m;
	memset(ctr, 0, 16);
	ctr[0] = (u8)(L - 1);
	memcpy(ctr + 1, nonce, (size_t)nlen);
	ln_aes_encrypt(a, ctr, s0);
	for (; n; data += m, n -= m) {
		c++;
		for (i = 0; i < L && i < 4; i++)
			ctr[15 - i] = (u8)(c >> (8 * i));
		ln_aes_encrypt(a, ctr, ks);
		m = LN_MIN(n, 16);
		xorblk(data, ks, m);
	}
}

void ln_aes_ccm_encrypt(const LnAes *a, const u8 *nonce, int nlen, const u8 *aad, size_t alen,
                        u8 *data, size_t n, u8 *tag, int tlen)
{
	u8 x[16], s0[16];
	ccm_mac(a, nonce, nlen, aad, alen, data, n, tlen, x);
	ccm_ctr(a, nonce, nlen, data, n, s0);
	xorblk(x, s0, 16);
	memcpy(tag, x, (size_t)tlen);
}

int ln_aes_ccm_decrypt(const LnAes *a, const u8 *nonce, int nlen, const u8 *aad, size_t alen,
                       u8 *data, size_t n, const u8 *tag, int tlen)
{
	u8 x[16], s0[16];
	ccm_ctr(a, nonce, nlen, data, n, s0);
	ccm_mac(a, nonce, nlen, aad, alen, data, n, tlen, x);
	xorblk(x, s0, 16);
	if (!ln_memeq_ct(x, tag, (size_t)tlen)) {
		ln_wipe(data, n);
		return -1;
	}
	return 0;
}
