/* Lagoon - cipher tests: AES (FIPS-197), CMAC (RFC 4493), CCM (RFC 3610 +
 * SMB-shaped vector), GCM/GMAC (GCM spec test case 4 + extra), RC4.
 * Extra vectors were cross-checked with Python's "cryptography" package.
 * SPDX-License-Identifier: GPL-2.0-only */
#include "testutil.h"
#include "ln_cipher.h"
#include "ln_sys.h"

static int unhex(const char *s, u8 *out)
{
	int n = 0;
	while (s[0] && s[1]) {
		unsigned v;
		sscanf(s, "%2x", &v);
		out[n++] = (u8)v;
		s += 2;
	}
	return n;
}

static void aes(void)
{
	LnAes a;
	u8 k[32], in[16], out[16];
	unhex("000102030405060708090a0b0c0d0e0f", k);
	unhex("00112233445566778899aabbccddeeff", in);
	CHECK_INT(ln_aes_setkey(&a, k, 16), 0);
	ln_aes_encrypt(&a, in, out);
	CHECK_HEX(out, 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
	unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", k);
	CHECK_INT(ln_aes_setkey(&a, k, 32), 0);
	ln_aes_encrypt(&a, in, out);
	CHECK_HEX(out, 16, "8ea2b7ca516745bfeafc49904b496089");
	CHECK_INT(ln_aes_setkey(&a, k, 24), -1);
}

static void cmac(void)
{
	LnAes a;
	u8 k[16], m[64], mac[16];
	unhex("2b7e151628aed2a6abf7158809cf4f3c", k);
	unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", m);
	ln_aes_setkey(&a, k, 16);
	ln_aes_cmac(&a, m, 0, mac); CHECK_HEX(mac, 16, "bb1d6929e95937287fa37d129b756746");
	ln_aes_cmac(&a, m, 16, mac); CHECK_HEX(mac, 16, "070a16b46b4d4144f79bdd9dd04a287c");
	ln_aes_cmac(&a, m, 40, mac); CHECK_HEX(mac, 16, "dfa66747de9ae63030ca32611497c827");
	ln_aes_cmac(&a, m, 64, mac); CHECK_HEX(mac, 16, "51f0bebf7e3b9d92fc49741779363cfe");
}

static void ccm(void)
{
	LnAes a;
	u8 k[16], nonce[13], aad[32], d[128], tag[16], keep[128];
	int i;
	/* RFC 3610 packet vector #1 */
	unhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", k);
	unhex("00000003020100a0a1a2a3a4a5", nonce);
	unhex("0001020304050607", aad);
	unhex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e", d);
	ln_aes_setkey(&a, k, 16);
	ln_aes_ccm_encrypt(&a, nonce, 13, aad, 8, d, 23, tag, 8);
	CHECK_HEX(d, 23, "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384");
	CHECK_HEX(tag, 8, "17e8d12cfdf926e0");
	CHECK_INT(ln_aes_ccm_decrypt(&a, nonce, 13, aad, 8, d, 23, tag, 8), 0);
	CHECK_HEX(d, 23, "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
	/* SMB 3.0 shape: 11-byte nonce, 32-byte AAD, 16-byte tag */
	for (i = 0; i < 16; i++) k[i] = (u8)i;
	for (i = 0; i < 11; i++) nonce[i] = (u8)(0x10 + i);
	for (i = 0; i < 32; i++) aad[i] = (u8)(0x40 + i);
	for (i = 0; i < 77; i++) d[i] = (u8)(i * 7);
	memcpy(keep, d, 77);
	ln_aes_setkey(&a, k, 16);
	ln_aes_ccm_encrypt(&a, nonce, 11, aad, 32, d, 77, tag, 16);
	CHECK_HEX(d, 77, "4c6873cedc9e7b9ab633af2e7638fcc7511fa6dcc34ee04e42ef30be59330033e92d9a4fbf416571806ce7aed370182e24a925376484225cc5b3a0dff8b200f809806291593a5b7d481a42ad02");
	CHECK_HEX(tag, 16, "bf6e476edf73240126f2768242b98cdd");
	CHECK_INT(ln_aes_ccm_decrypt(&a, nonce, 11, aad, 32, d, 77, tag, 16), 0);
	CHECK(!memcmp(d, keep, 77));
	ln_aes_ccm_encrypt(&a, nonce, 11, aad, 32, d, 77, tag, 16);
	d[5] ^= 1;
	CHECK_INT(ln_aes_ccm_decrypt(&a, nonce, 11, aad, 32, d, 77, tag, 16), -1);
}

static void gcm(void)
{
	static LnGcm g;
	u8 k[32], iv[12], aad[200], d[128], tag[16], keep[128];
	int n, i;
	/* GCM spec test case 4 */
	unhex("feffe9928665731c6d6a8f9467308308", k);
	unhex("cafebabefacedbaddecaf888", iv);
	unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad);
	n = unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", d);
	memcpy(keep, d, (size_t)n);
	ln_gcm_setkey(&g, k, 16);
	ln_gcm_encrypt(&g, iv, aad, 20, d, (size_t)n, tag);
	CHECK_HEX(d, n, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091");
	CHECK_HEX(tag, 16, "5bc94fbc3221a5db94fae95ae7121a47");
	CHECK_INT(ln_gcm_decrypt(&g, iv, aad, 20, d, (size_t)n, tag), 0);
	CHECK(!memcmp(d, keep, (size_t)n));
	tag[0] ^= 1;
	CHECK_INT(ln_gcm_decrypt(&g, iv, aad, 20, d, (size_t)n, tag), -1);
	/* AES-256-GCM, zero IV, 100 bytes */
	for (i = 0; i < 32; i++) k[i] = (u8)i;
	for (i = 0; i < 100; i++) d[i] = (u8)i;
	memset(iv, 0, 12);
	ln_gcm_setkey(&g, k, 32);
	ln_gcm_encrypt(&g, iv, (const u8 *)"hdr", 3, d, 100, tag);
	CHECK_HEX(d, 100, "0ebdb7ddb12985ba00a1a33e14219f96c25244403c9476389887a998d9e243496e7ec49f0ed79e211bea5bdeede34761993673d54d447092688f051d765d70dba92e7c49d59416a59bc0998c5a6906d60d4464ca74fd13166cff4e18a2028fefb7302c64");
	CHECK_HEX(tag, 16, "0b6da14fd6105f4500ab4757a8d1270b");
	/* GMAC over 200 bytes */
	for (i = 0; i < 16; i++) k[i] = (u8)i;
	for (i = 0; i < 11; i++) iv[i] = (u8)(0x10 + i);
	iv[11] = 0;
	for (i = 0; i < 200; i++) aad[i] = (u8)i;
	ln_gcm_setkey(&g, k, 16);
	ln_gmac(&g, iv, aad, 200, tag);
	CHECK_HEX(tag, 16, "04bbca75fee02ece694ed04eba219413");
}

static void rc4(void)
{
	LnRc4 r;
	u8 out[16];
	ln_rc4_init(&r, (const u8 *)"Key", 3);
	ln_rc4_crypt(&r, (const u8 *)"Plaintext", out, 9);
	CHECK_HEX(out, 9, "bbf316e8d940af0ad3");
	ln_rc4_init(&r, (const u8 *)"Secret", 6);
	ln_rc4_crypt(&r, (const u8 *)"Attack at dawn", out, 14);
	CHECK_HEX(out, 14, "45a01f645fc35b383552544b9bf5");
}

/* rough host speed numbers (informational) */
static void speed(void)
{
	static u8 buf[65536];
	static LnGcm g;
	LnAes a;
	u8 k[16] = { 1 }, tag[16], nonce[12] = { 0 };
	u32 t0 = ln_ms();
	int i;
	ln_aes_setkey(&a, k, 16);
	ln_gcm_setkey(&g, k, 16);
	for (i = 0; i < 16; i++) ln_aes_ccm_encrypt(&a, nonce, 11, k, 16, buf, sizeof(buf), tag, 16);
	printf("t_cipher: CCM 1 MB in %u ms;", ln_ms() - t0);
	t0 = ln_ms();
	for (i = 0; i < 16; i++) ln_gcm_encrypt(&g, nonce, k, 16, buf, sizeof(buf), tag);
	printf(" GCM 1 MB in %u ms;", ln_ms() - t0);
	t0 = ln_ms();
	for (i = 0; i < 16; i++) ln_aes_cmac(&a, buf, sizeof(buf), tag);
	printf(" CMAC 1 MB in %u ms\n", ln_ms() - t0);
}

int main(void)
{
	aes();
	cmac();
	ccm();
	gcm();
	rc4();
	speed();
	T_DONE("t_cipher");
}
