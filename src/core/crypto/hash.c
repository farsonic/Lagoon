/*
 * Lagoon - MD4 (RFC 1320, NTLM), MD5 (RFC 1321), SHA-256 and SHA-512
 * (FIPS 180-4), HMAC (RFC 2104). Straightforward portable implementations;
 * the Amiga build takes the SHA-256 compression from sha256_68k.s.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../ln_hash.h"

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/* ---------------- MD4 ---------------- */
static void md4_block(u32 s[4], const u8 *p)
{
	u32 x[16], a = s[0], b = s[1], c = s[2], d = s[3];
	int i;
	static const u8 r2[16] = { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
	static const u8 r3[16] = { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };
	static const u8 s1[4] = { 3, 7, 11, 19 }, s2[4] = { 3, 5, 9, 13 }, s3[4] = { 3, 9, 11, 15 };
	for (i = 0; i < 16; i++) x[i] = ln_le32(p + 4 * i);
	for (i = 0; i < 16; i++) {
		u32 t = a + ((b & c) | (~b & d)) + x[i];
		t = ROL32(t, s1[i & 3]);
		a = d; d = c; c = b; b = t;
	}
	for (i = 0; i < 16; i++) {
		u32 t = a + ((b & c) | (b & d) | (c & d)) + x[r2[i]] + 0x5A827999u;
		t = ROL32(t, s2[i & 3]);
		a = d; d = c; c = b; b = t;
	}
	for (i = 0; i < 16; i++) {
		u32 t = a + (b ^ c ^ d) + x[r3[i]] + 0x6ED9EBA1u;
		t = ROL32(t, s3[i & 3]);
		a = d; d = c; c = b; b = t;
	}
	s[0] += a; s[1] += b; s[2] += c; s[3] += d;
}

/* ---------------- MD5 ---------------- */
static const u32 md5_k[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
static const u8 md5_r[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static void md5_block(u32 s[4], const u8 *p)
{
	u32 x[16], a = s[0], b = s[1], c = s[2], d = s[3];
	int i;
	for (i = 0; i < 16; i++) x[i] = ln_le32(p + 4 * i);
	for (i = 0; i < 64; i++) {
		u32 f, t;
		int g;
		if (i < 16) { f = (b & c) | (~b & d); g = i; }
		else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
		else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
		else { f = c ^ (b | ~d); g = (7 * i) & 15; }
		t = d; d = c; c = b;
		f = a + f + md5_k[i] + x[g];
		b = b + ROL32(f, md5_r[i]);
		a = t;
	}
	s[0] += a; s[1] += b; s[2] += c; s[3] += d;
}

/* shared Merkle-Damgard plumbing for the 64-byte-block hashes */
typedef void (*blockfn)(u32 *s, const u8 *p);

static void upd64(u32 *s, u64 *len, u8 *buf, const void *data, size_t n, blockfn f)
{
	const u8 *p = data;
	size_t have = (size_t)(*len & 63);
	*len += n;
	if (have) {
		size_t t = 64 - have;
		if (n < t) { memcpy(buf + have, p, n); return; }
		memcpy(buf + have, p, t);
		f(s, buf);
		p += t; n -= t;
	}
	while (n >= 64) { f(s, p); p += 64; n -= 64; }
	memcpy(buf, p, n);
}

static void fin64(u32 *s, u64 len, u8 *buf, blockfn f, int be)
{
	size_t have = (size_t)(len & 63);
	u64 bits = len * 8;
	buf[have++] = 0x80;
	if (have > 56) { memset(buf + have, 0, 64 - have); f(s, buf); have = 0; }
	memset(buf + have, 0, 56 - have);
	if (be) ln_put_be64(buf + 56, bits); else ln_put_le64(buf + 56, bits);
	f(s, buf);
}

void ln_md4_init(LnMd4 *c) { c->s[0] = 0x67452301; c->s[1] = 0xefcdab89; c->s[2] = 0x98badcfe; c->s[3] = 0x10325476; c->len = 0; }
void ln_md4_update(LnMd4 *c, const void *p, size_t n) { upd64(c->s, &c->len, c->buf, p, n, md4_block); }
void ln_md4_final(LnMd4 *c, u8 out[16]) { int i; fin64(c->s, c->len, c->buf, md4_block, 0); for (i = 0; i < 4; i++) ln_put_le32(out + 4 * i, c->s[i]); }
void ln_md5_init(LnMd5 *c) { c->s[0] = 0x67452301; c->s[1] = 0xefcdab89; c->s[2] = 0x98badcfe; c->s[3] = 0x10325476; c->len = 0; }
void ln_md5_update(LnMd5 *c, const void *p, size_t n) { upd64(c->s, &c->len, c->buf, p, n, md5_block); }
void ln_md5_final(LnMd5 *c, u8 out[16]) { int i; fin64(c->s, c->len, c->buf, md5_block, 0); for (i = 0; i < 4; i++) ln_put_le32(out + 4 * i, c->s[i]); }

/* ---------------- SHA-256 ---------------- */
/* round constants (shared with sha256_68k.s) */
const u32 ln_sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#ifdef LN_CRYPTO_ASM
void ln_sha256_block(u32 s[8], const u8 *p);   /* sha256_68k.s */
#define sha256_block ln_sha256_block
#else
/* rounds unrolled eight at a time with the variables renamed instead of
 * moved, the message schedule in a 16-word ring computed as it is used */
#define S256_BS0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define S256_BS1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define S256_SS0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define S256_SS1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))
#define S256_W(i) (w[(i) & 15] += S256_SS1(w[((i) - 2) & 15]) + w[((i) - 7) & 15] + S256_SS0(w[((i) - 15) & 15]))
#define S256_R(a, b, c, d, e, f, g, h, i, W)                                       \
	do {                                                                       \
		u32 t1 = h + S256_BS1(e) + (g ^ (e & (f ^ g))) + k[i] + (W);       \
		d += t1;                                                           \
		h = t1 + S256_BS0(a) + ((a & b) | (c & (a | b)));                  \
	} while (0)

static void sha256_block(u32 s[8], const u8 *p)
{
	u32 w[16], a, b, c, d, e, f, g, h;
	const u32 *k = ln_sha256_k;
	int i;
	for (i = 0; i < 16; i++)
		w[i] = ln_be32(p + 4 * i);
	a = s[0]; b = s[1]; c = s[2]; d = s[3]; e = s[4]; f = s[5]; g = s[6]; h = s[7];
	for (i = 0; i < 16; i += 8) {
		S256_R(a, b, c, d, e, f, g, h, i + 0, w[i + 0]);
		S256_R(h, a, b, c, d, e, f, g, i + 1, w[i + 1]);
		S256_R(g, h, a, b, c, d, e, f, i + 2, w[i + 2]);
		S256_R(f, g, h, a, b, c, d, e, i + 3, w[i + 3]);
		S256_R(e, f, g, h, a, b, c, d, i + 4, w[i + 4]);
		S256_R(d, e, f, g, h, a, b, c, i + 5, w[i + 5]);
		S256_R(c, d, e, f, g, h, a, b, i + 6, w[i + 6]);
		S256_R(b, c, d, e, f, g, h, a, i + 7, w[i + 7]);
	}
	for (; i < 64; i += 8) {
		S256_R(a, b, c, d, e, f, g, h, i + 0, S256_W(i + 0));
		S256_R(h, a, b, c, d, e, f, g, i + 1, S256_W(i + 1));
		S256_R(g, h, a, b, c, d, e, f, i + 2, S256_W(i + 2));
		S256_R(f, g, h, a, b, c, d, e, i + 3, S256_W(i + 3));
		S256_R(e, f, g, h, a, b, c, d, i + 4, S256_W(i + 4));
		S256_R(d, e, f, g, h, a, b, c, i + 5, S256_W(i + 5));
		S256_R(c, d, e, f, g, h, a, b, i + 6, S256_W(i + 6));
		S256_R(b, c, d, e, f, g, h, a, i + 7, S256_W(i + 7));
	}
	s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}
#endif

void ln_sha256_init(LnSha256 *c)
{
	static const u32 iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	memcpy(c->s, iv, sizeof(iv));
	c->len = 0;
}
void ln_sha256_update(LnSha256 *c, const void *p, size_t n) { upd64(c->s, &c->len, c->buf, p, n, sha256_block); }
void ln_sha256_final(LnSha256 *c, u8 out[32]) { int i; fin64(c->s, c->len, c->buf, sha256_block, 1); for (i = 0; i < 8; i++) ln_put_be32(out + 4 * i, c->s[i]); }

/* ---------------- SHA-512 ---------------- */
#define K(h, l) (((u64)(h) << 32) | (u64)(l))
static const u64 k512[80] = {
	K(0x428a2f98, 0xd728ae22), K(0x71374491, 0x23ef65cd), K(0xb5c0fbcf, 0xec4d3b2f), K(0xe9b5dba5, 0x8189dbbc),
	K(0x3956c25b, 0xf348b538), K(0x59f111f1, 0xb605d019), K(0x923f82a4, 0xaf194f9b), K(0xab1c5ed5, 0xda6d8118),
	K(0xd807aa98, 0xa3030242), K(0x12835b01, 0x45706fbe), K(0x243185be, 0x4ee4b28c), K(0x550c7dc3, 0xd5ffb4e2),
	K(0x72be5d74, 0xf27b896f), K(0x80deb1fe, 0x3b1696b1), K(0x9bdc06a7, 0x25c71235), K(0xc19bf174, 0xcf692694),
	K(0xe49b69c1, 0x9ef14ad2), K(0xefbe4786, 0x384f25e3), K(0x0fc19dc6, 0x8b8cd5b5), K(0x240ca1cc, 0x77ac9c65),
	K(0x2de92c6f, 0x592b0275), K(0x4a7484aa, 0x6ea6e483), K(0x5cb0a9dc, 0xbd41fbd4), K(0x76f988da, 0x831153b5),
	K(0x983e5152, 0xee66dfab), K(0xa831c66d, 0x2db43210), K(0xb00327c8, 0x98fb213f), K(0xbf597fc7, 0xbeef0ee4),
	K(0xc6e00bf3, 0x3da88fc2), K(0xd5a79147, 0x930aa725), K(0x06ca6351, 0xe003826f), K(0x14292967, 0x0a0e6e70),
	K(0x27b70a85, 0x46d22ffc), K(0x2e1b2138, 0x5c26c926), K(0x4d2c6dfc, 0x5ac42aed), K(0x53380d13, 0x9d95b3df),
	K(0x650a7354, 0x8baf63de), K(0x766a0abb, 0x3c77b2a8), K(0x81c2c92e, 0x47edaee6), K(0x92722c85, 0x1482353b),
	K(0xa2bfe8a1, 0x4cf10364), K(0xa81a664b, 0xbc423001), K(0xc24b8b70, 0xd0f89791), K(0xc76c51a3, 0x0654be30),
	K(0xd192e819, 0xd6ef5218), K(0xd6990624, 0x5565a910), K(0xf40e3585, 0x5771202a), K(0x106aa070, 0x32bbd1b8),
	K(0x19a4c116, 0xb8d2d0c8), K(0x1e376c08, 0x5141ab53), K(0x2748774c, 0xdf8eeb99), K(0x34b0bcb5, 0xe19b48a8),
	K(0x391c0cb3, 0xc5c95a63), K(0x4ed8aa4a, 0xe3418acb), K(0x5b9cca4f, 0x7763e373), K(0x682e6ff3, 0xd6b2b8a3),
	K(0x748f82ee, 0x5defb2fc), K(0x78a5636f, 0x43172f60), K(0x84c87814, 0xa1f0ab72), K(0x8cc70208, 0x1a6439ec),
	K(0x90befffa, 0x23631e28), K(0xa4506ceb, 0xde82bde9), K(0xbef9a3f7, 0xb2c67915), K(0xc67178f2, 0xe372532b),
	K(0xca273ece, 0xea26619c), K(0xd186b8c7, 0x21c0c207), K(0xeada7dd6, 0xcde0eb1e), K(0xf57d4f7f, 0xee6ed178),
	K(0x06f067aa, 0x72176fba), K(0x0a637dc5, 0xa2c898a6), K(0x113f9804, 0xbef90dae), K(0x1b710b35, 0x131c471b),
	K(0x28db77f5, 0x23047d84), K(0x32caab7b, 0x40c72493), K(0x3c9ebe0a, 0x15c9bebc), K(0x431d67c4, 0x9c100d4c),
	K(0x4cc5d4be, 0xcb3e42b6), K(0x597f299c, 0xfc657e2a), K(0x5fcb6fab, 0x3ad6faec), K(0x6c44198c, 0x4a475817)
};

static void sha512_block(u64 s[8], const u8 *p)
{
	u64 w[80], a, b, c, d, e, f, g, h;
	int i;
	for (i = 0; i < 16; i++) w[i] = ln_be64(p + 8 * i);
	for (i = 16; i < 80; i++) {
		u64 s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
		u64 s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = s[0]; b = s[1]; c = s[2]; d = s[3]; e = s[4]; f = s[5]; g = s[6]; h = s[7];
	for (i = 0; i < 80; i++) {
		u64 t1 = h + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41)) + ((e & f) ^ (~e & g)) + k512[i] + w[i];
		u64 t2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

void ln_sha512_init(LnSha512 *c)
{
	static const u64 iv[8] = {
		K(0x6a09e667, 0xf3bcc908), K(0xbb67ae85, 0x84caa73b), K(0x3c6ef372, 0xfe94f82b), K(0xa54ff53a, 0x5f1d36f1),
		K(0x510e527f, 0xade682d1), K(0x9b05688c, 0x2b3e6c1f), K(0x1f83d9ab, 0xfb41bd6b), K(0x5be0cd19, 0x137e2179)
	};
	memcpy(c->s, iv, sizeof(iv));
	c->len = 0;
}

void ln_sha512_update(LnSha512 *c, const void *data, size_t n)
{
	const u8 *p = data;
	size_t have = (size_t)(c->len & 127);
	c->len += n;
	if (have) {
		size_t t = 128 - have;
		if (n < t) { memcpy(c->buf + have, p, n); return; }
		memcpy(c->buf + have, p, t);
		sha512_block(c->s, c->buf);
		p += t; n -= t;
	}
	while (n >= 128) { sha512_block(c->s, p); p += 128; n -= 128; }
	memcpy(c->buf, p, n);
}

void ln_sha512_final(LnSha512 *c, u8 out[64])
{
	size_t have = (size_t)(c->len & 127);
	int i;
	c->buf[have++] = 0x80;
	if (have > 112) { memset(c->buf + have, 0, 128 - have); sha512_block(c->s, c->buf); have = 0; }
	memset(c->buf + have, 0, 120 - have);
	ln_put_be64(c->buf + 120, c->len * 8);
	sha512_block(c->s, c->buf);
	for (i = 0; i < 8; i++) ln_put_be64(out + 8 * i, c->s[i]);
}

/* ---------------- one-shot ---------------- */
void ln_md4(const void *p, size_t n, u8 out[16]) { LnMd4 c; ln_md4_init(&c); ln_md4_update(&c, p, n); ln_md4_final(&c, out); }
void ln_md5(const void *p, size_t n, u8 out[16]) { LnMd5 c; ln_md5_init(&c); ln_md5_update(&c, p, n); ln_md5_final(&c, out); }
void ln_sha256(const void *p, size_t n, u8 out[32]) { LnSha256 c; ln_sha256_init(&c); ln_sha256_update(&c, p, n); ln_sha256_final(&c, out); }
void ln_sha512(const void *p, size_t n, u8 out[64]) { LnSha512 c; ln_sha512_init(&c); ln_sha512_update(&c, p, n); ln_sha512_final(&c, out); }

/* ---------------- HMAC ---------------- */
#define HMAC_IMPL(NAME, CTX, BS, DS, HASH)                                            \
void ln_hmac_##NAME##_init(LnHmac##CTX *h, const void *key, size_t klen)               \
{                                                                                     \
	u8 k[BS], pad[BS];                                                            \
	size_t i;                                                                     \
	memset(k, 0, sizeof(k));                                                      \
	if (klen > BS) ln_##HASH(key, klen, k); else memcpy(k, key, klen);            \
	for (i = 0; i < BS; i++) pad[i] = k[i] ^ 0x36;                                \
	ln_##HASH##_init(&h->in); ln_##HASH##_update(&h->in, pad, BS);                \
	for (i = 0; i < BS; i++) pad[i] = k[i] ^ 0x5c;                                \
	ln_##HASH##_init(&h->out); ln_##HASH##_update(&h->out, pad, BS);              \
	ln_wipe(k, sizeof(k));                                                        \
}                                                                                     \
void ln_hmac_##NAME##_update(LnHmac##CTX *h, const void *p, size_t n)                  \
{ ln_##HASH##_update(&h->in, p, n); }                                                 \
void ln_hmac_##NAME##_final(LnHmac##CTX *h, u8 out[DS])                                \
{                                                                                     \
	u8 d[DS];                                                                     \
	ln_##HASH##_final(&h->in, d);                                                 \
	ln_##HASH##_update(&h->out, d, DS);                                           \
	ln_##HASH##_final(&h->out, out);                                              \
}

HMAC_IMPL(md5, Md5, 64, 16, md5)
HMAC_IMPL(sha256, Sha256, 64, 32, sha256)
HMAC_IMPL(sha512, Sha512, 128, 64, sha512)

void ln_hmac_md5(const void *key, size_t klen, const void *p, size_t n, u8 out[16])
{ LnHmacMd5 h; ln_hmac_md5_init(&h, key, klen); ln_hmac_md5_update(&h, p, n); ln_hmac_md5_final(&h, out); }
void ln_hmac_sha256(const void *key, size_t klen, const void *p, size_t n, u8 out[32])
{ LnHmacSha256 h; ln_hmac_sha256_init(&h, key, klen); ln_hmac_sha256_update(&h, p, n); ln_hmac_sha256_final(&h, out); }
