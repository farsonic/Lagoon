/*
 * Lagoon - the crypto the AFP login methods need: a small big-number
 * modular exponentiation (Diffie-Hellman for DHX2 / DHCAST128) and the
 * CAST-128 block cipher (RFC 2144) in CBC mode.
 * Implemented in src/core/crypto/bignum.c and src/core/crypto/cast128.c.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef AFP_CRYPTO_H
#define AFP_CRYPTO_H

#include "../ln_types.h"

/* out = base^exp mod mod. All numbers are big-endian byte strings; out
 * gets exactly mlen bytes (zero padded on the left). The modulus must be
 * odd (DH primes are) and at most LN_BN_MAXBITS bits. Returns LN_OK,
 * LN_EINVAL (even/zero/too big modulus) or LN_ENOMEM. Heap only, the
 * stack use is small. */
#define LN_BN_MAXBITS 4096
int ln_bn_modexp(u8 *out, const u8 *base, size_t blen, const u8 *exp, size_t elen,
                 const u8 *mod, size_t mlen);

/* compare two big-endian numbers of possibly different lengths: <0, 0, >0 */
int ln_bn_cmp(const u8 *a, size_t alen, const u8 *b, size_t blen);

/* CAST-128 (CAST5) with 40..128 bit keys */
typedef struct LnCast128 {
	u32 km[16];
	u8  kr[16];
	int rounds;              /* 12 for keys <= 80 bits, else 16 */
} LnCast128;

void ln_cast128_setkey(LnCast128 *c, const u8 *key, size_t keylen);
void ln_cast128_encrypt(const LnCast128 *c, const u8 in[8], u8 out[8]);
void ln_cast128_decrypt(const LnCast128 *c, const u8 in[8], u8 out[8]);
/* CBC over len bytes (a multiple of 8) in place; iv is not updated */
void ln_cast128_cbc_encrypt(const LnCast128 *c, const u8 iv[8], u8 *buf, size_t len);
void ln_cast128_cbc_decrypt(const LnCast128 *c, const u8 iv[8], u8 *buf, size_t len);

#endif
