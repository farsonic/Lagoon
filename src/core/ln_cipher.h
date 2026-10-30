/*
 * Lagoon - block/stream ciphers and AEAD modes (src/core/crypto):
 * AES-128/256 (encryption direction only: every mode we need runs AES
 * forwards), AES-CMAC (RFC 4493), AES-CCM (SP 800-38C / RFC 3610),
 * AES-GCM and GMAC (SP 800-38D), RC4 (NTLM key exchange / NTLMSSP MAC).
 *
 * Memory: AES uses four 1 KB T-tables (shared, const); an LnAes key
 * schedule is 244 bytes; an LnGcm adds a 4 KB GHASH table.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_CIPHER_H
#define LN_CIPHER_H

#include "ln_types.h"

typedef struct LnAes {
	u32 rk[60];
	int nr;                  /* rounds: 10 (AES-128) or 14 (AES-256) */
} LnAes;

/* keylen 16 or 32 bytes; returns 0, or -1 for a bad length */
int  ln_aes_setkey(LnAes *a, const u8 *key, int keylen);
void ln_aes_encrypt(const LnAes *a, const u8 in[16], u8 out[16]);

/* AES-CMAC over one contiguous message */
void ln_aes_cmac(const LnAes *a, const void *msg, size_t n, u8 mac[16]);

/* AES-CCM, in place. nonce 7..13 bytes, tag 4..16 bytes (even).
 * decrypt returns 0 if the tag matches (data decrypted), -1 if not
 * (data is then wiped). */
void ln_aes_ccm_encrypt(const LnAes *a, const u8 *nonce, int nlen, const u8 *aad, size_t alen,
                        u8 *data, size_t n, u8 *tag, int tlen);
int  ln_aes_ccm_decrypt(const LnAes *a, const u8 *nonce, int nlen, const u8 *aad, size_t alen,
                        u8 *data, size_t n, const u8 *tag, int tlen);

/* AES-GCM with a 96-bit IV and 128-bit tag, in place */
typedef struct LnGcm {
	LnAes aes;
	u32 m[256][4];           /* GHASH 8-bit multiplication table for H (4 KB) */
} LnGcm;
int  ln_gcm_setkey(LnGcm *g, const u8 *key, int keylen);
void ln_gcm_encrypt(const LnGcm *g, const u8 iv[12], const u8 *aad, size_t alen,
                    u8 *data, size_t n, u8 tag[16]);
int  ln_gcm_decrypt(const LnGcm *g, const u8 iv[12], const u8 *aad, size_t alen,
                    u8 *data, size_t n, const u8 tag[16]);
/* GMAC = GCM with everything as additional data */
void ln_gmac(const LnGcm *g, const u8 iv[12], const void *msg, size_t n, u8 tag[16]);

/* RC4 */
typedef struct LnRc4 {
	u8 s[256];
	u8 i, j;
} LnRc4;
void ln_rc4_init(LnRc4 *r, const u8 *key, size_t klen);
void ln_rc4_crypt(LnRc4 *r, const u8 *in, u8 *out, size_t n);   /* in == out is fine */

#endif
