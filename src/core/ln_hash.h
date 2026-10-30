/*
 * Lagoon - hashes and MACs (MD4, MD5, SHA-256, SHA-512, HMAC).
 * Ciphers live in ln_cipher.h (AES, CMAC, CCM, GCM, RC4; DES/CAST/bignum for AFP).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_HASH_H
#define LN_HASH_H

#include "ln_types.h"

typedef struct { u32 s[4]; u64 len; u8 buf[64]; } LnMd4;
typedef struct { u32 s[4]; u64 len; u8 buf[64]; } LnMd5;
typedef struct { u32 s[8]; u64 len; u8 buf[64]; } LnSha256;
typedef struct { u64 s[8]; u64 len; u8 buf[128]; } LnSha512;

void ln_md4_init(LnMd4 *c);   void ln_md4_update(LnMd4 *c, const void *p, size_t n);   void ln_md4_final(LnMd4 *c, u8 out[16]);
void ln_md5_init(LnMd5 *c);   void ln_md5_update(LnMd5 *c, const void *p, size_t n);   void ln_md5_final(LnMd5 *c, u8 out[16]);
void ln_sha256_init(LnSha256 *c); void ln_sha256_update(LnSha256 *c, const void *p, size_t n); void ln_sha256_final(LnSha256 *c, u8 out[32]);
void ln_sha512_init(LnSha512 *c); void ln_sha512_update(LnSha512 *c, const void *p, size_t n); void ln_sha512_final(LnSha512 *c, u8 out[64]);

void ln_md4(const void *p, size_t n, u8 out[16]);
void ln_md5(const void *p, size_t n, u8 out[16]);
void ln_sha256(const void *p, size_t n, u8 out[32]);
void ln_sha512(const void *p, size_t n, u8 out[64]);

/* HMAC with MD5 / SHA-256 / SHA-512 (incremental for signing big packets) */
typedef struct { LnMd5 in, out; } LnHmacMd5;
typedef struct { LnSha256 in, out; } LnHmacSha256;
typedef struct { LnSha512 in, out; } LnHmacSha512;
void ln_hmac_md5_init(LnHmacMd5 *h, const void *key, size_t klen);
void ln_hmac_md5_update(LnHmacMd5 *h, const void *p, size_t n);
void ln_hmac_md5_final(LnHmacMd5 *h, u8 out[16]);
void ln_hmac_sha256_init(LnHmacSha256 *h, const void *key, size_t klen);
void ln_hmac_sha256_update(LnHmacSha256 *h, const void *p, size_t n);
void ln_hmac_sha256_final(LnHmacSha256 *h, u8 out[32]);
void ln_hmac_sha512_init(LnHmacSha512 *h, const void *key, size_t klen);
void ln_hmac_sha512_update(LnHmacSha512 *h, const void *p, size_t n);
void ln_hmac_sha512_final(LnHmacSha512 *h, u8 out[64]);
void ln_hmac_md5(const void *key, size_t klen, const void *p, size_t n, u8 out[16]);
void ln_hmac_sha256(const void *key, size_t klen, const void *p, size_t n, u8 out[32]);

#endif
