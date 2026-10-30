/*
 * Lagoon - RC4, only for NTLM key exchange and the NTLMSSP MAC
 * (MS-NLMP requires it; never used for bulk data).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../ln_cipher.h"

void ln_rc4_init(LnRc4 *r, const u8 *key, size_t klen)
{
	int i;
	u8 j = 0, t;
	for (i = 0; i < 256; i++)
		r->s[i] = (u8)i;
	for (i = 0; i < 256; i++) {
		j = (u8)(j + r->s[i] + key[i % klen]);
		t = r->s[i]; r->s[i] = r->s[j]; r->s[j] = t;
	}
	r->i = r->j = 0;
}

void ln_rc4_crypt(LnRc4 *r, const u8 *in, u8 *out, size_t n)
{
	u8 i = r->i, j = r->j, t;
	size_t k;
	for (k = 0; k < n; k++) {
		i++;
		j = (u8)(j + r->s[i]);
		t = r->s[i]; r->s[i] = r->s[j]; r->s[j] = t;
		out[k] = in[k] ^ r->s[(u8)(r->s[i] + r->s[j])];
	}
	r->i = i; r->j = j;
}
