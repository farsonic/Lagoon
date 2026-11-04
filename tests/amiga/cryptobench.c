/*
 * Lagoon - crypto throughput benchmark (AES-ECB, GHASH/GMAC, GCM, CMAC,
 * CCM, SHA-256, HMAC-SHA256) over a 64 KB buffer, the SMB message size on
 * the Amiga. Prints KB/s and a short digest of each result so 68k and host
 * builds can be compared for correctness.
 *
 *   cryptobench [ROUNDS] [MINMS] [TEST]   (defaults 1 round, 1000 ms, all tests)
 *
 * Build: make build/amiga/cryptobench (vbcc) or build/host/cryptobench.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ln_cipher.h"
#include "ln_hash.h"
#include "ln_sys.h"

#define BUFSZ 65536

static u8 *buf;
static LnAes aes;
static LnGcm *gcm;
static u8 out[32];
static u32 minms = 1000;
static const char *only;

static void t_ecb(void)
{
	u8 *p;
	for (p = buf; p < buf + BUFSZ; p += 16)
		ln_aes_encrypt(&aes, p, p);
	memcpy(out, buf + BUFSZ - 16, 16);
}
static void t_gmac(void) { ln_gmac(gcm, buf, buf, BUFSZ, out); }
static void t_gcm(void) { ln_gcm_encrypt(gcm, buf, buf, 32, buf + 32, BUFSZ - 32, out); }
static void t_cmac(void) { ln_aes_cmac(&aes, buf, BUFSZ, out); }
static void t_ccm(void) { ln_aes_ccm_encrypt(&aes, buf, 11, buf, 32, buf + 32, BUFSZ - 32, out, 16); }
static void t_sha(void) { ln_sha256(buf, BUFSZ, out); }
static void t_hmac(void) { ln_hmac_sha256(out, 16, buf, BUFSZ, out); }
static void t_aeskey(void)
{
	int i;
	for (i = 0; i < 64; i++)
		ln_aes_setkey(&aes, buf + 16 * i, 16);
	for (i = 0; i < 4; i++)
		ln_put_be32(out + 4 * i, aes.rk[40 + i]);
}

static void run(const char *name, void (*f)(void), int rounds)
{
	u32 t0, ms, n = 0;
	u8 dig[8];
	unsigned long kbs;
	int i;
	if (only && strcmp(only, name))
		return;
	for (i = 0; i < BUFSZ; i++)
		buf[i] = (u8)(i * 7 + 1);
	memset(out, 0, sizeof(out));
	t0 = ln_ms();
	do {
		f();
		if (!n++)
			memcpy(dig, out, 8);
		ms = ln_ms() - t0;
	} while ((int)n < rounds || ms < minms);
	kbs = ms ? (unsigned long)n * 64000UL / ms : 0;  /* 64 KB * 1000 / ms / 1024 ~ n*64000/ms */
	printf("%-8s %4lu x 64 KB %6lu ms %6lu KB/s  %02x%02x%02x%02x%02x%02x%02x%02x\n", name, (unsigned long)n,
	       (unsigned long)ms, kbs, dig[0], dig[1], dig[2], dig[3], dig[4], dig[5], dig[6], dig[7]);
}

int main(int argc, char **argv)
{
	static const u8 key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	                            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	int rounds = argc > 1 ? atoi(argv[1]) : 1;
	if (argc > 2)
		minms = (u32)atoi(argv[2]);
	if (argc > 3)
		only = argv[3];
	buf = malloc(BUFSZ);
	gcm = malloc(sizeof(LnGcm));
	if (!buf || !gcm)
		return 20;
	ln_aes_setkey(&aes, key, 16);
	ln_gcm_setkey(gcm, key, 16);
	run("aes-ecb", t_ecb, rounds);
	run("gmac", t_gmac, rounds);
	run("gcm", t_gcm, rounds);
	run("cmac", t_cmac, rounds);
	run("ccm", t_ccm, rounds);
	run("sha256", t_sha, rounds);
	run("hmac256", t_hmac, rounds);
	run("aeskey", t_aeskey, rounds);   /* 64 key setups per "64 KB" */
	free(gcm);
	free(buf);
	return 0;
}
