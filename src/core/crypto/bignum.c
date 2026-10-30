/*
 * Lagoon - just enough big-number arithmetic for Diffie-Hellman: modular
 * exponentiation with Montgomery multiplication (CIOS form) and a fixed
 * 4-bit window, for 128..4096 bit odd moduli. Numbers are arrays of 32-bit
 * limbs, least significant first. The hot loop is bn_muladd(), which has
 * a 68020 assembler version (mulu.l 32x32->64) for vbcc.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../afp/afp_crypto.h"
#include "../ln_err.h"
#include "../ln_sys.h"

typedef u32 limb;

#if defined(__VBCC__) && defined(__M68020) && !defined(LN_BN_NOASM)
/* t[0..n-1] += a[0..n-1] * b, returns the carry limb. n >= 1.
 * d0-d1/a0-a1 are scratch for vbcc; d2-d5 are saved here. */
limb bn_muladd(__reg("a0") limb *t, __reg("a1") const limb *a, __reg("d0") limb b, __reg("d1") int n) =
	"\tmovem.l\td2-d5,-(a7)\n"
	"\tmove.l\td0,d5\n"          /* d5 = b */
	"\tmoveq\t#0,d4\n"           /* d4 = carry */
	"\tsubq.l\t#1,d1\n"
	"\tmoveq\t#0,d0\n"           /* d0 = 0 for addx */
	"\tmove.l\t(a1)+,d3\n"
	"\tmulu.l\td5,d2:d3\n"       /* d2:d3 = a[j] * b */
	"\tadd.l\td4,d3\n"
	"\taddx.l\td0,d2\n"
	"\tadd.l\td3,(a0)+\n"
	"\taddx.l\td0,d2\n"
	"\tmove.l\td2,d4\n"
	"\tdbra\td1,*-16\n"         /* back to the move.l (16 bytes of loop body) */
	"\tmove.l\td4,d0\n"
	"\tmovem.l\t(a7)+,d2-d5";
#else
static limb bn_muladd(limb *t, const limb *a, limb b, int n)
{
	u64 c = 0;
	int j;
	for (j = 0; j < n; j++) {
		c += (u64)a[j] * b + t[j];
		t[j] = (limb)c;
		c >>= 32;
	}
	return (limb)c;
}
#endif

typedef struct Mont {
	int   n;            /* limbs */
	limb *m;            /* modulus */
	limb  minv;         /* -m^-1 mod 2^32 */
	limb *t;            /* n + 2 scratch limbs */
} Mont;

/* -x^-1 mod 2^32 for odd x (Newton iteration) */
static limb neg_inv32(limb x)
{
	limb y = x;          /* correct to 3 bits for odd x */
	int i;
	for (i = 0; i < 5; i++)
		y *= 2 - x * y;
	return (limb)(0u - y);
}

static int geq(const limb *a, const limb *b, int n)
{
	int i;
	for (i = n - 1; i >= 0; i--)
		if (a[i] != b[i])
			return a[i] > b[i];
	return 1;
}

static limb sub_n(limb *r, const limb *a, const limb *b, int n)
{
	limb borrow = 0;
	int i;
	for (i = 0; i < n; i++) {
		limb x = a[i], y = b[i];
		limb d = x - y - borrow;
		borrow = (x < y) || (x == y && borrow);
		r[i] = d;
	}
	return borrow;
}

/* r = a * b * R^-1 mod m (r may alias a or b) */
static void mont_mul(Mont *M, limb *r, const limb *a, const limb *b)
{
	int n = M->n, i;
	limb *t = M->t, c, s;
	memset(t, 0, (size_t)(n + 2) * sizeof(limb));
	for (i = 0; i < n; i++) {
		limb q;
		c = bn_muladd(t, a, b[i], n);
		s = t[n] + c;
		t[n + 1] += s < c;
		t[n] = s;
		q = t[0] * M->minv;
		c = bn_muladd(t, M->m, q, n);
		s = t[n] + c;
		t[n + 1] += s < c;
		t[n] = s;
		/* t[0] is 0 now: shift down one limb */
		memmove(t, t + 1, (size_t)(n + 1) * sizeof(limb));
		t[n + 1] = 0;
	}
	if (t[n] || geq(t, M->m, n))
		sub_n(r, t, M->m, n);
	else
		memcpy(r, t, (size_t)n * sizeof(limb));
}

static void from_bytes(limb *r, int n, const u8 *p, size_t len)
{
	int i;
	memset(r, 0, (size_t)n * sizeof(limb));
	for (i = 0; len > 0 && i < 4 * n; i++, len--)
		r[i / 4] |= (limb)p[len - 1] << (8 * (i % 4));
}

static void to_bytes(u8 *p, size_t len, const limb *r, int n)
{
	size_t i;
	for (i = 0; i < len; i++)
		p[len - 1 - i] = (int)(i / 4) < n ? (u8)(r[i / 4] >> (8 * (i % 4))) : 0;
}

/* r = a mod m, by shift-and-subtract over the bits of a (a has an limbs).
 * Only used to bring the base below m and to compute R^2 mod m. */
static void mod_slow(limb *r, const limb *a, int an, const Mont *M, limb *tmp)
{
	int n = M->n, i, b;
	memset(r, 0, (size_t)n * sizeof(limb));
	for (i = an - 1; i >= 0; i--)
		for (b = 31; b >= 0; b--) {
			/* r = 2r + bit; keep the carried-out bit */
			limb top = r[n - 1] >> 31;
			int j;
			for (j = n - 1; j > 0; j--)
				r[j] = (r[j] << 1) | (r[j - 1] >> 31);
			r[0] = (r[0] << 1) | ((a[i] >> b) & 1);
			if (top || geq(r, M->m, n)) {
				sub_n(tmp, r, M->m, n);
				memcpy(r, tmp, (size_t)n * sizeof(limb));
			}
		}
}

int ln_bn_cmp(const u8 *a, size_t alen, const u8 *b, size_t blen)
{
	while (alen > blen) { if (*a) return 1; a++; alen--; }
	while (blen > alen) { if (*b) return -1; b++; blen--; }
	while (alen) {
		if (*a != *b)
			return *a > *b ? 1 : -1;
		a++; b++; alen--;
	}
	return 0;
}

int ln_bn_modexp(u8 *out, const u8 *base, size_t blen, const u8 *exp, size_t elen,
                 const u8 *mod, size_t mlen)
{
	Mont M;
	limb *mem, *x, *acc, *tab, *tmp, *one, *rr;
	int n, bn, i, r = LN_OK;
	size_t ei, olen = mlen;

	while (mlen && !*mod) { mod++; mlen--; }
	while (blen && !*base) { base++; blen--; }
	if (!mlen || !(mod[mlen - 1] & 1) || mlen * 8 > LN_BN_MAXBITS)
		return LN_EINVAL;
	n = (int)((mlen + 3) / 4);
	bn = (int)((blen + 3) / 4);
	if (bn < n)
		bn = n;
	/* m, t(n+2), x, acc, tmp, one, rr(2n+1), base(bn), 16-entry table */
	mem = ln_alloc((size_t)(n + (n + 2) + 5 * n + (2 * n + 1) + bn + 16 * n) * sizeof(limb));
	if (!mem)
		return LN_ENOMEM;
	M.n = n;
	M.m = mem;
	M.t = M.m + n;
	x = M.t + n + 2;
	acc = x + n;
	tmp = acc + n;
	one = tmp + n;
	rr = one + n;            /* 2n+1 limbs: R^2 = 2^(64n) */
	tab = rr + 2 * n + 1 + bn;
	from_bytes(M.m, n, mod, mlen);
	M.minv = neg_inv32(M.m[0]);

	/* R^2 mod m, then x = base * R mod m = mont(base mod m, R^2) */
	memset(rr, 0, (size_t)(2 * n + 1) * sizeof(limb));
	rr[2 * n] = 1;
	mod_slow(acc, rr, 2 * n + 1, &M, tmp);          /* acc = R^2 mod m */
	from_bytes(rr, bn, base, blen);                 /* reuse rr as base (bn <= 2n+1+bn) */
	mod_slow(x, rr, bn, &M, tmp);                   /* x = base mod m */
	memcpy(rr, acc, (size_t)n * sizeof(limb));      /* rr = R^2 mod m */
	mont_mul(&M, x, x, rr);                         /* x in Montgomery form */
	memset(one, 0, (size_t)n * sizeof(limb));
	one[0] = 1;
	mont_mul(&M, acc, one, rr);                     /* acc = R mod m = 1 in Montgomery form */

	/* table[k] = x^k (Montgomery form) */
	memcpy(tab, acc, (size_t)n * sizeof(limb));
	for (i = 1; i < 16; i++)
		mont_mul(&M, tab + i * n, tab + (i - 1) * n, x);

	/* left to right, 4 bits at a time */
	for (ei = 0; ei < elen; ei++) {
		int nib;
		for (nib = 0; nib < 2; nib++) {
			unsigned w = nib ? (exp[ei] & 15) : (exp[ei] >> 4);
			int k;
			for (k = 0; k < 4; k++)
				mont_mul(&M, acc, acc, acc);
			if (w)
				mont_mul(&M, acc, acc, tab + w * n);
		}
		if (ln_break()) { r = LN_EBREAK; break; }
	}
	/* out of Montgomery form */
	mont_mul(&M, acc, acc, one);
	to_bytes(out, olen, acc, n);
	ln_wipe(mem, (size_t)(n + (n + 2) + 5 * n + (2 * n + 1) + bn + 16 * n) * sizeof(limb));
	ln_free(mem);
	return r;
}
