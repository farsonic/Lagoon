/* Lagoon - minimal test helpers for tests/t_*.c (native only). */
#ifndef TESTUTIL_H
#define TESTUTIL_H
#include <stdio.h>
#include <string.h>
static int t_run, t_fail;
#define CHECK(c) do { t_run++; if (!(c)) { t_fail++; fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); } } while (0)
#define CHECK_STR(a, b) do { const char *_a = (a), *_b = (b); t_run++; if (strcmp(_a, _b)) { t_fail++; fprintf(stderr, "%s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, _a, _b); } } while (0)
#define CHECK_INT(a, b) do { long long _a = (long long)(a), _b = (long long)(b); t_run++; if (_a != _b) { t_fail++; fprintf(stderr, "%s:%d: %s = %lld, expected %lld\n", __FILE__, __LINE__, #a, _a, _b); } } while (0)
static inline void t_hex(const unsigned char *p, size_t n, char *out) { static const char h[] = "0123456789abcdef"; size_t i; for (i = 0; i < n; i++) { out[2*i] = h[p[i] >> 4]; out[2*i+1] = h[p[i] & 15]; } out[2*n] = 0; }
#define CHECK_HEX(p, n, s) do { char _h[257]; t_hex((p), (n), _h); CHECK_STR(_h, (s)); } while (0)
#define T_DONE(name) do { printf("%s: %d checks, %d failed\n", name, t_run, t_fail); return t_fail ? 1 : 0; } while (0)
/* skip a whole test program (e.g. server not available): exit code 77 */
#define T_SKIP(name, why) do { printf("%s: skipped (%s)\n", name, why); return 77; } while (0)
#endif
