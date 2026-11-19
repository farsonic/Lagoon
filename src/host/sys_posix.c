/*
 * Lagoon - ln_sys.h on Linux/POSIX (native tests and the lncli tool).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include "../core/ln_sys.h"

int ln_log_level = 0;

/* memory, counted: the tests can see how much the core holds (the Mac bridge's server lives in
 * a fixed pool, src/mac/bridge/lm_pool.c) and give it a limit to run into. Each block carries
 * its size in front of it. */
size_t ln_host_mem_used, ln_host_mem_peak, ln_host_mem_limit;
#define MEMHDR 16

void *ln_alloc(size_t n)
{
	u8 *p;
	if (!n)
		n = 1;
	if (ln_host_mem_limit && ln_host_mem_used + n > ln_host_mem_limit)
		return NULL;
	p = calloc(1, n + MEMHDR);
	if (!p)
		return NULL;
	*(size_t *)p = n;
	ln_host_mem_used += n;
	if (ln_host_mem_used > ln_host_mem_peak)
		ln_host_mem_peak = ln_host_mem_used;
	return p + MEMHDR;
}
void ln_free(void *p)
{
	if (!p)
		return;
	ln_host_mem_used -= *(size_t *)((u8 *)p - MEMHDR);
	free((u8 *)p - MEMHDR);
}
void *ln_realloc(void *p, size_t old_n, size_t new_n)
{
	u8 *q = ln_alloc(new_n);
	if (q && p)
		memcpy(q, p, old_n < new_n ? old_n : new_n);
	if (q)
		ln_free(p);
	return q;
}

u32 ln_time_unix(void) { return (u32)time(NULL); }

u32 ln_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (u32)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int ln_tz_minutes(void)
{
	time_t t = time(NULL);
	struct tm lt;
	localtime_r(&t, &lt);
	return (int)(lt.tm_gmtoff / 60);
}

void ln_random(void *buf, size_t n)
{
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0 || read(fd, buf, n) != (ssize_t)n) {
		size_t i;
		for (i = 0; i < n; i++)
			((u8 *)buf)[i] = (u8)rand();
	}
	if (fd >= 0)
		close(fd);
}

int ln_break(void) { return 0; }

int ln_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);

void ln_log(int level, const char *fmt, ...)
{
	char b[1024];
	va_list ap;
	va_start(ap, fmt);
	ln_vsnprintf(b, sizeof(b), fmt, ap);
	va_end(ap);
	fprintf(stderr, "lagoon[%d]: %s\n", level, b);
}

const char *ln_hostname(void)
{
	static char h[64];
	if (!h[0] && gethostname(h, sizeof(h) - 1) != 0)
		strcpy(h, "Amiga");
	return h;
}
