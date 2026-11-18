/*
 * Lagoon - system services on the classic Mac OS (src/core/ln_sys.h), for the Mac build
 * (Makefile.mac). The program runs on Riptide's Mac app kit (riptide src/mac/app: crt0, the
 * Toolbox glue) and its MUI (riptide src/mac/mui), whose mm_alloc and mm_log are used here, so
 * memory comes from the application heap and the log goes where RiptidePrefs' does (the kernel's
 * log on Aurora68, docs/MAC-GUI.md in riptide).
 *
 * The Mac keeps local time in seconds since 1904 (low memory Time, $20C); the time zone comes
 * from the Map control panel's MachineLocation (ReadLocation), as the Amiga's comes from
 * locale.library. Ctrl-C is Command-period. The host name is the Macintosh Name of the Sharing
 * Setup control panel, as Riptide's own host name is (riptide src/mac/main_mac.c).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdarg.h>
#include "../core/ln_sys.h"
#include "../core/ln_hash.h"

/* riptide src/mac/mui/mm_os.c and src/mac/app (C linkage, GCC's convention) */
void *mm_alloc(unsigned long n);                 /* cleared; NULL when out of memory */
void  mm_free(void *p);
void  mm_log(const char *fmt, ...);
unsigned long long mac_us(void);                 /* Microseconds */
void **GetResource(long type, int id);           /* the Toolbox glue */

#define LM_TICKS  (*(volatile unsigned long *)0x16A)
#define LM_TIME   (*(volatile unsigned long *)0x20C)   /* seconds since 1904-01-01, local */
#define LM_KEYMAP ((volatile unsigned char *)0x174)

int ln_log_level = 0;

/* src/mac/mac_libc.h */
char *strstr(const char *hay, const char *needle)
{
	size_t n = strlen(needle);
	for (; *hay; hay++)
		if (!strncmp(hay, needle, n))
			return (char *)hay;
	return n ? NULL : (char *)hay;
}

void *ln_alloc(size_t n) { return mm_alloc(n ? (unsigned long)n : 1); }
void ln_free(void *p) { if (p) mm_free(p); }
void *ln_realloc(void *p, size_t old_n, size_t new_n)
{
	void *q = ln_alloc(new_n);
	if (q && p)
		memcpy(q, p, old_n < new_n ? old_n : new_n);
	if (q)
		ln_free(p);
	return q;
}

/* the Map control panel's offset from GMT (MachineLocation.gmtFlags.gmtDelta: seconds, 24 bits
 * signed), read with _ReadLocation ($A0E4: A0 = the record); 0 when the Mac has none */
static int read_location_minutes(void)
{
	long loc[3] = { 0, 0, 0 };                   /* latitude, longitude, gmtFlags */
	__asm__ volatile("move.l %0,%%a0\n\t.short 0xA0E4" : : "g"(loc) : "a0", "a1", "d0", "d1", "d2", "memory");
	long d = loc[2] & 0x00FFFFFFL;
	if (d & 0x00800000L)
		d |= (long)0xFF000000L;
	return (int)(d / 60);
}

int ln_tz_minutes(void)
{
	static int tz = 0x7fff;
	if (tz == 0x7fff)
		tz = read_location_minutes();
	return tz;
}

/* 1904 to 1970: 66 years with 17 leap days */
u32 ln_time_unix(void)
{
	return (u32)(LM_TIME - 2082844800UL) - (u32)(ln_tz_minutes() * 60);
}

u32 ln_ms(void)
{
	return (u32)(mac_us() / 1000u);
}

void ln_random(void *buf, size_t n)
{
	static u8 pool[32];
	static u32 counter;
	u8 *o = buf;
	while (n) {
		LnSha256 c;
		u8 d[32];
		u32 x[6];
		unsigned long long us = mac_us();
		size_t k;
		x[0] = (u32)LM_TIME; x[1] = (u32)LM_TICKS; x[2] = (u32)us; x[3] = (u32)(us >> 32);
		x[4] = (u32)(size_t)&x; x[5] = ++counter;
		ln_sha256_init(&c);
		ln_sha256_update(&c, pool, sizeof(pool));
		ln_sha256_update(&c, x, sizeof(x));
		ln_sha256_update(&c, &o, sizeof(o));
		ln_sha256_final(&c, d);
		memcpy(pool, d, sizeof(pool));
		pool[0] ^= 0x5a;               /* output and next state differ */
		k = n < 16 ? n : 16;
		memcpy(o, d + 16, k);
		o += k; n -= k;
	}
}

/* Command-period held down (KeyMap: Command is key $37, the period $2F) */
int ln_break(void)
{
	return (LM_KEYMAP[0x37 >> 3] & (1 << (0x37 & 7))) && (LM_KEYMAP[0x2F >> 3] & (1 << (0x2F & 7)));
}

int ln_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);

void ln_log(int level, const char *fmt, ...)
{
	char b[512];
	va_list ap;
	va_start(ap, fmt);
	ln_vsnprintf(b, sizeof(b), fmt, ap);
	va_end(ap);
	(void)level;
	mm_log("%s", b);
}

/* the Macintosh Name of Sharing Setup ('STR ' -16413 in the System file); "Macintosh" without */
const char *ln_hostname(void)
{
	static char h[64];
	if (!h[0]) {
		void **r = GetResource(0x53545220L /* 'STR ' */, -16413);
		size_t n = 0;
		if (r && *r) {
			const unsigned char *p = *r;
			n = p[0] < sizeof(h) - 1 ? p[0] : sizeof(h) - 1;
			memcpy(h, p + 1, n);
		}
		if (!n)
			memcpy(h, "Macintosh", n = 9);
		h[n] = 0;
	}
	return h;
}
