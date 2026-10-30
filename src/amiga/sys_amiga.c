/*
 * Lagoon - ln_sys.h on AmigaOS 3.x (exec, dos, locale). Usable from the
 * handler (no C library start-up code: nothing here needs it).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <libraries/locale.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/locale.h>
#include <stdarg.h>
#include "../core/ln_sys.h"
#include "../core/ln_hash.h"

int ln_log_level = 0;
/* where ln_log writes: a file name (opened per message, appended) or NULL
 * to write to Output() when the task has one */
const char *ln_log_file = NULL;

void *ln_alloc(size_t n) { return AllocVec(n ? n : 1, MEMF_ANY | MEMF_CLEAR); }
void ln_free(void *p) { if (p) FreeVec(p); }
void *ln_realloc(void *p, size_t old_n, size_t new_n)
{
	void *q = ln_alloc(new_n);
	if (q && p)
		CopyMem(p, q, old_n < new_n ? old_n : new_n);
	if (q)
		ln_free(p);
	return q;
}

int ln_tz_minutes(void)
{
	struct Library *LocaleBase = OpenLibrary("locale.library", 38);
	int tz = 0;
	if (LocaleBase) {
		struct Locale *l = OpenLocale(NULL);
		if (l) {
			tz = -(int)l->loc_GMTOffset;    /* minutes west -> east */
			CloseLocale(l);
		}
		CloseLibrary(LocaleBase);
	}
	return tz;
}

/* the Amiga clock runs in local time from 1978-01-01 */
u32 ln_time_unix(void)
{
	struct DateStamp ds;
	static int tz = 0x7fff;
	if (tz == 0x7fff)
		tz = ln_tz_minutes();
	DateStamp(&ds);
	return (u32)(252460800UL + (u32)ds.ds_Days * 86400UL + (u32)ds.ds_Minute * 60UL + (u32)ds.ds_Tick / 50UL)
	       - (u32)(tz * 60);
}

u32 ln_ms(void)
{
	struct DateStamp ds;
	DateStamp(&ds);
	return (u32)ds.ds_Days * 86400000UL + (u32)ds.ds_Minute * 60000UL + (u32)ds.ds_Tick * 20UL;
}

void ln_random(void *buf, size_t n)
{
	static u8 pool[32];
	static u32 counter;
	u8 *o = buf;
	while (n) {
		LnSha256 c;
		struct DateStamp ds;
		u8 d[32];
		u32 x[6];
		size_t k;
		DateStamp(&ds);
		x[0] = (u32)ds.ds_Days; x[1] = (u32)ds.ds_Minute; x[2] = (u32)ds.ds_Tick;
		x[3] = (u32)*(volatile u16 *)0xDFF006;   /* VHPOSR: beam position */ x[4] = (u32)(size_t)FindTask(NULL); x[5] = ++counter;
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

int ln_break(void)
{
	return (SetSignal(0, SIGBREAKF_CTRL_C) & SIGBREAKF_CTRL_C) != 0;
}

int ln_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);

void ln_log(int level, const char *fmt, ...)
{
	char b[512];
	va_list ap;
	BPTR fh;
	size_t l;
	va_start(ap, fmt);
	ln_vsnprintf(b, sizeof(b) - 1, fmt, ap);
	va_end(ap);
	l = strlen(b);
	b[l++] = '\n';
	(void)level;
	if (ln_log_file) {
		fh = Open((STRPTR)ln_log_file, MODE_READWRITE);
		if (fh) {
			Seek(fh, 0, OFFSET_END);
			Write(fh, b, (LONG)l);
			Close(fh);
		}
	} else if (((struct Process *)FindTask(NULL))->pr_Task.tc_Node.ln_Type == NT_PROCESS && (fh = Output()) != 0)
		Write(fh, b, (LONG)l);
}

const char *ln_hostname(void)
{
	static char h[64];
	if (!h[0]) {
		/* no "insert volume ENV:" requester when ENV: is not assigned yet */
		struct Process *me = (struct Process *)FindTask(NULL);
		APTR win = me->pr_WindowPtr;
		LONG r;
		char *dot;
		me->pr_WindowPtr = (APTR)-1;
		r = GetVar((STRPTR)"HOSTNAME", (STRPTR)h, sizeof(h), GVF_GLOBAL_ONLY);
		me->pr_WindowPtr = win;
		if (r <= 0)
			strcpy(h, "Amiga");
		if ((dot = strchr(h, '.')) != NULL)
			*dot = 0;
	}
	return h;
}
