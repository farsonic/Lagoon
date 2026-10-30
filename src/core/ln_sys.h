/*
 * Lagoon - system services the core needs, implemented per platform:
 * src/host/sys_posix.c (Linux, tests) and src/amiga/sys_amiga.c (exec/dos).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_SYS_H
#define LN_SYS_H

#include "ln_types.h"

/* memory: ln_alloc returns zeroed memory or NULL */
void *ln_alloc(size_t n);
void *ln_realloc(void *p, size_t old_n, size_t new_n);
void  ln_free(void *p);

/* time */
u32  ln_time_unix(void);            /* seconds since 1970-01-01 UTC */
u32  ln_ms(void);                   /* monotonic milliseconds (wraps) */
/* the local time zone offset from UTC in minutes (east positive), used to
 * show server times in local time on the Amiga (which keeps local time) */
int  ln_tz_minutes(void);

/* random bytes for client challenges, nonces, DH keys (best effort on the
 * Amiga: timer EClock + VBlank + addresses, mixed with SHA-256) */
void ln_random(void *buf, size_t n);

/* has the user asked us to stop? (Ctrl-C on the Amiga; never on host) */
int  ln_break(void);

/* logging: level 0 = errors, 1 = info, 2 = debug, 3 = packet dumps */
extern int ln_log_level;
void ln_log(int level, const char *fmt, ...) LN_PRINTF(2, 3);
#define LN_LOG(l, ...) do { if ((l) <= ln_log_level) ln_log((l), __VA_ARGS__); } while (0)

/* local host name (for NTLM workstation, AFP client name); "Amiga" if unknown */
const char *ln_hostname(void);

#endif
