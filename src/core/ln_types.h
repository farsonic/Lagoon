/*
 * Lagoon - basic types, byte packing and small helpers shared by everything.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * The core (src/core) is portable C99 that builds with gcc on Linux (native
 * tests) and with vbcc for AmigaOS 3.x (68020+, no FPU). Rules: no anonymous
 * structs/unions, no VLAs, no floating point, no OS calls: everything that
 * touches the system goes through ln_sys.h / ln_net.h, implemented in
 * src/host (POSIX) and src/amiga (exec/dos/bsdsocket).
 */
#ifndef LN_TYPES_H
#define LN_TYPES_H

#include <stddef.h>
#include <string.h>

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed char        s8;
typedef short              s16;
typedef int                s32;
typedef long long          s64;

#define LN_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define LN_MIN(a, b) ((a) < (b) ? (a) : (b))
#define LN_MAX(a, b) ((a) > (b) ? (a) : (b))
#define LN_UNUSED(x) ((void)(x))

#if defined(__GNUC__)
#define LN_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#define LN_PRINTF(a, b)
#endif

/* ---- little-endian (SMB, NTLM) and big-endian (AFP/DSI, NFS/XDR, DNS) ---- */
static inline u16 ln_le16(const u8 *p) { return (u16)(p[0] | (p[1] << 8)); }
static inline u32 ln_le32(const u8 *p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }
static inline u64 ln_le64(const u8 *p) { return (u64)ln_le32(p) | ((u64)ln_le32(p + 4) << 32); }
static inline u16 ln_be16(const u8 *p) { return (u16)((p[0] << 8) | p[1]); }
static inline u32 ln_be32(const u8 *p) { return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3]; }
static inline u64 ln_be64(const u8 *p) { return ((u64)ln_be32(p) << 32) | (u64)ln_be32(p + 4); }
static inline void ln_put_le16(u8 *p, u16 v) { p[0] = (u8)v; p[1] = (u8)(v >> 8); }
static inline void ln_put_le32(u8 *p, u32 v) { p[0] = (u8)v; p[1] = (u8)(v >> 8); p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24); }
static inline void ln_put_le64(u8 *p, u64 v) { ln_put_le32(p, (u32)v); ln_put_le32(p + 4, (u32)(v >> 32)); }
static inline void ln_put_be16(u8 *p, u16 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }
static inline void ln_put_be32(u8 *p, u32 v) { p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v; }
static inline void ln_put_be64(u8 *p, u64 v) { ln_put_be32(p, (u32)(v >> 32)); ln_put_be32(p + 4, (u32)v); }

/* bounded string copy that always terminates (dst size n > 0) */
size_t ln_strlcpy(char *dst, const char *src, size_t n);
size_t ln_strlcat(char *dst, const char *src, size_t n);
int    ln_strcasecmp(const char *a, const char *b);
int    ln_strncasecmp(const char *a, const char *b, size_t n);
char  *ln_strdup(const char *s);            /* ln_alloc'd */
int    ln_snprintf(char *buf, size_t n, const char *fmt, ...) LN_PRINTF(3, 4);
/* constant time compare (MACs) */
int    ln_memeq_ct(const void *a, const void *b, size_t n);
/* wipe secrets (not optimized away) */
void   ln_wipe(void *p, size_t n);

#endif
