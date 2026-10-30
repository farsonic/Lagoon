/*
 * Lagoon - character sets. Remote names are Unicode (UTF-8 inside Lagoon;
 * UTF-16LE on the SMB wire, UTF-8 decomposed on AFP); Amiga names are 8-bit
 * in the system code page (ISO-8859-1 by default, others via tables later).
 *
 * Amiga file names cannot contain ':' or '/' and are limited to 107 bytes
 * (FileInfoBlock) - see ln_name_to_amiga for the escaping rules.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_CHARSET_H
#define LN_CHARSET_H

#include "ln_types.h"

/* UTF-8 <-> UTF-16LE; return output length in bytes, or -1 on overflow.
 * Invalid input is replaced with U+FFFD. */
int ln_utf8_to_utf16le(const char *in, size_t inlen, u8 *out, size_t outmax);
int ln_utf16le_to_utf8(const u8 *in, size_t inbytes, char *out, size_t outmax);

/* decode one code point; returns bytes used (>=1), cp set (U+FFFD if bad) */
int ln_utf8_decode(const char *s, size_t n, u32 *cp);
int ln_utf8_encode(u32 cp, char *out);       /* 1..4 bytes */

/* Unicode NFC <-> NFD for Latin letters with diacritics (macOS/AFP names
 * are decomposed). Output is UTF-8; returns length or -1. */
int ln_utf8_nfc(const char *in, char *out, size_t outmax);
int ln_utf8_nfd(const char *in, char *out, size_t outmax);

/* Remote (UTF-8) name -> Amiga name in ISO-8859-1. Characters outside
 * Latin-1, and ':' / '/', become "%XX"-style escapes of their UTF-8 bytes
 * ('%' itself becomes "%25"), so the mapping is reversible. Returns length
 * or -1 if it does not fit. */
int ln_name_to_amiga(const char *utf8, char *out, size_t outmax);
/* Amiga name -> remote UTF-8 name (undoes the escapes). */
int ln_name_from_amiga(const char *amiga, char *out, size_t outmax);

/* case-insensitive compare of Latin-1 Amiga names (like DOS's) */
int ln_amiga_stricmp(const char *a, const char *b);

#endif
