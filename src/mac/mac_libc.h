/*
 * Lagoon on the classic Mac OS: the C library calls the core uses that riptide's small libc
 * (riptide src/amiga/libc.c, src/amiga/include) does not have; included in every Lagoon file of
 * the Mac build (Makefile.mac), defined in src/mac/sys_mac.c.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_MAC_LIBC_H
#define LN_MAC_LIBC_H
char *strstr(const char *hay, const char *needle);
#endif
