/*
 * Lagoon - Amiga folders as LnOps backends (fs_dos.c), for the SMB server.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_FS_DOS_H
#define LN_FS_DOS_H

#include "../core/ln_vfs.h"

extern const LnOps ln_dosfs_ops;
/* root: an Amiga directory ("Work:", "DH0:Projects"); LN_ENOSHARE if missing */
int ln_dosfs_open(const char *root, int readonly, LnFs **out);

#endif
