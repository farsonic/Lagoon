/*
 * Lagoon - the host directory backend (fs_posix.c) for the SMB server's
 * native tests and build/host/lnsrv.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_FS_POSIX_H
#define LN_FS_POSIX_H

#include "../core/ln_vfs.h"

extern const LnOps ln_posixfs_ops;
/* share root (a directory); readonly refuses every change with LN_EROFS */
int ln_posixfs_open(const char *root, int readonly, LnFs **out);

#endif
