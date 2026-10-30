/*
 * Lagoon - SMB 2/3 (Windows, macOS, Samba, NAS) backend: placeholder until the backend is written.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../ln_vfs.h"

static int stub_mount(const LnUrl *u, const LnCreds *c, LnFs **out)
{
	(void)u; (void)c; (void)out;
	return LN_ENOTSUP;
}

const LnOps ln_smb_ops = {
	"smb", "SMB 2/3 (Windows, macOS, Samba, NAS)", 445,
	stub_mount, 0
};
