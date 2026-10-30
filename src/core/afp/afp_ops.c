/*
 * Lagoon - AFP (older Macs, Netatalk) backend: placeholder until the backend is written.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../ln_vfs.h"

static int stub_mount(const LnUrl *u, const LnCreds *c, LnFs **out)
{
	(void)u; (void)c; (void)out;
	return LN_ENOTSUP;
}

const LnOps ln_afp_ops = {
	"afp", "AFP (older Macs, Netatalk)", 548,
	stub_mount, 0
};
