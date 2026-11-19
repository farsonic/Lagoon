/* Lagoon - the SMB server (build/host/lnsrv) with real clients: runs
 * tests/servers/lagoon/e2e.sh (smbclient for every dialect and signing,
 * impacket when available). Exit 77 when smbclient is not installed.
 * SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

int main(void)
{
	int r = system("tests/servers/lagoon/e2e.sh");
	if (r == -1 || !WIFEXITED(r)) {
		printf("t_smbsrv_clients: could not run e2e.sh\n");
		return 1;
	}
	r = WEXITSTATUS(r);
	if (r == 77) {
		printf("t_smbsrv_clients: skipped (no smbclient)\n");
		return 77;
	}
	printf("t_smbsrv_clients: %s\n", r ? "FAILED" : "passed");
	return r ? 1 : 0;
}
