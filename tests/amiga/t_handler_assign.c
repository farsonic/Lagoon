/*
 * Lagoon - tiny Assign for the emulator tests (the AROS ROM has no Assign
 * command): t_handler_assign NAME PATH [ADD]
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <string.h>

int main(int argc, char **argv)
{
	BPTR l;
	char name[64];
	size_t n;
	if (argc < 3) {
		PutStr((STRPTR)"usage: t_handler_assign NAME PATH [ADD]\n");
		return 20;
	}
	strncpy(name, argv[1], sizeof(name) - 1);
	name[sizeof(name) - 1] = 0;
	n = strlen(name);
	if (n && name[n - 1] == ':')
		name[n - 1] = 0;
	l = Lock((STRPTR)argv[2], SHARED_LOCK);
	if (!l) {
		PrintFault(IoErr(), (STRPTR)argv[2]);
		return 10;
	}
	if (argc > 3 && AssignAdd((STRPTR)name, l))
		return 0;
	if (!AssignLock((STRPTR)name, l)) {
		PrintFault(IoErr(), (STRPTR)name);
		UnLock(l);
		return 10;
	}
	return 0;
}
