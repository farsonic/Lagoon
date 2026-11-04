/*
 * Lagoon - lagoon-handler's entry point. The handler has no C start-up
 * code, so DOS jumps to the first byte of the first code hunk: this file
 * sorts first in the link (entry.o, handler.o, hcore.o) and holds nothing
 * but this function (vbcc places a file's string constants in front of its
 * first function, so the real work starts in handler.c).
 * SPDX-License-Identifier: GPL-2.0-only
 */
long handler_main(void);

long entry(void)
{
	return handler_main();
}
