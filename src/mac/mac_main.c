/*
 * Lagoon on the classic Mac OS: the application's start. Riptide's Mac app kit (riptide
 * src/mac/app: crt0 has initialised the Toolbox) and its MUI for the Mac (src/mac/mui) are set
 * up as RiptidePrefs sets them up (riptide src/mac/prefs/rp_main_mac.c), then the shared front
 * end runs (src/mui/lm_gui.c). The network is Riptide's (src/mac/net_mac.c): while a call waits,
 * lm_yield lets the Mac go on and lm_break answers Command-period.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../core/ln_sys.h"
#include "../mui/lm_gui.h"
#include "bridge/lm_bridge.h"

void mm_gfx_lib_init(void);
void mm_screen_init(void *qd_thePort_addr);
void mm_paths_init(void);
void mm_classes_init(void);
void mm_gfx_init(int compact);
void mm_log(const char *fmt, ...);
int  WaitNextEvent(int mask, void *event, long sleep, void *rgn);   /* the Toolbox glue */

/* screenBits.bounds in the QuickDraw globals: thePort's address - 116 (riptide app/toolbox.h) */
#define LM_MBARHEIGHT (*(volatile short *)0xBAA)

/* riptide's MUI for the Mac passes its own texts (menus, the cycle's pop-up) through the
 * translation hook RiptidePrefs has; Lagoon's texts come from its catalog already */
const char *tr(const char *s) { return s; }

/* while a network call waits: give the Mac a tick to other programs, take no event. Riptide has
 * left its core before it calls this, so the bridge's thread may run meanwhile (lm_app_core).
 * On the bridge's thread a wait goes back to the thread's host instead (src/mac/bridge). */
void lm_yield(void *arg)
{
	short ev[8];
	int depth;
	(void)arg;
	if (lmb_in_thread) {
		lmb_thread_yield(5);
		return;
	}
	depth = lm_app_core;
	lm_app_core = 0;
	WaitNextEvent(0, ev, 1, 0);
	lm_app_core = depth;
}
int lm_break(void *arg)
{
	(void)arg;
	return ln_break();
}

int main(void)
{
	void *a5;
	short *sb;
	int rc;
	__asm__ volatile("move.l %%a5,%0" : "=r"(a5));
	mm_gfx_lib_init();
	mm_classes_init();
	sb = (short *)((char *)*(void **)a5 - 116);       /* QuickDraw's screenBits.bounds */
	mm_gfx_init(sb[2] - sb[0] - LM_MBARHEIGHT - 20 < 560);
	mm_screen_init(*(void **)a5);
	mm_paths_init();
	mm_log("Lagoon for the Mac starts");
	rc = lm_gui_run();
	mm_log("Lagoon ends (%d)", rc);
	return 0;
}
