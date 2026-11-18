/*
 * Lagoon on the classic Mac OS: the AppleShare bridge (docs/mac.md, "Lagoon's bridge").
 *
 * A share Lagoon has connected over TCP is offered to the Mac's own AppleShare client as an AFP
 * server inside this Mac (src/core/afpsrv on the Mac's .MPP and .ATP drivers), so that the
 * Finder mounts it as an AppleShare volume. The server runs on a thread of its own, driven at
 * deferred-task time, because the AppleShare client calls the server synchronously from
 * whatever program is in front (the Finder spins in a File Manager call until the answer is
 * there) and Lagoon itself may be in the background: see lm_bridge.c for why and how.
 *
 * The parts:
 *   lm_bridge.c     the thread, the .ATP transport of the server, NBP, start, stop, mounting
 *   lm_pool.c       the thread's memory (the Memory Manager is not for interrupt time)
 *   bridge_glue.S   the context switch, the Time Manager and deferred task entries, the traps
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LM_BRIDGE_H
#define LM_BRIDGE_H

#include "../../core/ln_vfs.h"

/* ---- for the front end (src/mui/lm_gui.c, LM_BRIDGE) ---- */
enum { LMB_OFF = 0, LMB_STARTING = 1, LMB_SERVING = 2, LMB_STOPPING = 3, LMB_FAILED = 4 };
/* offer the share at url (with these credentials) under name; returns at once, LN_OK or an error
 * (AppleTalk is off: LN_ENONET). The thread then connects and registers the name. */
int  lm_bridge_start(const char *url, const LnCreds *cr, const char *name);
/* LMB_*; with LMB_FAILED, *err is the Lagoon error or *oserr the AppleTalk one */
int  lm_bridge_state(int *err, int *oserr);
/* the application's wait (mac_main.c): a tick to other programs */
void lm_yield(void *arg);
/* the share being offered ("" if none) */
const char *lm_bridge_name(void);
/* mount the offered share on the desktop (the File Manager's PBVolumeMount, as an alias would):
 * the Mac's result code, 0 = mounted */
int  lm_bridge_mount(void);
/* stop offering it: the AppleShare client is told the server is going (its volume goes) */
void lm_bridge_stop(void);

/* ---- for the Mac layer (sys_mac.c, net_mac.c, mac_main.c) ---- */
/* the bridge's thread is running now: the core's memory comes from lm_pool, its sockets are the
 * thread's Riptide client, a wait yields to the thread's host instead of WaitNextEvent */
extern volatile int lmb_in_thread;
/* the application is inside Riptide's core (net_mac.c counts it): the thread must not run */
extern volatile int lm_app_core;
void  lmb_thread_yield(unsigned ms);
void *lm_pool_alloc(unsigned long n);       /* cleared */
int   lm_pool_free(void *p);                /* 1 if p came from the pool */
int   lm_pool_init(void *mem, unsigned long size);
/* net_mac.c: a second Riptide client, the thread's */
int   ln_net_thread_attach(void);
void  ln_net_thread_detach(void);

#endif
