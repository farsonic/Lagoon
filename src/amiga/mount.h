/*
 * Lagoon - mounting shares as DOS devices on AmigaOS (src/amiga/mount.c),
 * shared by C:Lagoon and LagoonPrefs, plus the private protocol between
 * those and L:lagoon-handler.
 *
 * API (all calls return LN_OK or a negative LN_E* code; ln_strerror()
 * gives the text; err/errn, when not NULL, receive a one-line message that
 * is more specific, e.g. "L:lagoon-handler not found"):
 *
 *   ln_amiga_load_conf(c)
 *       Read ENV:Lagoon/lagoon.conf (fallback ENVARC:Lagoon/lagoon.conf)
 *       into *c. A missing file gives an empty list and LN_OK.
 *
 *   ln_amiga_mount(share, device, devout, devn, err, errn)
 *       Mount *share (name, url, user/password/domain, volume, readonly as
 *       in lagoon.conf) as DOS device `device` ("NAS" or "NAS:"; NULL or ""
 *       = share->name, or the first free LGN0:, LGN1: ... when share->name
 *       is empty). Builds a DeviceNode for L:lagoon-handler, adds it, then
 *       starts the handler at once (DeviceProc) so that connection and
 *       logon errors are reported now; on failure the device is removed
 *       again. devout receives the device name used (without ':').
 *       LN_EEXIST: the device name is already in use.
 *
 *   ln_amiga_unmount(device, err, errn)
 *       Send ACTION_DIE to the handler and remove the device node.
 *       LN_EINUSE while files or locks are open on the volume, LN_ENOENT if
 *       there is no such device, LN_EINVAL if it is not a Lagoon device.
 *
 *   ln_amiga_find_mount(share_name, dev, devn)
 *       1 (and the device name) if a share of that name is mounted, else 0.
 *
 *   ln_amiga_list_mounts(cb, ud)
 *       Calls cb(ud, device, info) for every Lagoon device in the DOS list;
 *       info is the mount record (NULL for devices mounted from a
 *       DOSDriver with Startup = "<share name>"). Returns the count.
 *
 *   ln_amiga_status(device, st)
 *       Asks the running handler for an LnStatus (ACTION_LAGOON_STATUS).
 *       LN_ENOENT if not mounted, LN_ECONNRESET is never returned: a handler
 *       that lost its server reports st->online = 0.
 *
 * How it works: the DeviceNode has dn_Handler = "L:lagoon-handler",
 * dn_GlobalVec = -1 (C handler: the startup packet arrives in pr_MsgPort),
 * dn_StackSize = LN_HANDLER_STACK and dn_Startup = a BSTR that is either a
 * share name to look up in lagoon.conf (for DOSDrivers: Startup = "NAS")
 * or "&" + the hex address of an LnMountInfo in public memory (what
 * ln_amiga_mount uses: it carries ad-hoc URLs and MOUNT overrides, and
 * the handler writes its startup error there). The LnMountInfo, the BSTRs
 * and the handler's seglist belong to the device node and are freed by
 * ln_amiga_unmount.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_AMIGA_MOUNT_H
#define LN_AMIGA_MOUNT_H

#include "ln_conf.h"
#include "ln_err.h"

#define LN_HANDLER_PATH   "L:lagoon-handler"
#define LN_HANDLER_STACK  16384
#define LN_MOUNT_MAGIC    0x4C474D49UL      /* 'LGMI' */
#define LN_STATUS_MAGIC   0x4C475354UL      /* 'LGST' */
/* custom packet: dp_Arg1 = LnStatus *, dp_Arg2 = sizeof(LnStatus) */
#define ACTION_LAGOON_STATUS 0x4C470001L

/* the mount record dn_Startup points to ("&%08lx") */
typedef struct LnMountInfo {
	u32     magic;               /* LN_MOUNT_MAGIC */
	u32     size;                /* sizeof(LnMountInfo) */
	LnShare share;               /* password field holds ln_conf_hide() text */
	char    device[32];
	volatile int error;          /* set by the handler: last startup error (LN_E*), 0 = ok */
	u32     bstr_mem;            /* private: the BSTR block for dn_Handler/dn_Startup */
} LnMountInfo;

/* what Lagoon STATUS shows */
typedef struct LnStatus {
	u32  magic;                  /* LN_STATUS_MAGIC */
	u32  size;
	char device[32];
	char volume[108];
	char share[32];
	char url[LN_URL_MAX];        /* without password */
	char backend[48];            /* LnOps name */
	int  online;                 /* 0 while the server is unreachable */
	int  readonly;
	u32  locks, files;
	u32  reconnects;
	u32  mounted;                /* Unix time of the mount */
	u64  bytes_read, bytes_written;
} LnStatus;

typedef void (*ln_mount_cb)(void *ud, const char *device, const LnMountInfo *info);

int ln_amiga_load_conf(LnConf *c);
/* write c to ENV:Lagoon/lagoon.conf, and to ENVARC: too when envarc (the
 * old ENVARC: file becomes lagoon.conf.bak); creates the drawers */
int ln_amiga_save_conf(const LnConf *c, int envarc);

/* the SMB server (Lagoon SERVE) runs as a task of this name */
#define LN_SERVER_TASK "Lagoon server"
int  ln_amiga_server_running(void);
/* send it SIGBREAKF_CTRL_C (stop) or _CTRL_F (reload lagoon.conf); 0 = not running */
int  ln_amiga_server_signal(unsigned long sig);
/* start "Run >NIL: Lagoon SERVE" in the background; LN_OK or LN_EIO */
int  ln_amiga_server_start(void);
int ln_amiga_mount(const LnShare *share, const char *device, char *devout, size_t devn, char *err, size_t errn);
int ln_amiga_unmount(const char *device, char *err, size_t errn);
int ln_amiga_find_mount(const char *share_name, char *dev, size_t devn);
int ln_amiga_list_mounts(ln_mount_cb cb, void *ud);
int ln_amiga_status(const char *device, LnStatus *st);

#endif
