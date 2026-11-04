/*
 * Lagoon - mounting shares as DOS devices (API in mount.h), used by
 * C:Lagoon and LagoonPrefs.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <exec/types.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/filehandler.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "mount.h"
#include "ln_sys.h"

#define MAX_MOUNTS 32

int ln_amiga_load_conf(LnConf *c)
{
	static const char *const files[] = { "ENV:Lagoon/lagoon.conf", "ENVARC:Lagoon/lagoon.conf" };
	int i, line = 0, r = LN_OK;
	struct Process *me = (struct Process *)FindTask(NULL);
	APTR win = me->pr_WindowPtr;
	ln_conf_init(c);
	for (i = 0; i < 2; i++) {
		BPTR fh;
		/* no "insert volume ENV:" requester if the assign is missing */
		me->pr_WindowPtr = (APTR)-1;
		fh = Open((STRPTR)files[i], MODE_OLDFILE);
		me->pr_WindowPtr = win;
		LONG len;
		char *t;
		if (!fh)
			continue;
		Seek(fh, 0, OFFSET_END);
		len = Seek(fh, 0, OFFSET_BEGINNING);
		if (len < 0 || len > 256 * 1024 || !(t = ln_alloc((size_t)len + 1))) {
			Close(fh);
			return LN_ENOMEM;
		}
		if (Read(fh, t, len) != len)
			r = LN_EIO;
		Close(fh);
		if (r == LN_OK)
			r = ln_conf_parse(c, t, &line);
		ln_wipe(t, (size_t)len);
		ln_free(t);
		return r;
	}
	return LN_OK;
}

static void err_set(char *err, size_t n, const char *fmt, const char *a, const char *b)
{
	if (err && n)
		ln_snprintf(err, n, fmt, a, b);
}

/* device name without ':' into out; LN_EINVAL if unusable */
static int dev_name(const char *in, char *out, size_t n)
{
	size_t l;
	ln_strlcpy(out, in, n);
	l = strlen(out);
	if (l && out[l - 1] == ':')
		out[--l] = 0;
	if (!l || l > 30 || strchr(out, ':') || strchr(out, '/'))
		return LN_EINVAL;
	return LN_OK;
}

static int bstr_eq_tail(BSTR b, const char *tail)
{
	const UBYTE *s = (const UBYTE *)BADDR(b);
	size_t tl = strlen(tail);
	char tmp[256];
	if (!s || s[0] < tl)
		return 0;
	memcpy(tmp, s + 1 + s[0] - tl, tl);
	tmp[tl] = 0;
	return !ln_strcasecmp(tmp, tail);
}

static void bstr_c(BSTR b, char *out, size_t n)
{
	const UBYTE *s = (const UBYTE *)BADDR(b);
	size_t l = s ? s[0] : 0;
	if (l >= n)
		l = n - 1;
	if (l)
		memcpy(out, s + 1, l);
	out[l] = 0;
}

static int is_lagoon(struct DosList *dl)
{
	return dl->dol_Type == DLT_DEVICE && bstr_eq_tail(dl->dol_misc.dol_handler.dol_Handler, "lagoon-handler");
}

/* our mount record if dn_Startup is "&address" */
static LnMountInfo *mount_info(struct DosList *dl)
{
	char s[64];
	LnMountInfo *mi;
	u32 v = 0;
	const char *p;
	if (!dl->dol_misc.dol_handler.dol_Startup)
		return NULL;
	bstr_c((BSTR)dl->dol_misc.dol_handler.dol_Startup, s, sizeof(s));
	if (s[0] != '&')
		return NULL;
	for (p = s + 1; *p; p++) {
		int d = (*p >= '0' && *p <= '9') ? *p - '0' : (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10 : -1;
		if (d < 0)
			return NULL;
		v = v * 16 + (u32)d;
	}
	mi = (LnMountInfo *)v;
	if (!mi || (v & 1) || !TypeOfMem(mi) || mi->magic != LN_MOUNT_MAGIC || mi->size != sizeof(LnMountInfo))
		return NULL;
	return mi;
}

static struct DosList *find_dev(const char *name, ULONG flags)
{
	struct DosList *dl = LockDosList(flags | LDF_READ);
	dl = FindDosEntry(dl, (STRPTR)name, flags);
	UnLockDosList(flags | LDF_READ);
	return dl;
}

static void free_node(struct DosList *dl, LnMountInfo *mi)
{
	if (dl->dol_misc.dol_handler.dol_SegList)
		UnLoadSeg(dl->dol_misc.dol_handler.dol_SegList);
	dl->dol_misc.dol_handler.dol_SegList = 0;
	if (mi) {
		void *b = (void *)mi->bstr_mem;
		ln_wipe(mi, sizeof(*mi));
		FreeVec(mi);
		FreeVec(b);
		FreeDosEntry(dl);
	}
}

int ln_amiga_mount(const LnShare *share, const char *device, char *devout, size_t devn, char *err, size_t errn)
{
	char dev[40], colon[44], other[40];
	LnMountInfo *mi;
	UBYTE *blk;
	struct DosList *dl;
	struct MsgPort *port;
	int i, r;
	if (err && errn)
		err[0] = 0;
	if (device && *device)
		r = dev_name(device, dev, sizeof(dev));
	else if (share->name[0])
		r = dev_name(share->name, dev, sizeof(dev));
	else {
		r = LN_ENOSPC;
		for (i = 0; i < 100; i++) {
			ln_snprintf(dev, sizeof(dev), "LGN%d", i);
			if (!find_dev(dev, LDF_DEVICES | LDF_VOLUMES | LDF_ASSIGNS)) {
				r = LN_OK;
				break;
			}
		}
	}
	if (r != LN_OK) {
		err_set(err, errn, "bad device name \"%s\"%s", device ? device : share->name, "");
		return LN_EINVAL;
	}
	if (share->name[0] && ln_amiga_find_mount(share->name, other, sizeof(other))) {
		err_set(err, errn, "%s is already mounted as %s:", share->name, other);
		return LN_EEXIST;
	}
	if (find_dev(dev, LDF_DEVICES | LDF_ASSIGNS)) {
		err_set(err, errn, "device %s: already exists%s", dev, "");
		return LN_EEXIST;
	}
	mi = AllocVec(sizeof(LnMountInfo), MEMF_PUBLIC | MEMF_CLEAR);
	blk = AllocVec(128, MEMF_PUBLIC | MEMF_CLEAR);
	dl = MakeDosEntry((STRPTR)dev, DLT_DEVICE);
	if (!mi || !blk || !dl) {
		FreeVec(mi);
		FreeVec(blk);
		if (dl)
			FreeDosEntry(dl);
		return LN_ENOMEM;
	}
	mi->magic = LN_MOUNT_MAGIC;
	mi->size = sizeof(LnMountInfo);
	mi->share = *share;
	ln_conf_hide(share->password, mi->share.password, sizeof(mi->share.password));
	ln_strlcpy(mi->device, dev, sizeof(mi->device));
	mi->error = 1;                  /* "the handler never ran" */
	mi->bstr_mem = (u32)blk;
	blk[0] = (UBYTE)strlen(LN_HANDLER_PATH);
	memcpy(blk + 1, LN_HANDLER_PATH, strlen(LN_HANDLER_PATH));
	ln_snprintf((char *)blk + 65, 60, "&%08lx", (unsigned long)(u32)mi);
	blk[64] = (UBYTE)strlen((char *)blk + 65);
	dl->dol_misc.dol_handler.dol_Handler = MKBADDR(blk);
	dl->dol_misc.dol_handler.dol_StackSize = LN_HANDLER_STACK;
	dl->dol_misc.dol_handler.dol_Priority = 5;
	dl->dol_misc.dol_handler.dol_Startup = (ULONG)MKBADDR(blk + 64);
	dl->dol_misc.dol_handler.dol_SegList = 0;
	dl->dol_misc.dol_handler.dol_GlobVec = (BPTR)-1;
	LockDosList(LDF_DEVICES | LDF_WRITE);
	r = AddDosEntry(dl) ? LN_OK : LN_EEXIST;
	UnLockDosList(LDF_DEVICES | LDF_WRITE);
	if (r != LN_OK) {
		free_node(dl, mi);
		err_set(err, errn, "cannot add device %s:%s", dev, "");
		return r;
	}
	/* start the handler now, so errors show up here */
	ln_snprintf(colon, sizeof(colon), "%s:", dev);
	port = DeviceProc((STRPTR)colon);
	if (!port) {
		LONG ioerr = IoErr();
		int e = mi->error;
		LockDosList(LDF_DEVICES | LDF_WRITE);
		RemDosEntry(dl);
		UnLockDosList(LDF_DEVICES | LDF_WRITE);
		free_node(dl, mi);
		if (e < 0) {
			err_set(err, errn, "%s", ln_strerror(e), "");
			return e;
		}
		if (err && errn) {
			char num[16];
			ln_snprintf(num, sizeof(num), "%ld", (long)ioerr);
			err_set(err, errn, "cannot start " LN_HANDLER_PATH " (DOS error %s)%s", num, "");
		}
		return ioerr == ERROR_OBJECT_NOT_FOUND ? LN_ENOENT : LN_EIO;
	}
	if (devout && devn)
		ln_strlcpy(devout, dev, devn);
	return LN_OK;
}

int ln_amiga_unmount(const char *device, char *err, size_t errn)
{
	char dev[40];
	struct DosList *dl;
	struct MsgPort *task;
	LnMountInfo *mi;
	int i;
	if (err && errn)
		err[0] = 0;
	if (dev_name(device, dev, sizeof(dev)) != LN_OK) {
		err_set(err, errn, "bad device name \"%s\"%s", device, "");
		return LN_EINVAL;
	}
	dl = LockDosList(LDF_DEVICES | LDF_READ);
	dl = FindDosEntry(dl, (STRPTR)dev, LDF_DEVICES);
	if (!dl) {
		UnLockDosList(LDF_DEVICES | LDF_READ);
		err_set(err, errn, "no device %s:%s", dev, "");
		return LN_ENOENT;
	}
	if (!is_lagoon(dl)) {
		UnLockDosList(LDF_DEVICES | LDF_READ);
		err_set(err, errn, "%s: is not a Lagoon device%s", dev, "");
		return LN_EINVAL;
	}
	task = dl->dol_Task;
	mi = mount_info(dl);
	UnLockDosList(LDF_DEVICES | LDF_READ);
	if (task) {
		if (!DoPkt(task, ACTION_DIE, 0, 0, 0, 0, 0)) {
			LONG e = IoErr();
			if (e == ERROR_OBJECT_IN_USE) {
				err_set(err, errn, "%s: is in use (files or locks are open)%s", dev, "");
				return LN_EINUSE;
			}
			err_set(err, errn, "%s: did not quit%s", dev, "");
			return LN_EIO;
		}
		/* the handler clears dn_Task as it goes */
		for (i = 0; i < 250 && dl->dol_Task; i++)
			Delay(1);
	}
	LockDosList(LDF_DEVICES | LDF_WRITE);
	RemDosEntry(dl);
	UnLockDosList(LDF_DEVICES | LDF_WRITE);
	/* devices from a DOSDriver keep their (Mount's) memory */
	if (mi)
		free_node(dl, mi);
	return LN_OK;
}

typedef struct MEnt {
	char        device[32];
	LnMountInfo info;
	int         has_info;
	char        startup[64];
} MEnt;

static int collect(MEnt *m, int max)
{
	struct DosList *dl = LockDosList(LDF_DEVICES | LDF_READ);
	int n = 0;
	while (n < max && (dl = NextDosEntry(dl, LDF_DEVICES)) != NULL) {
		LnMountInfo *mi;
		if (!is_lagoon(dl))
			continue;
		memset(&m[n], 0, sizeof(m[n]));
		bstr_c(dl->dol_Name, m[n].device, sizeof(m[n].device));
		if ((mi = mount_info(dl)) != NULL) {
			m[n].info = *mi;
			m[n].info.share.password[0] = 0;
			m[n].has_info = 1;
		} else if (dl->dol_misc.dol_handler.dol_Startup)
			bstr_c((BSTR)dl->dol_misc.dol_handler.dol_Startup, m[n].startup, sizeof(m[n].startup));
		n++;
	}
	UnLockDosList(LDF_DEVICES | LDF_READ);
	return n;
}

int ln_amiga_list_mounts(ln_mount_cb cb, void *ud)
{
	MEnt *m = ln_alloc(sizeof(MEnt) * MAX_MOUNTS);
	int n, i;
	if (!m)
		return LN_ENOMEM;
	n = collect(m, MAX_MOUNTS);
	for (i = 0; i < n; i++)
		cb(ud, m[i].device, m[i].has_info ? &m[i].info : NULL);
	ln_free(m);
	return n;
}

int ln_amiga_find_mount(const char *share_name, char *dev, size_t devn)
{
	MEnt *m = ln_alloc(sizeof(MEnt) * MAX_MOUNTS);
	int n, i, found = 0;
	if (!m)
		return 0;
	n = collect(m, MAX_MOUNTS);
	for (i = 0; i < n && !found; i++) {
		const char *nm = m[i].has_info ? m[i].info.share.name : m[i].startup;
		if (nm[0] && !ln_strcasecmp(nm, share_name)) {
			found = 1;
			if (dev && devn)
				ln_strlcpy(dev, m[i].device, devn);
		}
	}
	ln_free(m);
	return found;
}

int ln_amiga_status(const char *device, LnStatus *st)
{
	char dev[40];
	struct DosList *dl;
	struct MsgPort *task = NULL;
	if (dev_name(device, dev, sizeof(dev)) != LN_OK)
		return LN_EINVAL;
	dl = LockDosList(LDF_DEVICES | LDF_READ);
	dl = FindDosEntry(dl, (STRPTR)dev, LDF_DEVICES);
	if (dl && is_lagoon(dl))
		task = dl->dol_Task;
	UnLockDosList(LDF_DEVICES | LDF_READ);
	if (!dl)
		return LN_ENOENT;
	if (!task)
		return LN_ENOSHARE;     /* the handler is not running */
	memset(st, 0, sizeof(*st));
	if (!DoPkt(task, ACTION_LAGOON_STATUS, (LONG)st, (LONG)sizeof(*st), 0, 0, 0) || st->magic != LN_STATUS_MAGIC)
		return LN_ENOTSUP;
	return LN_OK;
}
