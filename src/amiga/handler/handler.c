/*
 * Lagoon - L:lagoon-handler, the AmigaDOS file system handler that shows a
 * network share as a volume. One process per mounted share, started by DOS
 * from the DeviceNode that C:Lagoon (src/amiga/mount.c) or a DOSDriver
 * built: dn_GlobalVec = -1, so the startup packet arrives in pr_MsgPort;
 * dn_Startup is a BSTR, either a share name from lagoon.conf or
 * "&<address of an LnMountInfo>" (see mount.h).
 *
 * Built without C library start-up code (-nostdlib): DOS enters at entry.c,
 * which calls handler_main(). Only vc.lib functions that need no
 * initialisation are used (memcpy, strlen ...).
 *
 * This file is the DOS side: packets, BSTRs, locks/file handles as DOS
 * sees them, FileInfoBlocks, ExAll, the volume node, the timer. The file
 * system logic lives in hcore.c. See docs/handler.md.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <exec/types.h>
#include <exec/memory.h>
#include <exec/execbase.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/filehandler.h>
#include <dos/exall.h>
#include <devices/timer.h>
#include <devices/input.h>
#include <devices/inputevent.h>
#include <utility/hooks.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>
#include "hcore.h"
#include "ln_sys.h"
#include "ln_net.h"
#include "ln_conf.h"
#include "ln_charset.h"
#include "mount.h"

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;
struct Library *UtilityBase;
extern const char *ln_log_file;      /* sys_amiga.c */

#define ALOCK_MAGIC 0x4C474C4BUL       /* 'LGLK' */
#define AFILE_MAGIC 0x4C474648UL       /* 'LGFH' */
#define VOLNAME_MAX 64

/* a DOS lock: the FileLock DOS sees, plus ours */
typedef struct ALock {
	struct FileLock fl;
	u32    magic;
	HLock *h;
} ALock;

/* what fh_Arg1 points to */
typedef struct AFile {
	u32    magic;
	HFile *f;
} AFile;

typedef struct Handler {
	struct Process    *proc;
	struct MsgPort    *port;
	struct DeviceNode *dn;
	struct DosList    *vol;
	UBYTE             *volname;        /* BSTR buffer of the volume node (VOLNAME_MAX + 2) */
	HC                 hc;
	const LnOps       *ops;
	LnFs              *fs;
	LnShare            share;
	LnMountInfo       *mi;
	char               device[32];
	char               logname[64];
	int                tz;
	int                cfg_readonly;
	LONG               wp_key;         /* ACTION_WRITE_PROTECT passkey */
	u32                mounted;
	struct MsgPort    *tport;
	struct timerequest *treq;
	int                timer_on;
	char              *n1, *n2;        /* packet name buffers (256 each) */
	int                quit;
	struct DosPacket  *die;            /* the ACTION_DIE to reply when gone */
	ULONG              bpb;            /* bytes per block reported to DOS */
} Handler;

static Handler *G;

static int  startup(struct DosPacket *pkt);
static void serve(void);
static void shutdown(void);

/* ----------------------------------------------------------- entry ---- */

LONG handler_main(void)
{
	struct Process *me;
	struct Message *msg;
	struct DosPacket *pkt;
	SysBase = *(struct ExecBase **)4L;
	me = (struct Process *)FindTask(NULL);
	WaitPort(&me->pr_MsgPort);
	msg = GetMsg(&me->pr_MsgPort);
	pkt = (struct DosPacket *)msg->mn_Node.ln_Name;
	DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)"dos.library", 37);
	UtilityBase = OpenLibrary((STRPTR)"utility.library", 37);
	if (!DOSBase || !UtilityBase || !startup(pkt)) {
		/* startup() replied the packet (or we cannot even do that) */
		if (UtilityBase)
			CloseLibrary(UtilityBase);
		if (DOSBase)
			CloseLibrary((struct Library *)DOSBase);
		return 0;
	}
	serve();
	shutdown();       /* replies the DIE packet under Forbid() and returns */
	return 0;
}

/* -------------------------------------------------------- helpers ---- */

static void reply(struct DosPacket *p, LONG r1, LONG r2)
{
	struct MsgPort *rp = p->dp_Port;
	struct Message *m = p->dp_Link;
	p->dp_Res1 = r1;
	p->dp_Res2 = r2;
	p->dp_Port = G ? G->port : &((struct Process *)FindTask(NULL))->pr_MsgPort;
	m->mn_Node.ln_Name = (char *)p;
	m->mn_Node.ln_Succ = NULL;
	m->mn_Node.ln_Pred = NULL;
	PutMsg(rp, m);
}

/* BSTR -> C string (n >= 256 holds every BSTR) */
static char *bstr(BPTR b, char *out, size_t n)
{
	const UBYTE *s = (const UBYTE *)BADDR(b);
	size_t l = 0;
	if (s) {
		l = s[0];
		if (l >= n)
			l = n - 1;
		memcpy(out, s + 1, l);
	}
	out[l] = 0;
	return out;
}

static void set_bstr(UBYTE *dst, const char *s, size_t max)
{
	size_t l = strlen(s);
	if (l > max)
		l = max;
	dst[0] = (UBYTE)l;
	memcpy(dst + 1, s, l);
	if (l < max)
		dst[l + 1] = 0;
}

enum { CTX_GEN, CTX_READ, CTX_WRITE, CTX_DELETE, CTX_START };

/* the one LN_E* -> DOS ERROR_* table */
static LONG doserr(int r, int ctx)
{
	switch (r) {
	case LN_OK: return 0;
	case LN_ENOENT: return ERROR_OBJECT_NOT_FOUND;
	case LN_EEXIST: return ERROR_OBJECT_EXISTS;
	case LN_ENOTDIR: return ERROR_OBJECT_WRONG_TYPE;
	case LN_EISDIR: return ERROR_OBJECT_WRONG_TYPE;
	case LN_ENOTEMPTY: return ERROR_DIRECTORY_NOT_EMPTY;
	case LN_EACCES:
		return ctx == CTX_READ ? ERROR_READ_PROTECTED : ctx == CTX_DELETE ? ERROR_DELETE_PROTECTED :
		       ERROR_WRITE_PROTECTED;
	case LN_EROFS: return ERROR_DISK_WRITE_PROTECTED;
	case LN_ENOSPC: return ERROR_DISK_FULL;
	case LN_EINUSE: return ERROR_OBJECT_IN_USE;
	case LN_EINVAL: return ERROR_INVALID_COMPONENT_NAME;
	case LN_ENAMETOOLONG: return ERROR_INVALID_COMPONENT_NAME;
	case LN_ENOMEM: return ERROR_NO_FREE_STORE;
	case LN_ENOTSUP: return ERROR_ACTION_NOT_KNOWN;
	case LN_EAUTH: return ERROR_READ_PROTECTED;
	case LN_EBREAK: return ERROR_BREAK;
	case LN_ESTALE: return ERROR_OBJECT_NOT_FOUND;
	case LN_ENOSHARE: return ctx == CTX_START ? ERROR_DEVICE_NOT_MOUNTED : ERROR_OBJECT_NOT_FOUND;
	case LN_ETIMEDOUT: case LN_ECONNREFUSED: case LN_ECONNRESET: case LN_EHOSTUNREACH:
	case LN_ENOHOST: case LN_ENONET:
		return ERROR_NO_DISK;             /* server not reachable */
	case LN_EIO: case LN_EPROTO: case LN_ECRYPTO:
	default:
		return ERROR_NOT_A_DOS_DISK;      /* the server said something we cannot use */
	}
}

/* Unix UTC <-> DateStamp in local time */
static void to_ds(u32 t, struct DateStamp *ds)
{
	s32 s;
	if (t <= 252460800UL) {
		ds->ds_Days = ds->ds_Minute = ds->ds_Tick = 0;
		return;
	}
	s = (s32)(t - 252460800UL) + G->tz * 60;
	if (s < 0)
		s = 0;
	ds->ds_Days = s / 86400;
	s %= 86400;
	ds->ds_Minute = s / 60;
	ds->ds_Tick = (s % 60) * TICKS_PER_SECOND;
}

static u32 from_ds(const struct DateStamp *ds)
{
	return 252460800UL + (u32)ds->ds_Days * 86400UL + (u32)ds->ds_Minute * 60UL +
	       (u32)ds->ds_Tick / TICKS_PER_SECOND - (u32)(G->tz * 60);
}

static LONG prot_to_fib(u32 p)
{
	LONG f = 0;
	if (!(p & LN_P_READ)) f |= FIBF_READ;
	if (!(p & LN_P_WRITE)) f |= FIBF_WRITE;
	if (!(p & LN_P_EXEC)) f |= FIBF_EXECUTE;
	if (!(p & LN_P_DELETE)) f |= FIBF_DELETE;
	if (p & LN_P_ARCHIVE) f |= FIBF_ARCHIVE;
	if (p & LN_P_PURE) f |= FIBF_PURE;
	if (p & LN_P_SCRIPT) f |= FIBF_SCRIPT;
	return f;
}

static u32 fib_to_prot(LONG f)
{
	u32 p = 0;
	if (!(f & FIBF_READ)) p |= LN_P_READ;
	if (!(f & FIBF_WRITE)) p |= LN_P_WRITE;
	if (!(f & FIBF_EXECUTE)) p |= LN_P_EXEC;
	if (!(f & FIBF_DELETE)) p |= LN_P_DELETE;
	if (f & FIBF_ARCHIVE) p |= LN_P_ARCHIVE;
	if (f & FIBF_PURE) p |= LN_P_PURE;
	if (f & FIBF_SCRIPT) p |= LN_P_SCRIPT;
	return p;
}

static LONG clamp32(u64 v) { return v > 0x7fffffffUL ? 0x7fffffffL : (LONG)v; }

/* ------------------------------------------------- locks and files ---- */

static int get_lock(BPTR b, HLock **out)
{
	ALock *a = (ALock *)BADDR(b);
	*out = NULL;
	if (!a)
		return 1;
	if (a->magic != ALOCK_MAGIC || a->fl.fl_Task != G->port || !a->h)
		return 0;
	*out = a->h;
	return 1;
}

static BPTR mk_lock(HLock *h, LONG *err)
{
	ALock *a = AllocVec(sizeof(ALock), MEMF_PUBLIC | MEMF_CLEAR);
	if (!a) {
		hc_unlock(&G->hc, h);
		*err = ERROR_NO_FREE_STORE;
		return 0;
	}
	a->fl.fl_Key = (LONG)h->key;
	a->fl.fl_Access = h->excl ? EXCLUSIVE_LOCK : SHARED_LOCK;
	a->fl.fl_Task = G->port;
	a->fl.fl_Volume = MKBADDR(G->vol);
	a->magic = ALOCK_MAGIC;
	a->h = h;
	h->os = a;
	return MKBADDR(a);
}

static void free_alock(ALock *a)
{
	a->magic = 0;
	FreeVec(a);
}

static HFile *get_file(LONG arg)
{
	AFile *a = (AFile *)arg;
	if (!a || a->magic != AFILE_MAGIC)
		return NULL;
	return a->f;
}

/* ----------------------------------------------- FileInfoBlock / ExAll -- */

static void fill_fib(struct FileInfoBlock *fib, LONG key, const char *aname, int root, int type, u64 size,
                     u32 mtime, u32 prot, const char *comment, u32 uid, u32 gid)
{
	char c[80];
	fib->fib_DiskKey = key;
	fib->fib_DirEntryType = fib->fib_EntryType = root ? ST_ROOT : type == LN_T_DIR ? ST_USERDIR : ST_FILE;
	set_bstr((UBYTE *)fib->fib_FileName, aname, HC_NAMEMAX);
	fib->fib_Protection = prot_to_fib(prot);
	fib->fib_Size = type == LN_T_DIR ? 0 : clamp32(size);
	fib->fib_NumBlocks = type == LN_T_DIR ? 0 : clamp32((size + G->bpb - 1) / G->bpb);
	to_ds(mtime, &fib->fib_Date);
	hc_utf8_to_latin1(comment ? comment : "", c, sizeof(c));
	set_bstr((UBYTE *)fib->fib_Comment, c, 79);
	fib->fib_OwnerUID = (UWORD)uid;
	fib->fib_OwnerGID = (UWORD)gid;
}

static void fib_from_stat(struct FileInfoBlock *fib, LONG key, const char *aname, int root, const LnStat *st)
{
	fill_fib(fib, key, aname, root, st->type, st->size, st->mtime, st->prot, st->comment, st->uid, st->gid);
}

static void lock_name(HLock *l, char *out)
{
	if (!l || !l->rpath[0])
		ln_strlcpy(out, (const char *)G->volname + 1, HC_NAMEMAX + 1);
	else
		hc_amiga_name(ln_path_base(l->rpath), out);
}

static const UWORD ed_size[8] = { 0, 8, 12, 16, 20, 32, 36, 40 };

static void examine_all(struct DosPacket *p)
{
	HLock *l;
	UBYTE *buf = (UBYTE *)p->dp_Arg2, *end;
	LONG size = p->dp_Arg3, type = p->dp_Arg4;
	struct ExAllControl *eac = (struct ExAllControl *)p->dp_Arg5;
	struct ExAllData *prev = NULL;
	u32 idx;
	const HEnt *e;
	int r;
	if (!get_lock(p->dp_Arg1, &l)) {
		reply(p, DOSFALSE, ERROR_INVALID_LOCK);
		return;
	}
	if (type < ED_NAME || type > ED_OWNER) {
		reply(p, DOSFALSE, ERROR_BAD_NUMBER);
		return;
	}
	if (!l) {
		/* ExAll on the root without a lock: use a temporary one */
		reply(p, DOSFALSE, ERROR_OBJECT_WRONG_TYPE);
		return;
	}
	if (l->type != LN_T_DIR) {
		reply(p, DOSFALSE, ERROR_OBJECT_WRONG_TYPE);
		return;
	}
	eac->eac_Entries = 0;
	idx = eac->eac_LastKey;
	end = buf + size;
	for (;;) {
		struct ExAllData *ed;
		size_t need, nl, cl = 0;
		char c[80];
		UBYTE *s;
		r = hc_next(&G->hc, l, &idx, &e);
		if (r < 0) {
			reply(p, DOSFALSE, doserr(r, CTX_READ));
			return;
		}
		if (r == 0) {
			eac->eac_LastKey = 0;
			reply(p, DOSFALSE, ERROR_NO_MORE_ENTRIES);
			return;
		}
		if (eac->eac_MatchString && !MatchPatternNoCase(eac->eac_MatchString, (STRPTR)e->aname))
			continue;
		nl = strlen(e->aname) + 1;
		if (type >= ED_COMMENT) {
			hc_utf8_to_latin1(e->comment ? e->comment : "", c, sizeof(c));
			cl = strlen(c) + 1;
		}
		need = ((size_t)ed_size[type] + nl + cl + 3) & ~(size_t)3;
		if (buf + need > end) {
			idx--;           /* this one goes into the next buffer */
			eac->eac_LastKey = idx;
			if (!eac->eac_Entries)
				reply(p, DOSFALSE, ERROR_BUFFER_OVERFLOW);
			else
				reply(p, DOSTRUE, 0);
			return;
		}
		ed = (struct ExAllData *)buf;
		ed->ed_Next = NULL;
		s = buf + ed_size[type];
		memcpy(s, e->aname, nl);
		ed->ed_Name = (STRPTR)s;
		s += nl;
		if (type >= ED_TYPE)
			ed->ed_Type = e->type == LN_T_DIR ? ST_USERDIR : ST_FILE;
		if (type >= ED_SIZE)
			ed->ed_Size = e->type == LN_T_DIR ? 0 : (ULONG)clamp32(e->size);
		if (type >= ED_PROTECTION)
			ed->ed_Prot = (ULONG)prot_to_fib(e->prot);
		if (type >= ED_DATE) {
			struct DateStamp ds;
			to_ds(e->mtime, &ds);
			ed->ed_Days = (ULONG)ds.ds_Days;
			ed->ed_Mins = (ULONG)ds.ds_Minute;
			ed->ed_Ticks = (ULONG)ds.ds_Tick;
		}
		if (type >= ED_COMMENT) {
			memcpy(s, c, cl);
			ed->ed_Comment = (STRPTR)s;
		}
		if (type >= ED_OWNER) {
			ed->ed_OwnerUID = (UWORD)e->uid;
			ed->ed_OwnerGID = (UWORD)e->gid;
		}
		if (eac->eac_MatchFunc && !CallHookPkt(eac->eac_MatchFunc, &type, ed))
			continue;
		if (prev)
			prev->ed_Next = ed;
		prev = ed;
		buf += need;
		eac->eac_Entries++;
		eac->eac_LastKey = idx;
	}
}

/* --------------------------------------------------------- volume ---- */

static void wb_event(UBYTE cls)
{
	struct MsgPort *mp = CreateMsgPort();
	struct IOStdReq *io = mp ? (struct IOStdReq *)CreateIORequest(mp, sizeof(struct IOStdReq)) : NULL;
	struct InputEvent ie;
	if (io && !OpenDevice((STRPTR)"input.device", 0, (struct IORequest *)io, 0)) {
		memset(&ie, 0, sizeof(ie));
		ie.ie_Class = cls;
		io->io_Command = IND_WRITEEVENT;
		io->io_Data = &ie;
		io->io_Length = sizeof(ie);
		DoIO((struct IORequest *)io);
		CloseDevice((struct IORequest *)io);
	}
	if (io)
		DeleteIORequest((struct IORequest *)io);
	if (mp)
		DeleteMsgPort(mp);
}

static int add_volume(const char *name)
{
	struct DosList *v = AllocVec(sizeof(struct DosList), MEMF_PUBLIC | MEMF_CLEAR);
	UBYTE *nm = AllocVec(VOLNAME_MAX + 2, MEMF_PUBLIC | MEMF_CLEAR);
	if (!v || !nm) {
		FreeVec(v);
		FreeVec(nm);
		return 0;
	}
	set_bstr(nm, name, VOLNAME_MAX);
	v->dol_Type = DLT_VOLUME;
	v->dol_Task = G->port;
	DateStamp(&v->dol_misc.dol_volume.dol_VolumeDate);
	v->dol_misc.dol_volume.dol_DiskType = ID_DOS_DISK;
	v->dol_Name = MKBADDR(nm);
	G->vol = v;
	G->volname = nm;
	LockDosList(LDF_VOLUMES | LDF_WRITE);
	if (!AddDosEntry(v)) {
		UnLockDosList(LDF_VOLUMES | LDF_WRITE);
		LN_LOG(0, "cannot add volume %s:", name);
		return 0;
	}
	UnLockDosList(LDF_VOLUMES | LDF_WRITE);
	wb_event(IECLASS_DISKINSERTED);
	return 1;
}

static void remove_volume(void)
{
	if (!G->vol)
		return;
	LockDosList(LDF_VOLUMES | LDF_WRITE);
	RemDosEntry(G->vol);
	UnLockDosList(LDF_VOLUMES | LDF_WRITE);
	FreeVec(G->vol);
	FreeVec(G->volname);
	G->vol = NULL;
	G->volname = NULL;
	wb_event(IECLASS_DISKREMOVED);
}

static void info(struct InfoData *id)
{
	LnStatFs sf;
	u64 total, used;
	ULONG bpb;
	memset(id, 0, sizeof(*id));
	if (hc_statfs(&G->hc, &sf) != LN_OK) {
		if (!G->hc.sfs_valid)
			memset(&sf, 0, sizeof(sf));
		else
			sf = G->hc.sfs;
	}
	bpb = G->bpb;
	total = sf.total_bytes;
	used = sf.total_bytes > sf.free_bytes ? sf.total_bytes - sf.free_bytes : 0;
	while (total / bpb > 0x7fffffffUL)
		bpb *= 2;
	id->id_UnitNumber = 0;
	id->id_DiskState = (G->hc.readonly || sf.readonly) ? ID_WRITE_PROTECTED : ID_VALIDATED;
	id->id_NumBlocks = (LONG)(total / bpb);
	id->id_NumBlocksUsed = (LONG)(used / bpb);
	id->id_BytesPerBlock = (LONG)bpb;
	id->id_DiskType = ID_DOS_DISK;
	id->id_VolumeNode = MKBADDR(G->vol);
	id->id_InUse = (G->hc.nlocks + G->hc.nfiles) ? DOSTRUE : 0;
}

/* ------------------------------------------------------------ timer ---- */

static void timer_start(void)
{
	ULONG secs = hc_dirty(&G->hc) ? 1 : 10;
	if (!G->treq || G->timer_on)
		return;
	G->treq->tr_node.io_Command = TR_ADDREQUEST;
	G->treq->tr_time.tv_secs = secs;
	G->treq->tr_time.tv_micro = 0;
	SendIO((struct IORequest *)G->treq);
	G->timer_on = 1;
}

static void timer_open(void)
{
	G->tport = CreateMsgPort();
	if (G->tport)
		G->treq = (struct timerequest *)CreateIORequest(G->tport, sizeof(struct timerequest));
	if (G->treq && OpenDevice((STRPTR)TIMERNAME, UNIT_VBLANK, (struct IORequest *)G->treq, 0)) {
		DeleteIORequest((struct IORequest *)G->treq);
		G->treq = NULL;
	}
}

static void timer_close(void)
{
	if (G->treq) {
		if (G->timer_on) {
			AbortIO((struct IORequest *)G->treq);
			WaitIO((struct IORequest *)G->treq);
		}
		CloseDevice((struct IORequest *)G->treq);
		DeleteIORequest((struct IORequest *)G->treq);
	}
	if (G->tport)
		DeleteMsgPort(G->tport);
	G->treq = NULL;
	G->tport = NULL;
	G->timer_on = 0;
}

static void sleep_ms(u32 ms)
{
	LONG t = (LONG)(ms / 20);
	Delay(t > 0 ? t : 1);
}

/* ----------------------------------------------------------- startup -- */

static int load_conf(LnConf *c)
{
	static const char *const files[] = { "ENV:Lagoon/lagoon.conf", "ENVARC:Lagoon/lagoon.conf" };
	int i;
	ln_conf_init(c);
	for (i = 0; i < 2; i++) {
		BPTR fh = Open((STRPTR)files[i], MODE_OLDFILE);
		LONG len;
		char *t;
		int bad = 0;
		if (!fh)
			continue;
		Seek(fh, 0, OFFSET_END);
		len = Seek(fh, 0, OFFSET_BEGINNING);
		if (len < 0 || len > 256 * 1024 || !(t = ln_alloc((size_t)len + 1))) {
			Close(fh);
			return LN_ENOMEM;
		}
		if (Read(fh, t, len) != len)
			bad = 1;
		Close(fh);
		if (!bad && ln_conf_parse(c, t, &bad) != LN_OK)
			LN_LOG(0, "%s: error in line %d", files[i], bad);
		ln_wipe(t, (size_t)len);
		ln_free(t);
		return LN_OK;
	}
	return LN_OK;
}

static u32 hexnum(const char *s)
{
	u32 v = 0;
	for (; *s; s++) {
		int d = (*s >= '0' && *s <= '9') ? *s - '0' : (*s >= 'a' && *s <= 'f') ? *s - 'a' + 10 :
		        (*s >= 'A' && *s <= 'F') ? *s - 'A' + 10 : -1;
		if (d < 0)
			break;
		v = v * 16 + (u32)d;
	}
	return v;
}

/* fills G->share from dn_Startup; LN_OK or an error */
static int find_share(BPTR startup)
{
	char *s = G->n1;
	LnConf *c;
	int r = LN_OK;
	bstr(startup, s, 256);
	c = ln_alloc(sizeof(LnConf));
	if (!c)
		return LN_ENOMEM;
	load_conf(c);
	ln_log_level = c->loglevel;
	if (s[0] == '&') {
		LnMountInfo *mi = (LnMountInfo *)hexnum(s + 1);
		if (!mi || ((u32)mi & 1) || !TypeOfMem(mi) || mi->magic != LN_MOUNT_MAGIC || mi->size != sizeof(LnMountInfo))
			r = LN_EINVAL;
		else {
			G->mi = mi;
			G->share = mi->share;
			ln_conf_unhide(mi->share.password, G->share.password, sizeof(G->share.password));
		}
	} else {
		LnShare *sh = ln_conf_find(c, s);
		if (sh)
			G->share = *sh;
		else
			r = LN_ENOSHARE;
	}
	ln_wipe(c, sizeof(LnConf));
	ln_free(c);
	return r;
}

/* returns 1 when the handler runs, 0 after failing (packet replied) */
static int startup(struct DosPacket *pkt)
{
	LnCreds *cr;
	int r;
	char *vn, *p;
	Handler *g = AllocVec(sizeof(Handler), MEMF_PUBLIC | MEMF_CLEAR);
	G = g;
	ln_log_level = 0;
	ln_log_file = NULL;
	if (!g || !(g->n1 = ln_alloc(512))) {
		if (g)
			FreeVec(g);
		G = NULL;
		reply(pkt, DOSFALSE, ERROR_NO_FREE_STORE);
		return 0;
	}
	g->n2 = g->n1 + 256;
	g->proc = (struct Process *)FindTask(NULL);
	g->port = &g->proc->pr_MsgPort;
	g->dn = (struct DeviceNode *)BADDR(pkt->dp_Arg3);
	g->tz = ln_tz_minutes();
	g->bpb = 512;
	g->mounted = ln_time_unix();
	if (g->dn)
		bstr(g->dn->dn_Name, g->device, sizeof(g->device));
	r = find_share(pkt->dp_Arg2);
	if (r == LN_OK && ln_log_level > 0) {
		ln_snprintf(g->logname, sizeof(g->logname), "T:lagoon-%s.log", g->share.name[0] ? g->share.name : g->device);
		ln_log_file = g->logname;
	}
	LN_LOG(1, "lagoon-handler starting for %s: (%s)", g->device, g->share.url);
	if (r == LN_OK)
		r = ln_net_init();
	if (r == LN_OK) {
		cr = ln_alloc(sizeof(LnCreds));
		if (!cr)
			r = LN_ENOMEM;
		else {
			ln_strlcpy(cr->user, g->share.user, sizeof(cr->user));
			ln_strlcpy(cr->domain, g->share.domain, sizeof(cr->domain));
			ln_strlcpy(cr->password, g->share.password, sizeof(cr->password));
			r = ln_vfs_mount_url(g->share.url, cr, &g->ops, &g->fs);
			ln_wipe(cr, sizeof(*cr));
			ln_free(cr);
		}
	}
	if (r != LN_OK) {
		LN_LOG(0, "mount of %s failed: %s", g->share.url, ln_strerror(r));
		if (g->mi)
			g->mi->error = r;
		ln_net_exit();
		ln_wipe(&g->share, sizeof(g->share));
		ln_free(g->n1);
		if (g->dn)
			g->dn->dn_Task = NULL;
		reply(pkt, DOSFALSE, doserr(r, CTX_START));
		FreeVec(g);
		G = NULL;
		return 0;
	}
	if (g->mi)
		g->mi->error = 0;
	g->cfg_readonly = g->share.readonly;
	hc_init(&g->hc, g->ops, g->fs, g->share.readonly);
	g->hc.sleep_ms = sleep_ms;
	{
		LnStatFs sf;
		if (hc_statfs(&g->hc, &sf) == LN_OK && sf.block_size >= 512 && sf.block_size <= 65536)
			g->bpb = sf.block_size;
	}
	/* the volume: label from the config, else the share name */
	vn = g->n2;
	ln_strlcpy(vn, g->share.volume[0] ? g->share.volume : g->share.name[0] ? g->share.name : g->device, VOLNAME_MAX + 1);
	for (p = vn; *p; p++)
		if (*p == ':' || *p == '/')
			*p = '_';
	if (g->dn)
		g->dn->dn_Task = g->port;
	reply(pkt, DOSTRUE, 0);
	/* after replying: DOS may hold the DOS list while it waits for us */
	add_volume(vn);
	timer_open();
	LN_LOG(1, "mounted %s as %s: (volume %s:)", g->share.url, g->device, vn);
	return 1;
}

static void shutdown(void)
{
	struct DosPacket *die = G->die;
	Handler *g = G;
	struct Message *m;
	LN_LOG(1, "unmounting %s:", g->device);
	timer_close();
	hc_free(&g->hc);
	g->ops->unmount(g->fs);
	ln_net_exit();
	remove_volume();
	ln_wipe(&g->share, sizeof(g->share));
	ln_free(g->n1);
	ln_log_file = NULL;
	CloseLibrary(UtilityBase);
	Forbid();
	if (g->dn)
		g->dn->dn_Task = NULL;
	G = NULL;
	FreeVec(g);
	/* packets that arrived meanwhile: the device is gone */
	while ((m = GetMsg(&((struct Process *)FindTask(NULL))->pr_MsgPort)) != NULL)
		reply((struct DosPacket *)m->mn_Node.ln_Name, DOSFALSE, ERROR_DEVICE_NOT_MOUNTED);
	if (die)
		reply(die, DOSTRUE, 0);
	CloseLibrary((struct Library *)DOSBase);
	/* returning ends the process; Forbid() keeps DOS from unloading our
	 * code before we are gone */
}

/* ------------------------------------------------------------ packets -- */

static void status(struct DosPacket *p)
{
	LnStatus *st = (LnStatus *)p->dp_Arg1;
	if (!st || p->dp_Arg2 != (LONG)sizeof(LnStatus)) {
		reply(p, DOSFALSE, ERROR_BAD_NUMBER);
		return;
	}
	memset(st, 0, sizeof(*st));
	st->magic = LN_STATUS_MAGIC;
	st->size = sizeof(*st);
	ln_strlcpy(st->device, G->device, sizeof(st->device));
	if (G->volname)
		ln_strlcpy(st->volume, (const char *)G->volname + 1, sizeof(st->volume));
	ln_strlcpy(st->share, G->share.name, sizeof(st->share));
	ln_strlcpy(st->url, G->share.url, sizeof(st->url));
	ln_strlcpy(st->backend, G->ops->name, sizeof(st->backend));
	st->online = !G->hc.offline;
	st->readonly = G->hc.readonly;
	st->locks = (u32)G->hc.nlocks;
	st->files = (u32)G->hc.nfiles;
	st->reconnects = G->hc.reconnects;
	st->mounted = G->mounted;
	st->bytes_read = G->hc.bytes_read;
	st->bytes_written = G->hc.bytes_written;
	reply(p, DOSTRUE, 0);
}

#define LOCK_ARG(arg, var) \
	if (!get_lock((arg), &(var))) { reply(p, DOSFALSE, ERROR_INVALID_LOCK); return; }
#define FILE_ARG(arg, var) \
	if (!((var) = get_file(arg))) { reply(p, DOSFALSE, ERROR_OBJECT_WRONG_TYPE); return; }

static void open_file(struct DosPacket *p, int mode)
{
	struct FileHandle *fh = (struct FileHandle *)BADDR(p->dp_Arg1);
	HLock *base;
	HFile *f;
	AFile *a;
	int r;
	LOCK_ARG(p->dp_Arg2, base);
	r = hc_open(&G->hc, base, bstr(p->dp_Arg3, G->n1, 256), mode, &f);
	if (r != LN_OK) {
		reply(p, DOSFALSE, doserr(r, mode == HC_OLD ? CTX_READ : CTX_WRITE));
		return;
	}
	a = AllocVec(sizeof(AFile), MEMF_PUBLIC | MEMF_CLEAR);
	if (!a) {
		hc_close(&G->hc, f);
		reply(p, DOSFALSE, ERROR_NO_FREE_STORE);
		return;
	}
	a->magic = AFILE_MAGIC;
	a->f = f;
	fh->fh_Arg1 = (LONG)a;
	fh->fh_Port = NULL;            /* not interactive */
	reply(p, DOSTRUE, 0);
}

static void dispatch(struct DosPacket *p)
{
	HC *h = &G->hc;
	HLock *l, *l2, *nl;
	HFile *f;
	LnStat st;
	LONG err = 0;
	int r;
	u64 v;

	switch (p->dp_Type) {
	case ACTION_LOCATE_OBJECT:
		LOCK_ARG(p->dp_Arg1, l);
		r = hc_lock(h, l, bstr(p->dp_Arg2, G->n1, 256), p->dp_Arg3 == EXCLUSIVE_LOCK, &nl);
		if (r) {
			reply(p, DOSFALSE, doserr(r, CTX_READ));
			return;
		}
		{
			BPTR b = mk_lock(nl, &err);
			reply(p, (LONG)b, err);
		}
		return;
	case ACTION_FREE_LOCK:
		LOCK_ARG(p->dp_Arg1, l);
		if (l) {
			ALock *a = (ALock *)BADDR(p->dp_Arg1);
			hc_unlock(h, l);
			free_alock(a);
		}
		reply(p, DOSTRUE, 0);
		return;
	case ACTION_COPY_DIR:
	case ACTION_PARENT:
		LOCK_ARG(p->dp_Arg1, l);
		r = p->dp_Type == ACTION_COPY_DIR ? hc_duplock(h, l, &nl) : hc_parent(h, l, &nl);
		if (r) {
			reply(p, DOSFALSE, doserr(r, CTX_READ));
			return;
		}
		if (!nl) {
			reply(p, 0, 0);       /* parent of the root */
			return;
		}
		{
			BPTR b = mk_lock(nl, &err);
			reply(p, (LONG)b, err);
		}
		return;
	case ACTION_COPY_DIR_FH:
	case ACTION_PARENT_FH:
		FILE_ARG(p->dp_Arg1, f);
		r = p->dp_Type == ACTION_COPY_DIR_FH ? hc_lock_file(h, f, &nl) : hc_parent_file(h, f, &nl);
		if (r) {
			reply(p, DOSFALSE, doserr(r, CTX_READ));
			return;
		}
		if (!nl) {
			reply(p, 0, 0);
			return;
		}
		{
			BPTR b = mk_lock(nl, &err);
			reply(p, (LONG)b, err);
		}
		return;
	case ACTION_SAME_LOCK:
		LOCK_ARG(p->dp_Arg1, l);
		LOCK_ARG(p->dp_Arg2, l2);
		reply(p, hc_same_lock(l, l2) ? DOSTRUE : DOSFALSE, 0);
		return;
	case ACTION_EXAMINE_OBJECT: {
		struct FileInfoBlock *fib = (struct FileInfoBlock *)BADDR(p->dp_Arg2);
		LOCK_ARG(p->dp_Arg1, l);
		r = hc_stat_lock(h, l, &st);
		if (r) {
			reply(p, DOSFALSE, doserr(r, CTX_READ));
			return;
		}
		lock_name(l, G->n1);
		/* directories: fib_DiskKey 0 starts ExNext */
		fib_from_stat(fib, st.type == LN_T_DIR ? 0 : (LONG)(l ? l->key : 1), G->n1, !l || !l->rpath[0], &st);
		reply(p, DOSTRUE, 0);
		return;
	}
	case ACTION_EXAMINE_NEXT: {
		struct FileInfoBlock *fib = (struct FileInfoBlock *)BADDR(p->dp_Arg2);
		const HEnt *e;
		u32 idx = (u32)fib->fib_DiskKey;
		HLock *tmp = NULL;
		LOCK_ARG(p->dp_Arg1, l);
		if (!l) {
			/* ExNext() on the root given as lock 0 */
			if ((r = hc_duplock(h, NULL, &tmp)) != LN_OK) {
				reply(p, DOSFALSE, doserr(r, CTX_READ));
				return;
			}
			l = tmp;
		}
		r = hc_next(h, l, &idx, &e);
		if (r > 0) {
			fill_fib(fib, (LONG)idx, e->aname, 0, e->type, e->size, e->mtime, e->prot, e->comment, e->uid, e->gid);
			reply(p, DOSTRUE, 0);
		} else
			reply(p, DOSFALSE, r == 0 ? ERROR_NO_MORE_ENTRIES : doserr(r, CTX_READ));
		if (tmp)
			hc_unlock(h, tmp);
		return;
	}
	case ACTION_EXAMINE_ALL:
		examine_all(p);
		return;
	case ACTION_EXAMINE_ALL_END:
		LOCK_ARG(p->dp_Arg1, l);
		hc_end_scan(h, l);
		reply(p, DOSTRUE, 0);
		return;
	case ACTION_EXAMINE_FH: {
		struct FileInfoBlock *fib = (struct FileInfoBlock *)BADDR(p->dp_Arg2);
		FILE_ARG(p->dp_Arg1, f);
		r = hc_stat_file(h, f, &st);
		if (r) {
			reply(p, DOSFALSE, doserr(r, CTX_READ));
			return;
		}
		hc_amiga_name(ln_path_base(f->rpath), G->n1);
		fib_from_stat(fib, (LONG)f->key, G->n1, 0, &st);
		reply(p, DOSTRUE, 0);
		return;
	}
	case ACTION_FINDINPUT:
		open_file(p, HC_OLD);
		return;
	case ACTION_FINDOUTPUT:
		open_file(p, HC_NEW);
		return;
	case ACTION_FINDUPDATE:
		open_file(p, HC_RW);
		return;
	case ACTION_FH_FROM_LOCK: {
		struct FileHandle *fh = (struct FileHandle *)BADDR(p->dp_Arg1);
		ALock *al = (ALock *)BADDR(p->dp_Arg2);
		AFile *a;
		LOCK_ARG(p->dp_Arg2, l);
		if (!l) {
			reply(p, DOSFALSE, ERROR_OBJECT_WRONG_TYPE);
			return;
		}
		a = AllocVec(sizeof(AFile), MEMF_PUBLIC | MEMF_CLEAR);
		if (!a) {
			reply(p, DOSFALSE, ERROR_NO_FREE_STORE);
			return;
		}
		r = hc_open_lock(h, l, &f);
		if (r) {
			FreeVec(a);
			reply(p, DOSFALSE, doserr(r, CTX_READ));
			return;
		}
		free_alock(al);          /* the lock now belongs to the file */
		a->magic = AFILE_MAGIC;
		a->f = f;
		fh->fh_Arg1 = (LONG)a;
		fh->fh_Port = NULL;
		reply(p, DOSTRUE, 0);
		return;
	}
	case ACTION_READ: {
		long n;
		FILE_ARG(p->dp_Arg1, f);
		n = hc_read(h, f, (void *)p->dp_Arg2, p->dp_Arg3);
		reply(p, n < 0 ? -1 : (LONG)n, n < 0 ? doserr((int)n, CTX_READ) : 0);
		return;
	}
	case ACTION_WRITE: {
		long n;
		FILE_ARG(p->dp_Arg1, f);
		n = hc_write(h, f, (const void *)p->dp_Arg2, p->dp_Arg3);
		reply(p, n < 0 ? -1 : (LONG)n, n < 0 ? doserr((int)n, CTX_WRITE) : 0);
		return;
	}
	case ACTION_SEEK:
		FILE_ARG(p->dp_Arg1, f);
		r = hc_seek(h, f, (s64)p->dp_Arg2, (int)p->dp_Arg3, &v);
		if (r)
			reply(p, -1, r == LN_EINVAL ? ERROR_SEEK_ERROR : doserr(r, CTX_READ));
		else
			reply(p, clamp32(v), 0);
		return;
	case ACTION_SET_FILE_SIZE:
		FILE_ARG(p->dp_Arg1, f);
		r = hc_set_size(h, f, (s64)p->dp_Arg2, (int)p->dp_Arg3, &v);
		if (r)
			reply(p, -1, r == LN_EINVAL ? ERROR_SEEK_ERROR : doserr(r, CTX_WRITE));
		else
			reply(p, clamp32(v), 0);
		return;
	case ACTION_END: {
		AFile *a = (AFile *)p->dp_Arg1;
		FILE_ARG(p->dp_Arg1, f);
		r = hc_close(h, f);
		a->magic = 0;
		FreeVec(a);
		reply(p, r ? DOSFALSE : DOSTRUE, doserr(r, CTX_WRITE));
		return;
	}
	case ACTION_CHANGE_MODE: {
		int excl = p->dp_Arg3 == EXCLUSIVE_LOCK;
		if (p->dp_Arg1 == CHANGE_FH) {
			struct FileHandle *fh = (struct FileHandle *)BADDR(p->dp_Arg2);
			FILE_ARG(fh ? fh->fh_Arg1 : 0, f);
			r = hc_change_file(h, f, excl);
		} else if (p->dp_Arg1 == CHANGE_LOCK) {
			LOCK_ARG(p->dp_Arg2, l);
			if (!l) {
				reply(p, DOSFALSE, ERROR_OBJECT_WRONG_TYPE);
				return;
			}
			r = hc_change_lock(h, l, excl);
			if (r == LN_OK)
				((ALock *)l->os)->fl.fl_Access = excl ? EXCLUSIVE_LOCK : SHARED_LOCK;
		} else {
			reply(p, DOSFALSE, ERROR_BAD_NUMBER);
			return;
		}
		reply(p, r ? DOSFALSE : DOSTRUE, doserr(r, CTX_GEN));
		return;
	}
	case ACTION_DELETE_OBJECT:
		LOCK_ARG(p->dp_Arg1, l);
		r = hc_delete(h, l, bstr(p->dp_Arg2, G->n1, 256));
		reply(p, r ? DOSFALSE : DOSTRUE, doserr(r, CTX_DELETE));
		return;
	case ACTION_RENAME_OBJECT:
		LOCK_ARG(p->dp_Arg1, l);
		LOCK_ARG(p->dp_Arg3, l2);
		r = hc_rename(h, l, bstr(p->dp_Arg2, G->n1, 256), l2, bstr(p->dp_Arg4, G->n2, 256));
		reply(p, r ? DOSFALSE : DOSTRUE, doserr(r, CTX_WRITE));
		return;
	case ACTION_CREATE_DIR:
		LOCK_ARG(p->dp_Arg1, l);
		r = hc_mkdir(h, l, bstr(p->dp_Arg2, G->n1, 256), &nl);
		if (r) {
			reply(p, DOSFALSE, doserr(r, CTX_WRITE));
			return;
		}
		{
			BPTR b = mk_lock(nl, &err);
			reply(p, (LONG)b, err);
		}
		return;
	case ACTION_SET_PROTECT:
	case ACTION_SET_COMMENT:
	case ACTION_SET_DATE: {
		u32 mask;
		LOCK_ARG(p->dp_Arg2, l);
		memset(&st, 0, sizeof(st));
		if (p->dp_Type == ACTION_SET_PROTECT) {
			st.prot = fib_to_prot(p->dp_Arg4);
			mask = LN_SET_PROT;
		} else if (p->dp_Type == ACTION_SET_COMMENT) {
			hc_latin1_to_utf8(bstr(p->dp_Arg4, G->n2, 256), st.comment, sizeof(st.comment));
			mask = LN_SET_COMMENT;
		} else {
			st.mtime = from_ds((const struct DateStamp *)p->dp_Arg4);
			mask = LN_SET_MTIME;
		}
		r = hc_setattr(h, l, bstr(p->dp_Arg3, G->n1, 256), &st, mask);
		reply(p, r ? DOSFALSE : DOSTRUE, doserr(r, CTX_WRITE));
		return;
	}
	case ACTION_INFO:
		LOCK_ARG(p->dp_Arg1, l);
		info((struct InfoData *)BADDR(p->dp_Arg2));
		reply(p, DOSTRUE, 0);
		return;
	case ACTION_DISK_INFO:
		info((struct InfoData *)BADDR(p->dp_Arg1));
		reply(p, DOSTRUE, 0);
		return;
	case ACTION_CURRENT_VOLUME:
		reply(p, (LONG)MKBADDR(G->vol), 0);
		return;
	case ACTION_RENAME_DISK:
		bstr(p->dp_Arg1, G->n1, 256);
		if (!G->n1[0] || strchr(G->n1, ':') || strchr(G->n1, '/') || !G->vol) {
			reply(p, DOSFALSE, ERROR_INVALID_COMPONENT_NAME);
			return;
		}
		LockDosList(LDF_VOLUMES | LDF_WRITE);
		set_bstr(G->volname, G->n1, VOLNAME_MAX);
		UnLockDosList(LDF_VOLUMES | LDF_WRITE);
		reply(p, DOSTRUE, 0);
		return;
	case ACTION_WRITE_PROTECT:
		if (p->dp_Arg1) {
			if (!h->readonly)
				G->wp_key = p->dp_Arg2;
			h->readonly = 1;
		} else {
			if (h->readonly && G->wp_key && G->wp_key != p->dp_Arg2) {
				reply(p, DOSFALSE, ERROR_INVALID_COMPONENT_NAME);
				return;
			}
			h->readonly = 0;
			G->wp_key = 0;
		}
		reply(p, DOSTRUE, 0);
		return;
	case ACTION_FLUSH:
		hc_flush_all(h);
		reply(p, DOSTRUE, 0);
		return;
	case ACTION_IS_FILESYSTEM:
	case ACTION_INHIBIT:
		reply(p, DOSTRUE, 0);
		return;
	case ACTION_DIE:
		if (h->nlocks || h->nfiles) {
			reply(p, DOSFALSE, ERROR_OBJECT_IN_USE);
			return;
		}
		G->quit = 1;
		G->die = p;              /* replied by shutdown() */
		return;
	case ACTION_LAGOON_STATUS:
		status(p);
		return;
	case ACTION_LOCK_RECORD:
	case ACTION_FREE_RECORD:
	default:
		reply(p, DOSFALSE, ERROR_ACTION_NOT_KNOWN);
		return;
	}
}

static void serve(void)
{
	ULONG psig = 1UL << G->port->mp_SigBit;
	timer_start();
	while (!G->quit) {
		ULONG tsig = G->tport ? 1UL << G->tport->mp_SigBit : 0;
		ULONG sig = Wait(psig | tsig | SIGBREAKF_CTRL_C);
		struct Message *m;
		if (sig & SIGBREAKF_CTRL_C) {
			if (!G->hc.nlocks && !G->hc.nfiles) {
				LN_LOG(1, "Ctrl-C: quitting");
				G->quit = 1;
				break;
			}
			LN_LOG(1, "Ctrl-C ignored: %d locks and %d files are open", G->hc.nlocks, G->hc.nfiles);
		}
		while (!G->quit && (m = GetMsg(G->port)) != NULL)
			dispatch((struct DosPacket *)m->mn_Node.ln_Name);
		if (G->tport && GetMsg(G->tport)) {
			G->timer_on = 0;
			hc_idle(&G->hc);
		}
		timer_start();
	}
}
