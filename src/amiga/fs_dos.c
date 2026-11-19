/*
 * Lagoon - "dos" backend: an Amiga folder (any path: "Work:", "DH0:Projects",
 * an assign) behind the LnOps interface, for the SMB server (`Lagoon SERVE`).
 * dos.library only (V37): Lock/Examine/ExNext, Open/Read/Write/Seek,
 * SetFileSize, Rename, DeleteFile, CreateDir, SetProtection, SetFileDate,
 * Info. Names are ISO-8859-1 on the Amiga and UTF-8 in the core (a name
 * with characters outside Latin-1 cannot be created: LN_EINVAL). Amiga
 * dates are local time from 1978; protection bits RWED are inverted.
 * The host equivalent is src/host/fs_posix.c.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <exec/types.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "../core/ln_vfs.h"
#include "../core/ln_sys.h"
#include "../core/ln_charset.h"
#include "fs_dos.h"

#define APATH 512

struct LnFs {
	char root[256];
	int  ro;
	int  tz;                 /* minutes east of UTC */
};
struct LnFile {
	BPTR fh;
	LONG pos;                /* -1 = unknown */
	LnFs *fs;
};
struct LnDir {
	BPTR lock;
	struct FileInfoBlock *fib;
	LnFs *fs;
};

static int map(LONG e)
{
	switch (e) {
	case ERROR_OBJECT_NOT_FOUND: case ERROR_DIR_NOT_FOUND: return LN_ENOENT;
	case ERROR_OBJECT_EXISTS: return LN_EEXIST;
	case ERROR_OBJECT_WRONG_TYPE: return LN_ENOTDIR;
	case ERROR_DIRECTORY_NOT_EMPTY: return LN_ENOTEMPTY;
	case ERROR_DELETE_PROTECTED: case ERROR_WRITE_PROTECTED: case ERROR_READ_PROTECTED: return LN_EACCES;
	case ERROR_DISK_WRITE_PROTECTED: return LN_EROFS;
	case ERROR_DISK_FULL: return LN_ENOSPC;
	case ERROR_OBJECT_IN_USE: return LN_EINUSE;
	case ERROR_INVALID_COMPONENT_NAME: case ERROR_BAD_STREAM_NAME: return LN_EINVAL;
	case ERROR_LINE_TOO_LONG: return LN_ENAMETOOLONG;
	case ERROR_NO_FREE_STORE: return LN_ENOMEM;
	case ERROR_DEVICE_NOT_MOUNTED: case ERROR_NO_DISK: case ERROR_NOT_A_DOS_DISK: return LN_ENOSHARE;
	case ERROR_ACTION_NOT_KNOWN: return LN_ENOTSUP;
	}
	return LN_EIO;
}

/* root + UTF-8 relative path -> Amiga path */
static int apath(LnFs *fs, const char *path, char *out, size_t n)
{
	size_t l;
	char comp[256];
	ln_strlcpy(out, fs->root, n);
	while (*path) {
		const char *e = strchr(path, '/');
		size_t cl = e ? (size_t)(e - path) : strlen(path);
		char u[256];
		if (cl >= sizeof(u))
			return LN_ENAMETOOLONG;
		memcpy(u, path, cl);
		u[cl] = 0;
		if (ln_utf8_to_latin1(u, comp, sizeof(comp)) < 0)
			return LN_EINVAL;
		l = strlen(out);
		if (l && out[l - 1] != ':' && out[l - 1] != '/')
			ln_strlcat(out, "/", n);
		if (ln_strlcat(out, comp, n) >= n)
			return LN_ENAMETOOLONG;
		path += cl;
		if (*path == '/')
			path++;
	}
	return LN_OK;
}

static u32 to_unix(LnFs *fs, const struct DateStamp *d)
{
	return (u32)(252460800UL + (u32)d->ds_Days * 86400UL + (u32)d->ds_Minute * 60UL + (u32)d->ds_Tick / 50UL)
	       - (u32)(fs->tz * 60);
}

static void to_ds(LnFs *fs, u32 t, struct DateStamp *d)
{
	u32 a = t + (u32)(fs->tz * 60);
	a = a > 252460800UL ? a - 252460800UL : 0;
	d->ds_Days = (LONG)(a / 86400UL);
	d->ds_Minute = (LONG)((a % 86400UL) / 60UL);
	d->ds_Tick = (LONG)((a % 60UL) * 50UL);
}

static void fill(LnFs *fs, const struct FileInfoBlock *fib, LnStat *st)
{
	LONG p = fib->fib_Protection;
	memset(st, 0, sizeof(*st));
	st->type = fib->fib_DirEntryType > 0 ? LN_T_DIR : LN_T_FILE;
	st->size = st->type == LN_T_FILE ? (u64)(ULONG)fib->fib_Size : 0;
	st->mtime = st->ctime = to_unix(fs, &fib->fib_Date);
	if (!(p & FIBF_READ)) st->prot |= LN_P_READ;
	if (!(p & FIBF_WRITE)) st->prot |= LN_P_WRITE;
	if (!(p & FIBF_EXECUTE)) st->prot |= LN_P_EXEC;
	if (!(p & FIBF_DELETE)) st->prot |= LN_P_DELETE;
	if (p & FIBF_ARCHIVE) st->prot |= LN_P_ARCHIVE;
	if (p & FIBF_SCRIPT) st->prot |= LN_P_SCRIPT;
	if (p & FIBF_PURE) st->prot |= LN_P_PURE;
	st->fileid = (u64)(ULONG)fib->fib_DiskKey;
	{
		/* the file note (UTF-8) */
		char c[80];
		c[0] = 0;
		ln_latin1_to_utf8((const char *)fib->fib_Comment, c, sizeof(c));
		ln_strlcpy(st->comment, c, sizeof(st->comment));
	}
}

static LONG from_ln(u32 prot, LONG keep)
{
	LONG p = keep & ~(LONG)(FIBF_READ | FIBF_WRITE | FIBF_EXECUTE | FIBF_DELETE | FIBF_ARCHIVE | FIBF_SCRIPT | FIBF_PURE);
	if (!(prot & LN_P_READ)) p |= FIBF_READ;
	if (!(prot & LN_P_WRITE)) p |= FIBF_WRITE;
	if (!(prot & LN_P_EXEC)) p |= FIBF_EXECUTE;
	if (!(prot & LN_P_DELETE)) p |= FIBF_DELETE;
	if (prot & LN_P_ARCHIVE) p |= FIBF_ARCHIVE;
	if (prot & LN_P_SCRIPT) p |= FIBF_SCRIPT;
	if (prot & LN_P_PURE) p |= FIBF_PURE;
	return p;
}

/* Examine an Amiga path: LN_OK with st, or an error */
static int examine(LnFs *fs, const char *ap, LnStat *st)
{
	BPTR l = Lock((STRPTR)ap, SHARED_LOCK);
	struct FileInfoBlock *fib;
	int r = LN_OK;
	if (!l)
		return map(IoErr());
	fib = AllocDosObject(DOS_FIB, NULL);
	if (!fib)
		r = LN_ENOMEM;
	else if (!Examine(l, fib))
		r = map(IoErr());
	else if (st)
		fill(fs, fib, st);
	if (fib)
		FreeDosObject(DOS_FIB, fib);
	UnLock(l);
	return r;
}

int ln_dosfs_open(const char *root, int readonly, LnFs **out)
{
	LnFs *fs;
	LnStat st;
	int r;
	fs = ln_alloc(sizeof(LnFs));
	if (!fs)
		return LN_ENOMEM;
	ln_strlcpy(fs->root, root, sizeof(fs->root));
	fs->ro = readonly;
	fs->tz = ln_tz_minutes();
	r = examine(fs, fs->root, &st);
	if (r == LN_OK && st.type != LN_T_DIR)
		r = LN_ENOTDIR;
	if (r) {
		ln_free(fs);
		return r == LN_ENOENT ? LN_ENOSHARE : r;
	}
	*out = fs;
	return LN_OK;
}

static int d_mount(const LnUrl *url, const LnCreds *cr, LnFs **out)
{
	(void)url; (void)cr; (void)out;
	return LN_ENOTSUP;          /* opened with ln_dosfs_open */
}

static void d_unmount(LnFs *fs) { ln_free(fs); }
static int d_reconnect(LnFs *fs) { (void)fs; return LN_OK; }
static int d_ping(LnFs *fs) { (void)fs; return LN_OK; }

static int d_statfs(LnFs *fs, LnStatFs *st)
{
	BPTR l = Lock((STRPTR)fs->root, SHARED_LOCK);
	struct InfoData *id;
	int r = LN_OK;
	memset(st, 0, sizeof(*st));
	if (!l)
		return map(IoErr());
	id = AllocVec(sizeof(struct InfoData), MEMF_ANY | MEMF_CLEAR);
	if (!id)
		r = LN_ENOMEM;
	else if (!Info(l, id))
		r = map(IoErr());
	else {
		u64 bpb = (u64)(ULONG)id->id_BytesPerBlock;
		st->block_size = (u32)bpb;
		st->total_bytes = (u64)(ULONG)id->id_NumBlocks * bpb;
		st->free_bytes = id->id_NumBlocks > id->id_NumBlocksUsed ?
		                 (u64)(ULONG)(id->id_NumBlocks - id->id_NumBlocksUsed) * bpb : 0;
		st->readonly = fs->ro || id->id_DiskState == ID_WRITE_PROTECTED;
		if (id->id_VolumeNode) {
			struct DeviceList *dl = (struct DeviceList *)BADDR(id->id_VolumeNode);
			const UBYTE *b = (const UBYTE *)BADDR(dl->dl_Name);
			if (b) {
				char v[40];
				int k = b[0] < sizeof(v) ? b[0] : (int)sizeof(v) - 1;
				memcpy(v, b + 1, (size_t)k);
				v[k] = 0;
				ln_latin1_to_utf8(v, st->volume, sizeof(st->volume));
			}
		}
	}
	if (id)
		FreeVec(id);
	UnLock(l);
	return r;
}

static int d_stat(LnFs *fs, const char *path, LnStat *st)
{
	char ap[APATH];
	int r = apath(fs, path, ap, sizeof(ap));
	return r ? (r == LN_EINVAL ? LN_ENOENT : r) : examine(fs, ap, st);
}

static int d_opendir(LnFs *fs, const char *path, LnDir **out)
{
	char ap[APATH];
	LnDir *d;
	int r = apath(fs, path, ap, sizeof(ap));
	if (r)
		return r == LN_EINVAL ? LN_ENOENT : r;
	d = ln_alloc(sizeof(LnDir));
	if (!d)
		return LN_ENOMEM;
	d->fs = fs;
	d->fib = AllocDosObject(DOS_FIB, NULL);
	d->lock = Lock((STRPTR)ap, SHARED_LOCK);
	if (!d->fib || !d->lock || !Examine(d->lock, d->fib) || d->fib->fib_DirEntryType <= 0) {
		r = !d->fib ? LN_ENOMEM : !d->lock ? map(IoErr()) : d->fib->fib_DirEntryType <= 0 ? LN_ENOTDIR : map(IoErr());
		if (d->lock) UnLock(d->lock);
		if (d->fib) FreeDosObject(DOS_FIB, d->fib);
		ln_free(d);
		return r;
	}
	*out = d;
	return LN_OK;
}

static int d_readdir(LnDir *d, char *name, size_t n, LnStat *st)
{
	while (ExNext(d->lock, d->fib)) {
		if (ln_latin1_to_utf8((const char *)d->fib->fib_FileName, name, n) < 0)
			continue;
		fill(d->fs, d->fib, st);
		return 1;
	}
	return IoErr() == ERROR_NO_MORE_ENTRIES ? 0 : map(IoErr());
}

static void d_closedir(LnDir *d)
{
	UnLock(d->lock);
	FreeDosObject(DOS_FIB, d->fib);
	ln_free(d);
}

static int d_open(LnFs *fs, const char *path, int flags, LnFile **out)
{
	char ap[APATH];
	LnStat st;
	int r, exists;
	LONG mode;
	BPTR fh;
	if (fs->ro && (flags & (LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC)))
		return LN_EROFS;
	if ((r = apath(fs, path, ap, sizeof(ap))) != LN_OK)
		return r == LN_EINVAL && !(flags & LN_O_CREATE) ? LN_ENOENT : r;
	r = examine(fs, ap, &st);
	if (r != LN_OK && r != LN_ENOENT)
		return r;
	exists = r == LN_OK;
	if (exists && st.type == LN_T_DIR)
		return LN_EISDIR;
	if (exists && (flags & LN_O_EXCL) && (flags & LN_O_CREATE))
		return LN_EEXIST;
	if (!exists && !(flags & LN_O_CREATE))
		return LN_ENOENT;
	if (!exists)
		mode = MODE_NEWFILE;
	else
		mode = (flags & (LN_O_WRITE | LN_O_TRUNC)) ? MODE_READWRITE : MODE_OLDFILE;
	fh = Open((STRPTR)ap, mode);
	if (!fh)
		return map(IoErr());
	if (exists && (flags & LN_O_TRUNC) && SetFileSize(fh, 0, OFFSET_BEGINNING) < 0) {
		r = map(IoErr());
		Close(fh);
		return r;
	}
	*out = ln_alloc(sizeof(LnFile));
	if (!*out) {
		Close(fh);
		return LN_ENOMEM;
	}
	(*out)->fh = fh;
	(*out)->pos = 0;
	(*out)->fs = fs;
	return LN_OK;
}

static int seek_to(LnFile *f, u64 off, int extend)
{
	LONG o = (LONG)off;
	if (off > 0x7fffffffUL)
		return LN_ENOSPC;
	if (f->pos == o)
		return LN_OK;
	if (Seek(f->fh, o, OFFSET_BEGINNING) < 0) {
		/* beyond the end: make the file longer first (writes only) */
		if (!extend || SetFileSize(f->fh, o, OFFSET_BEGINNING) < 0 || Seek(f->fh, o, OFFSET_BEGINNING) < 0) {
			f->pos = -1;
			return extend ? map(IoErr()) : LN_OK;
		}
	}
	f->pos = o;
	return LN_OK;
}

static long d_read(LnFile *f, u64 off, void *buf, long n)
{
	LONG r;
	if (seek_to(f, off, 0) != LN_OK || f->pos < 0)
		return 0;                   /* past the end */
	r = Read(f->fh, buf, n);
	if (r < 0) {
		f->pos = -1;
		return map(IoErr());
	}
	f->pos += r;
	return r;
}

static long d_write(LnFile *f, u64 off, const void *buf, long n)
{
	LONG r;
	int e = seek_to(f, off, 1);
	if (e)
		return e;
	r = Write(f->fh, (APTR)buf, n);
	if (r < 0) {
		f->pos = -1;
		return map(IoErr());
	}
	f->pos += r;
	return r;
}

static int d_fstat(LnFile *f, LnStat *st)
{
	struct FileInfoBlock *fib = AllocDosObject(DOS_FIB, NULL);
	int r = LN_OK;
	if (!fib)
		return LN_ENOMEM;
	if (!ExamineFH(f->fh, fib))
		r = map(IoErr());
	else
		fill(f->fs, fib, st);
	FreeDosObject(DOS_FIB, fib);
	return r;
}

static int d_truncate(LnFile *f, u64 size)
{
	if (size > 0x7fffffffUL)
		return LN_ENOSPC;
	f->pos = -1;
	return SetFileSize(f->fh, (LONG)size, OFFSET_BEGINNING) < 0 ? map(IoErr()) : LN_OK;
}

static int d_flush(LnFile *f) { (void)f; return LN_OK; }

static int d_close(LnFile *f)
{
	Close(f->fh);
	ln_free(f);
	return LN_OK;
}

static int d_mkdir(LnFs *fs, const char *path)
{
	char ap[APATH];
	BPTR l;
	int r;
	if (fs->ro) return LN_EROFS;
	if ((r = apath(fs, path, ap, sizeof(ap))) != LN_OK) return r;
	if ((l = Lock((STRPTR)ap, SHARED_LOCK)) != 0) {
		UnLock(l);
		return LN_EEXIST;
	}
	l = CreateDir((STRPTR)ap);
	if (!l)
		return map(IoErr());
	UnLock(l);
	return LN_OK;
}

static int d_remove(LnFs *fs, const char *path)
{
	char ap[APATH];
	int r;
	if (fs->ro) return LN_EROFS;
	if ((r = apath(fs, path, ap, sizeof(ap))) != LN_OK) return r == LN_EINVAL ? LN_ENOENT : r;
	return DeleteFile((STRPTR)ap) ? LN_OK : map(IoErr());
}

static int d_rename(LnFs *fs, const char *from, const char *to)
{
	char a[APATH], b[APATH];
	BPTR la, lb;
	int r;
	if (fs->ro) return LN_EROFS;
	if ((r = apath(fs, from, a, sizeof(a))) != LN_OK || (r = apath(fs, to, b, sizeof(b))) != LN_OK)
		return r;
	lb = Lock((STRPTR)b, SHARED_LOCK);
	if (lb) {
		/* the same object: a change of case only */
		int same = 0;
		la = Lock((STRPTR)a, SHARED_LOCK);
		if (la) {
			same = SameLock(la, lb) == LOCK_SAME;
			UnLock(la);
		}
		UnLock(lb);
		if (!same)
			return LN_EEXIST;
	}
	return Rename((STRPTR)a, (STRPTR)b) ? LN_OK : map(IoErr());
}

static int d_setattr(LnFs *fs, const char *path, const LnStat *st, u32 mask)
{
	char ap[APATH];
	int r;
	if (fs->ro) return LN_EROFS;
	if ((r = apath(fs, path, ap, sizeof(ap))) != LN_OK) return r;
	if (mask & LN_SET_MTIME) {
		struct DateStamp ds;
		to_ds(fs, st->mtime, &ds);
		if (!SetFileDate((STRPTR)ap, &ds))
			return map(IoErr());
	}
	if (mask & LN_SET_PROT) {
		BPTR l = Lock((STRPTR)ap, SHARED_LOCK);
		struct FileInfoBlock *fib = AllocDosObject(DOS_FIB, NULL);
		LONG keep = 0;
		if (l && fib && Examine(l, fib))
			keep = fib->fib_Protection;
		if (fib) FreeDosObject(DOS_FIB, fib);
		if (l) UnLock(l);
		if (!SetProtection((STRPTR)ap, from_ln(st->prot, keep)))
			return map(IoErr());
	}
	if (mask & LN_SET_COMMENT) {
		char c[80];
		if (ln_utf8_to_latin1(st->comment, c, sizeof(c)) < 0 || !SetComment((STRPTR)ap, (STRPTR)c))
			return map(IoErr());
	}
	return LN_OK;
}

static long d_max_io(LnFs *fs) { (void)fs; return 65536; }

const LnOps ln_dosfs_ops = {
	"dos", "Amiga folder", 0,
	d_mount, d_unmount, d_reconnect, d_ping,
	d_statfs, d_stat,
	d_opendir, d_readdir, d_closedir,
	d_open, d_read, d_write, d_fstat, d_truncate, d_flush, d_close,
	d_mkdir, d_remove, d_rename, d_setattr,
	NULL, d_max_io
};
