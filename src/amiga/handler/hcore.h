/*
 * Lagoon - the portable half of lagoon-handler: everything between DOS
 * packets and LnOps that does not touch the OS. Amiga path parsing and name
 * matching, DOS lock semantics (shared/exclusive per object), directory
 * snapshots for ExNext/ExAll, an attribute + directory cache with a short
 * TTL, read-ahead / write-behind file buffers, reconnect with back-off and
 * keep-alives. handler.c turns packets into these calls and maps the LN_E*
 * results to DOS ERROR_* codes; tests/t_hcore.c runs it natively against
 * the mem backend.
 *
 * Paths: "rpath" = remote UTF-8 path relative to the share root as LnOps
 * wants it ("" = root); "apath" = Amiga path as DOS sends it ("VOL:a/b",
 * ":a", "/a", "a//b"), in ISO-8859-1. All calls return LN_OK / a count or a
 * negative LN_E* code; lock conflicts are LN_EINUSE, a missing object is
 * LN_ENOENT, a file where a directory is needed LN_ENOTDIR and vice versa
 * LN_EISDIR, a write on a write-protected mount LN_EROFS.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef HCORE_H
#define HCORE_H

#include "ln_vfs.h"

#define HC_PATHMAX  1024        /* remote paths, UTF-8 */
#define HC_NAMEMAX  107         /* FileInfoBlock fib_FileName (BSTR) */
#define HC_NLISTS   4           /* cached directory listings */
#define HC_NATTR    16          /* cached attributes */

/* a directory entry in a listing */
typedef struct HEnt {
	char *aname;                /* Amiga name shown (Latin-1, <= 107 bytes, unique case-insensitively) */
	char *rname;                /* remote name */
	char *comment;              /* NULL if none (UTF-8) */
	int   type;
	u64   size;
	u32   mtime, ctime, prot, uid, gid;
	u64   fileid;
} HEnt;

typedef struct HPool HPool;

/* a directory listing: cached, and referenced by locks as their
 * ExNext/ExAll snapshot (so iteration is stable while the cache moves on) */
typedef struct HList {
	int    refs;
	u32    stamp;               /* ln_ms() when read */
	char  *dir;                 /* rpath */
	int    n, cap;
	HEnt  *e;
	int   *hash;                /* fold-hash index into e, -1 = empty */
	int    hsize;
	HPool *pool;
} HList;

typedef struct HLock {
	struct HLock *next;
	char  *rpath;
	int    excl;                /* exclusive (ACCESS_WRITE) */
	int    type;                /* LN_T_FILE / LN_T_DIR */
	u32    key;                 /* fl_Key: fileid or a hash of the path */
	HList *snap;                /* ExNext / ExAll snapshot (or NULL) */
	void  *os;                  /* handler's FileLock */
} HLock;

typedef struct HFile {
	struct HFile *next;
	char  *rpath;
	int    excl;
	int    oflags;              /* LN_O_READ/WRITE the file was opened with */
	LnFile *lf;
	u64    pos, size;
	u8    *buf;                 /* read-ahead or write-behind buffer */
	u64    boff;                /* file offset of buf[0] */
	long   blen;                /* valid bytes in buf */
	int    dirty;               /* buf holds unwritten data */
	int    err;                 /* sticky error of a delayed write */
	u32    key;
} HFile;

typedef struct HAttrCache {
	char  *path;
	LnStat st;
	u32    stamp;
} HAttrCache;

typedef struct HC {
	const LnOps *ops;
	LnFs  *fs;
	int    readonly;            /* local write protection (config / ACTION_WRITE_PROTECT) */
	long   maxio;               /* backend request size */
	long   bufsize;             /* per-file buffer */
	HLock *locks;
	HFile *files;
	int    nlocks, nfiles;
	HList *lists[HC_NLISTS];
	HAttrCache attr[HC_NATTR];
	int    attr_next;
	LnStatFs sfs;
	u32    sfs_stamp;
	int    sfs_valid;
	u32    ttl_ms;              /* cache lifetime (default 3000) */
	/* connection state */
	int    offline;             /* reconnect gave up; retried every retry_ms */
	u32    last_try;
	u32    last_net;            /* last successful server traffic (for keep-alives) */
	u32    last_io;             /* last client request (for idle flushing) */
	u32    reconnect_ms;        /* give up after this long (default 30000) */
	u32    retry_ms;            /* while offline, try again at most this often (default 10000) */
	u32    ping_ms;             /* keep-alive interval (default 60000) */
	void (*sleep_ms)(u32 ms);   /* back-off wait (Delay() on the Amiga) */
	/* statistics for Lagoon STATUS */
	u32    reconnects;
	u64    bytes_read, bytes_written;
} HC;

/* open modes (DOS MODE_OLDFILE / MODE_NEWFILE / MODE_READWRITE) */
enum { HC_OLD = 1, HC_NEW = 2, HC_RW = 3 };
/* seek modes (DOS OFFSET_BEGINNING / CURRENT / END) */
enum { HC_SEEK_SET = -1, HC_SEEK_CUR = 0, HC_SEEK_END = 1 };

int  hc_init(HC *h, const LnOps *ops, LnFs *fs, int readonly);
/* releases files (flushing them), locks and caches; does not unmount */
void hc_free(HC *h);

/* the Amiga name a remote name is shown as (out: HC_NAMEMAX + 1 bytes):
 * ln_name_to_amiga, and names longer than 107 bytes are cut with a
 * "~XXXX" suffix (hash of the remote name) so they stay unique */
void hc_amiga_name(const char *rname, char *out);
/* Latin-1 <-> UTF-8 for comments */
void hc_latin1_to_utf8(const char *in, char *out, size_t n);
void hc_utf8_to_latin1(const char *in, char *out, size_t n);

/* locks (base NULL = the root) */
int  hc_lock(HC *h, HLock *base, const char *apath, int excl, HLock **out);
void hc_unlock(HC *h, HLock *l);
int  hc_duplock(HC *h, HLock *l, HLock **out);           /* l NULL = root */
int  hc_parent(HC *h, HLock *l, HLock **out);            /* *out NULL at the root */
int  hc_lock_file(HC *h, HFile *f, HLock **out);         /* DupLockFromFH */
int  hc_parent_file(HC *h, HFile *f, HLock **out);       /* ParentOfFH */
int  hc_change_lock(HC *h, HLock *l, int excl);
int  hc_change_file(HC *h, HFile *f, int excl);
int  hc_same_lock(const HLock *a, const HLock *b);
/* current attributes of a locked object / open file */
int  hc_stat_lock(HC *h, HLock *l, LnStat *st);
int  hc_stat_file(HC *h, HFile *f, LnStat *st);
/* directory iteration over a snapshot: *idx = 0 starts (re-reads the
 * directory, through the cache), returns 1 + entry and advances *idx,
 * 0 at the end */
int  hc_next(HC *h, HLock *l, u32 *idx, const HEnt **e);
void hc_end_scan(HC *h, HLock *l);

/* files */
int  hc_open(HC *h, HLock *base, const char *apath, int mode, HFile **out);
int  hc_open_lock(HC *h, HLock *l, HFile **out);         /* frees l on success */
long hc_read(HC *h, HFile *f, void *buf, long n);
long hc_write(HC *h, HFile *f, const void *buf, long n);
int  hc_seek(HC *h, HFile *f, s64 off, int mode, u64 *oldpos);
int  hc_set_size(HC *h, HFile *f, s64 off, int mode, u64 *newsize);
int  hc_close(HC *h, HFile *f);
int  hc_flush_all(HC *h);

/* name space */
int  hc_delete(HC *h, HLock *base, const char *apath);
int  hc_rename(HC *h, HLock *b1, const char *a1, HLock *b2, const char *a2);
int  hc_mkdir(HC *h, HLock *base, const char *apath, HLock **out);
int  hc_setattr(HC *h, HLock *base, const char *apath, const LnStat *st, u32 mask);
int  hc_statfs(HC *h, LnStatFs *st);

/* call when idle (timer): flushes write-behind buffers after 1 s and
 * pings the server every ping_ms; returns LN_OK or the ping error */
int  hc_idle(HC *h);
/* has anything dirty that hc_idle should flush soon? */
int  hc_dirty(const HC *h);
/* reconnect now (with back-off); LN_OK or LN_ECONNRESET */
int  hc_reconnect(HC *h);
/* drop all cached listings and attributes */
void hc_cache_clear(HC *h);

#endif
