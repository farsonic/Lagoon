/*
 * Lagoon - NFS v3 backend (RFC 1813) for Unix, Linux, BSD servers and NAS
 * boxes: ONC RPC over TCP (nfs_rpc.c), portmapper, MOUNT v3, AUTH_SYS.
 *
 * URL: nfs://host[:nfsport]/export/path[?options]. The export is found by
 * trying MNT on the whole path, then on shorter prefixes; the rest is looked
 * up inside the export. Options: uid=, gid=, gids=a,b,c (AUTH_SYS identity,
 * default 65534 "nobody"), mountport=, pmapport=, secure=no (do not bind a
 * reserved local port), sync=yes (FILE_SYNC writes), maxio=, timeout= (s),
 * ro, access=no (no ACCESS calls), fmode=, dmode= (octal create modes).
 *
 * File handles of recent directories are cached by path. NFS3ERR_STALE
 * flushes the cache and looks the path up again (also for open files);
 * NFS3ERR_JUKEBOX is retried after a delay. Writes are UNSTABLE and kept
 * in memory (up to NFS_WBUF bytes per file) until a COMMIT, so they can be
 * resent with FILE_SYNC if the server's write verifier changes (reboot).
 * Symbolic links are reported as LN_T_LINK by stat/readdir; paths are
 * resolved through relative links (and absolute ones pointing inside the
 * export), and open/opendir follow a link in the last component.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "nfs_rpc.h"
#include "../ln_sys.h"

#define NFS_PATHMAX  1024
#define NFS_CACHE    16
#define NFS_CPATH    256
#define NFS_WBUF     (128L * 1024)
#define NFS_MAXIO    32768L        /* default cap: the 68k likes modest requests */

typedef struct FhCache {
	char  path[NFS_CPATH];       /* relative to the base, "" = unused */
	NfsFh fh;
	u32   used;
} FhCache;

struct LnFs {
	NfsRpc  rpc;                 /* NFS connection */
	char    host[128];
	u16     pmport, mntport, nfsport;
	int     nfsport_fixed, mntport_fixed;
	char    export[NFS_CPATH];   /* the path MNT accepted */
	char    sub[NFS_PATHMAX];    /* the rest of the URL path, inside the export */
	char    rootpath[NFS_PATHMAX]; /* export + "/" + sub: absolute symlinks inside it resolve */
	NfsFh   mroot;               /* export root (MNT) */
	NfsFh   base;                /* mroot + sub: the share root */
	u32     uid, gid, gids[16];
	int     ngids;
	u8      cred[RPC_CREDMAX];
	size_t  credlen;
	int     secure, timeout_ms, file_sync, readonly, use_access, rdplus;
	long    maxio;
	u32     fmode, dmode;
	FhCache cache[NFS_CACHE];
	u32     tick;
	char    p1[NFS_PATHMAX], p2[NFS_PATHMAX], lnk[NFS_PATHMAX];  /* resolve scratch */
	char    pa[NFS_PATHMAX], pb[NFS_PATHMAX];                    /* callers' scratch */
};

typedef struct WChunk {
	struct WChunk *next;
	u64 off;
	u32 len;
	u8  data[4];
} WChunk;

struct LnFile {
	LnFs   *fs;
	NfsFh   fh;
	int     flags;
	char   *path;
	WChunk *wq, *wtail;          /* unstable data not yet committed */
	long    wbytes;
	u8      verf[8];
	int     have_verf;
};

struct LnDir {
	LnFs  *fs;
	NfsFh  fh;
	int    plus, have, eof;
	u64    cookie;
	u8     verf[8];
	u8    *buf;
	size_t cap;
	NfsXdr x;
};

/* ------------------------------------------------------------ helpers */

static u32 parse_octal(const LnUrl *u, const char *key, u32 def)
{
	char b[16];
	const char *v = ln_url_opt(u, key, NULL, b, sizeof(b));
	u32 m = 0;
	if (!v || !*v) return def;
	while (*v >= '0' && *v <= '7') m = m * 8 + (u32)(*v++ - '0');
	return m & 07777;
}

static int opt_yes(const LnUrl *u, const char *key, int def)
{
	char b[16];
	const char *v = ln_url_opt(u, key, NULL, b, sizeof(b));
	if (!v) return def;
	return !(!ln_strcasecmp(v, "no") || !ln_strcasecmp(v, "0") || !ln_strcasecmp(v, "false") ||
	         !ln_strcasecmp(v, "off"));
}

/* wait ms without busy looping: the NFS socket is idle between calls */
static void nfs_sleep(LnFs *fs, int ms)
{
	u8 b;
	if (fs->rpc.sock && ln_tcp_recv_some(fs->rpc.sock, &b, 1, ms) != LN_ETIMEDOUT)
		rpc_disconnect(&fs->rpc);
}

/* make the call in x; *st = nfsstat3 (results follow in res). Retries
 * NFS3ERR_JUKEBOX (file being recalled from tape etc.) with growing delays. */
static int nfs_call(LnFs *fs, NfsXdr *x, NfsXdr *res, u32 *st)
{
	int tries = 0, e = rpc_call(&fs->rpc, x, res);
	while (!e) {
		*st = xdr_get_u32(res);
		if (res->err) return LN_EPROTO;
		if (*st != NFS3ERR_JUKEBOX || ++tries > 10) return LN_OK;
		LN_LOG(2, "nfs: server busy (JUKEBOX), retry %d", tries);
		nfs_sleep(fs, 500 * tries);
		e = rpc_recall(&fs->rpc, res);
	}
	return e;
}

static void put_sattr(NfsXdr *x, int setmode, u32 mode, int setsize, u64 size, int mtime_how, u32 mtime,
                      int atime_how)
{
	xdr_put_u32(x, (u32)setmode);
	if (setmode) xdr_put_u32(x, mode);
	xdr_put_u32(x, 0);               /* uid */
	xdr_put_u32(x, 0);               /* gid */
	xdr_put_u32(x, (u32)setsize);
	if (setsize) xdr_put_u64(x, size);
	xdr_put_u32(x, (u32)atime_how);  /* 0 don't, 1 server time, 2 client time */
	if (atime_how == 2) { xdr_put_u32(x, mtime); xdr_put_u32(x, 0); }
	xdr_put_u32(x, (u32)mtime_how);
	if (mtime_how == 2) { xdr_put_u32(x, mtime); xdr_put_u32(x, 0); }
}

static void to_stat(LnFs *fs, const NfsAttr *a, LnStat *st)
{
	nfs_attr_to_stat(a, fs->uid, fs->gid, fs->gids, fs->ngids, st);
}

/* ------------------------------------------------------- basic calls */

static int nfs_getattr(LnFs *fs, const NfsFh *fh, NfsAttr *a)
{
	NfsXdr x, res;
	u32 st;
	int e;
	rpc_begin(&fs->rpc, &x, NFS3_GETATTR);
	xdr_put_fh(&x, fh);
	if ((e = nfs_call(fs, &x, &res, &st))) return e;
	if (st) return nfs_stat_to_ln(st);
	xdr_get_fattr(&res, a);
	return res.err ? LN_EPROTO : LN_OK;
}

static int nfs_lookup(LnFs *fs, const NfsFh *dir, const char *name, NfsFh *out, NfsAttr *a)
{
	NfsXdr x, res;
	u32 st;
	int e;
	rpc_begin(&fs->rpc, &x, NFS3_LOOKUP);
	xdr_put_fh(&x, dir);
	xdr_put_string(&x, name);
	if ((e = nfs_call(fs, &x, &res, &st))) return e;
	if (st) return nfs_stat_to_ln(st);
	if (xdr_get_fh(&res, out)) return LN_EPROTO;
	if (xdr_get_post_attr(&res, a)) return LN_OK;
	if (res.err) return LN_EPROTO;
	return nfs_getattr(fs, out, a);
}

static int nfs_readlink(LnFs *fs, const NfsFh *fh, char *out, size_t n)
{
	NfsXdr x, res;
	u32 st;
	int e;
	rpc_begin(&fs->rpc, &x, NFS3_READLINK);
	xdr_put_fh(&x, fh);
	if ((e = nfs_call(fs, &x, &res, &st))) return e;
	if (st) return nfs_stat_to_ln(st);
	xdr_get_post_attr(&res, NULL);
	return xdr_get_string(&res, out, n);
}

static int nfs_access(LnFs *fs, const NfsFh *fh, u32 want, u32 *got)
{
	NfsXdr x, res;
	u32 st;
	int e;
	rpc_begin(&fs->rpc, &x, NFS3_ACCESS);
	xdr_put_fh(&x, fh);
	xdr_put_u32(&x, want);
	if ((e = nfs_call(fs, &x, &res, &st))) return e;
	if (st) return nfs_stat_to_ln(st);
	xdr_get_post_attr(&res, NULL);
	*got = xdr_get_u32(&res);
	return res.err ? LN_EPROTO : LN_OK;
}

static int nfs_setattr_fh(LnFs *fs, const NfsFh *fh, int setmode, u32 mode, int setsize, u64 size,
                          int mtime_how, u32 mtime, int atime_how)
{
	NfsXdr x, res;
	u32 st;
	int e;
	rpc_begin(&fs->rpc, &x, NFS3_SETATTR);
	xdr_put_fh(&x, fh);
	put_sattr(&x, setmode, mode, setsize, size, mtime_how, mtime, atime_how);
	xdr_put_u32(&x, 0);              /* no guard */
	if ((e = nfs_call(fs, &x, &res, &st))) return e;
	return nfs_stat_to_ln(st);
}

/* --------------------------------------------- directory handle cache */

static void cache_flush(LnFs *fs)
{
	int i;
	for (i = 0; i < NFS_CACHE; i++) fs->cache[i].path[0] = 0;
}

/* forget path and everything below it */
static void cache_drop(LnFs *fs, const char *path)
{
	size_t l = strlen(path);
	int i;
	if (!l) { cache_flush(fs); return; }
	for (i = 0; i < NFS_CACHE; i++) {
		const char *p = fs->cache[i].path;
		if (p[0] && !strncmp(p, path, l) && (p[l] == 0 || p[l] == '/'))
			fs->cache[i].path[0] = 0;
	}
}

static void cache_put(LnFs *fs, const char *path, size_t l, const NfsFh *fh)
{
	int i, victim = 0;
	if (!l || l >= NFS_CPATH) return;
	for (i = 0; i < NFS_CACHE; i++) {
		FhCache *c = &fs->cache[i];
		if (c->path[0] && strlen(c->path) == l && !memcmp(c->path, path, l)) { victim = i; break; }
		if (!c->path[0]) { victim = i; break; }
		if (c->used < fs->cache[victim].used) victim = i;
	}
	memcpy(fs->cache[victim].path, path, l);
	fs->cache[victim].path[l] = 0;
	fs->cache[victim].fh = *fh;
	fs->cache[victim].used = ++fs->tick;
}

/* longest cached directory that is a prefix of path; returns its length
 * (0 = none: *dir = base) */
static size_t cache_find(LnFs *fs, const char *path, NfsFh *dir)
{
	size_t best = 0, pl = strlen(path);
	int i, bi = -1;
	for (i = 0; i < NFS_CACHE; i++) {
		const char *p = fs->cache[i].path;
		size_t l = strlen(p);
		if (l && l <= pl && l > best && !memcmp(p, path, l) && (path[l] == 0 || path[l] == '/')) {
			best = l;
			bi = i;
		}
	}
	if (bi < 0) { *dir = fs->base; return 0; }
	fs->cache[bi].used = ++fs->tick;
	*dir = fs->cache[bi].fh;
	return best;
}

/* ------------------------------------------------------ path resolve */

/* normalize in place: drop "", ".", resolve ".."; -1 if it leaves the root */
static int norm_path(char *s)
{
	size_t ol = 0;
	char *p = s;
	while (*p) {
		char *c = p;
		size_t l;
		while (*p && *p != '/') p++;
		l = (size_t)(p - c);
		if (*p) p++;
		if (l == 0 || (l == 1 && c[0] == '.')) continue;
		if (l == 2 && c[0] == '.' && c[1] == '.') {
			if (!ol) return -1;
			while (ol && s[ol - 1] != '/') ol--;
			if (ol) ol--;
			continue;
		}
		if (ol) s[ol++] = '/';
		memmove(s + ol, c, l);
		ol += l;
	}
	s[ol] = 0;
	return 0;
}

/* the component p1[start..end) is a symlink to t: rewrite p1 */
static int splice_link(LnFs *fs, size_t start, size_t end, const char *t)
{
	char *np = fs->p2;
	size_t n = sizeof(fs->p2);
	if (t[0] == '/') {
		size_t rl = strlen(fs->rootpath);
		if (rl == 1) rl = 0;         /* export "/" */
		if (strncmp(t, fs->rootpath, rl) || (t[rl] && t[rl] != '/')) {
			LN_LOG(1, "nfs: symlink to %s points outside the share", t);
			return LN_ENOENT;
		}
		ln_strlcpy(np, t + rl, n);
	} else {
		if (start >= n) return LN_ENAMETOOLONG;
		memcpy(np, fs->p1, start);
		np[start] = 0;
		ln_strlcat(np, t, n);
	}
	ln_strlcat(np, "/", n);
	if (ln_strlcat(np, fs->p1 + end, n) >= n) return LN_ENAMETOOLONG;
	if (norm_path(np)) return LN_ENOENT;
	ln_strlcpy(fs->p1, np, sizeof(fs->p1));
	return LN_OK;
}

static int walk(LnFs *fs, const char *path, int follow, NfsFh *fh, NfsAttr *a)
{
	char name[256];
	int hops = 0, e;
	size_t pos;
	NfsFh dir;
	if (ln_strlcpy(fs->p1, path, sizeof(fs->p1)) >= sizeof(fs->p1)) return LN_ENAMETOOLONG;
	if (norm_path(fs->p1)) return LN_ENOENT;
restart:
	pos = cache_find(fs, fs->p1, &dir);
	if (!fs->p1[pos]) {
		*fh = dir;
		return nfs_getattr(fs, fh, a);
	}
	if (fs->p1[pos] == '/') pos++;
	for (;;) {
		size_t start = pos, l;
		int last;
		while (fs->p1[pos] && fs->p1[pos] != '/') pos++;
		l = pos - start;
		if (l >= sizeof(name)) return LN_ENAMETOOLONG;
		memcpy(name, fs->p1 + start, l);
		name[l] = 0;
		last = !fs->p1[pos];
		if ((e = nfs_lookup(fs, &dir, name, fh, a))) return e;
		if (a->type == NF3LNK && (!last || follow)) {
			if (++hops > 8) return LN_EIO;  /* link loop */
			if ((e = nfs_readlink(fs, fh, fs->lnk, sizeof(fs->lnk)))) return e;
			if ((e = splice_link(fs, start, pos, fs->lnk))) return e;
			goto restart;
		}
		if (last) return LN_OK;
		if (a->type != NF3DIR) return LN_ENOTDIR;
		cache_put(fs, fs->p1, pos, fh);
		dir = *fh;
		pos++;
	}
}

static int do_mnt(LnFs *fs, const char *path, NfsFh *fh);

/* re-MNT the export and look the share root up again */
static int remount(LnFs *fs)
{
	NfsFh root;
	NfsAttr a;
	int e = do_mnt(fs, fs->export, &root);
	if (e) return e;
	cache_flush(fs);
	fs->mroot = root;
	fs->base = root;
	if (fs->sub[0]) {
		NfsFh b;
		if ((e = walk(fs, fs->sub, 1, &b, &a))) return e;
		if (a.type != NF3DIR) return LN_ENOTDIR;
		cache_flush(fs);
		fs->base = b;
	}
	return LN_OK;
}

/* path (relative to the share root) -> handle + attributes */
static int resolve(LnFs *fs, const char *path, int follow, NfsFh *fh, NfsAttr *a)
{
	int attempt, e = LN_ESTALE;
	for (attempt = 0; attempt < 3; attempt++) {
		e = walk(fs, path, follow, fh, a);
		if (e != LN_ESTALE) return e;
		LN_LOG(1, "nfs: stale handle resolving \"%s\", looking it up again", path);
		cache_flush(fs);
		if (attempt == 1 && remount(fs)) return LN_ESTALE;
	}
	return e;
}

/* parent directory of path + last name; fails for the root */
static int resolve_parent(LnFs *fs, const char *path, char *pbuf, NfsFh *dir, const char **name)
{
	NfsAttr a;
	int e;
	*name = ln_path_base(path);
	if (!**name) return LN_EINVAL;
	if (strlen(*name) > 255) return LN_ENAMETOOLONG;
	ln_path_parent(pbuf, NFS_PATHMAX, path);
	if ((e = resolve(fs, pbuf, 1, dir, &a))) return e;
	return a.type == NF3DIR ? LN_OK : LN_ENOTDIR;
}

/* ------------------------------------------------------------- mount */

static int mnt_rpc(LnFs *fs, NfsRpc *m, size_t rmax)
{
	return rpc_open(m, fs->host, fs->mntport, MOUNT_PROG, MOUNT_VERS, 1024, rmax, fs->secure,
	                fs->timeout_ms, fs->cred, fs->credlen);
}

static int do_mnt(LnFs *fs, const char *path, NfsFh *fh)
{
	NfsRpc m;
	NfsXdr x, res;
	int e = mnt_rpc(fs, &m, 4096);
	if (!e) {
		rpc_begin(&m, &x, MNT3_MNT);
		xdr_put_string(&x, path);
		e = rpc_call(&m, &x, &res);
	}
	if (!e) {
		u32 st = xdr_get_u32(&res);
		e = res.err ? LN_EPROTO : mnt_stat_to_ln(st);
		if (!e && xdr_get_fh(&res, fh)) e = LN_EPROTO;
		if (!e) {
			u32 i, n = xdr_get_u32(&res), sys = n == 0;
			for (i = 0; i < n && i < 32 && !res.err; i++) {
				u32 f = xdr_get_u32(&res);
				if (f == 0 || f == 1) sys = 1;
			}
			if (!sys) LN_LOG(0, "nfs: export %s does not offer AUTH_SYS, trying anyway", path);
		}
		LN_LOG(2, "nfs: MNT %s: %s", path, e ? ln_strerror(e) : "ok");
	}
	rpc_close(&m);
	return e;
}

static void do_umnt(LnFs *fs)
{
	NfsRpc m;
	NfsXdr x, res;
	int save = fs->timeout_ms;
	fs->timeout_ms = 3000;
	if (!mnt_rpc(fs, &m, 1024)) {
		rpc_begin(&m, &x, MNT3_UMNT);
		xdr_put_string(&x, fs->export);
		rpc_call(&m, &x, &res);
	}
	rpc_close(&m);
	fs->timeout_ms = save;
}

static int find_ports(LnFs *fs)
{
	int e;
	if (!fs->mntport_fixed) {
		e = pmap_getport(fs->host, fs->pmport, MOUNT_PROG, MOUNT_VERS, fs->timeout_ms, &fs->mntport);
		if (e) { LN_LOG(0, "nfs: portmapper on %s: %s", fs->host, ln_strerror(e)); return e; }
		if (!fs->mntport) { LN_LOG(0, "nfs: no MOUNT v3 service on %s", fs->host); return LN_ENOTSUP; }
	}
	if (!fs->nfsport_fixed) {
		if (pmap_getport(fs->host, fs->pmport, NFS_PROG, NFS_VERS, fs->timeout_ms, &fs->nfsport) || !fs->nfsport)
			fs->nfsport = 2049;
	}
	return LN_OK;
}

static void parse_opts(LnFs *fs, const LnUrl *u)
{
	char b[LN_URL_MAX];
	const char *v;
	int t;
	ln_strlcpy(fs->host, u->host, sizeof(fs->host));
	fs->uid = (u32)ln_url_opt_int(u, "uid", 65534);
	fs->gid = (u32)ln_url_opt_int(u, "gid", 65534);
	v = ln_url_opt(u, "gids", NULL, b, sizeof(b));
	while (v && *v && fs->ngids < 16) {
		u32 g = 0;
		int d = 0;
		while (*v >= '0' && *v <= '9') { g = g * 10 + (u32)(*v++ - '0'); d = 1; }
		if (d) fs->gids[fs->ngids++] = g;
		if (*v) v++;
	}
	fs->pmport = (u16)ln_url_opt_int(u, "pmapport", 111);
	fs->mntport = (u16)ln_url_opt_int(u, "mountport", 0);
	fs->mntport_fixed = fs->mntport != 0;
	fs->nfsport = u->port;
	fs->nfsport_fixed = u->port != 0;
	fs->secure = opt_yes(u, "secure", 1);
	fs->file_sync = opt_yes(u, "sync", 0);
	fs->readonly = opt_yes(u, "ro", 0);
	fs->use_access = opt_yes(u, "access", 1);
	t = ln_url_opt_int(u, "timeout", 30);
	fs->timeout_ms = (t < 2 ? 2 : t > 600 ? 600 : t) * 1000;
	fs->maxio = ln_url_opt_int(u, "maxio", (int)NFS_MAXIO);
	if (fs->maxio < 1024) fs->maxio = 1024;
	if (fs->maxio > 65536) fs->maxio = 65536;
	fs->fmode = parse_octal(u, "fmode", 0644);
	fs->dmode = parse_octal(u, "dmode", 0755);
	fs->rdplus = 1;
}

static int nfs_mount(const LnUrl *u, const LnCreds *cr, LnFs **out)
{
	LnFs *fs;
	char *full;
	int e, cl;
	size_t l;
	(void)cr;                        /* AUTH_SYS: identity comes from uid=/gid= */
	if (!u->host[0]) return LN_EINVAL;
	fs = ln_alloc(sizeof(*fs));
	if (!fs) return LN_ENOMEM;
	parse_opts(fs, u);
	cl = rpc_auth_sys(fs->cred, sizeof(fs->cred), ln_time_unix(), ln_hostname(), fs->uid, fs->gid,
	                  fs->gids, fs->ngids);
	if (cl < 0) { ln_free(fs); return LN_EINVAL; }
	fs->credlen = (size_t)cl;

	/* the whole path: "/" + share + "/" + path */
	full = fs->p2;
	ln_strlcpy(full, "/", NFS_PATHMAX);
	ln_strlcat(full, u->share, NFS_PATHMAX);
	if (u->path[0]) { ln_strlcat(full, "/", NFS_PATHMAX); ln_strlcat(full, u->path, NFS_PATHMAX); }
	if (norm_path(full + 1)) { ln_free(fs); return LN_EINVAL; }
	if (strlen(full) >= sizeof(fs->rootpath)) { ln_free(fs); return LN_ENAMETOOLONG; }
	ln_strlcpy(fs->rootpath, full, sizeof(fs->rootpath));

	if ((e = find_ports(fs))) { ln_free(fs); return e; }

	/* find the export: the longest prefix of the path MNT accepts */
	ln_strlcpy(fs->pa, fs->rootpath, sizeof(fs->pa));
	for (;;) {
		int e2;
		if (strlen(fs->pa) >= sizeof(fs->export)) e2 = LN_ENAMETOOLONG;
		else e2 = do_mnt(fs, fs->pa, &fs->mroot);
		if (!e2) break;
		if (e2 != LN_ENOSHARE && e2 != LN_EACCES && e2 != LN_ENOTDIR && e2 != LN_ENAMETOOLONG &&
		    e2 != LN_EINVAL) { e = e2; break; }
		if (!e) e = e2;              /* report the error for the full path */
		if (!strcmp(fs->pa, "/")) break;
		{
			char *s = strrchr(fs->pa, '/');
			if (s == fs->pa) s[1] = 0; else *s = 0;
		}
	}
	if (e && !fs->mroot.len) {
		LN_LOG(0, "nfs: MNT %s on %s: %s", fs->rootpath, fs->host, ln_strerror(e));
		ln_free(fs);
		return e;
	}
	e = LN_OK;
	ln_strlcpy(fs->export, fs->pa, sizeof(fs->export));
	l = strlen(fs->export);
	ln_strlcpy(fs->sub, fs->rootpath + (l == 1 ? 1 : l), sizeof(fs->sub));
	norm_path(fs->sub);
	LN_LOG(1, "nfs: mounted export %s (sub \"%s\") NFS port %u MOUNT port %u", fs->export, fs->sub,
	       fs->nfsport, fs->mntport);

	e = rpc_open(&fs->rpc, fs->host, fs->nfsport, NFS_PROG, NFS_VERS, (size_t)fs->maxio + 1024,
	             (size_t)fs->maxio + 8192, fs->secure, fs->timeout_ms, fs->cred, fs->credlen);
	if (!e) {
		/* FSINFO: the server's preferred transfer sizes */
		NfsXdr x, res;
		u32 st;
		rpc_begin(&fs->rpc, &x, NFS3_FSINFO);
		xdr_put_fh(&x, &fs->mroot);
		e = nfs_call(fs, &x, &res, &st);
		if (!e && st) e = nfs_stat_to_ln(st);
		if (!e) {
			u32 rtmax, wtmax;
			xdr_get_post_attr(&res, NULL);
			rtmax = xdr_get_u32(&res);
			xdr_skip(&res, 8);       /* rtpref, rtmult */
			wtmax = xdr_get_u32(&res);
			if (!res.err) {
				if (rtmax && (long)rtmax < fs->maxio) fs->maxio = (long)rtmax;
				if (wtmax && (long)wtmax < fs->maxio) fs->maxio = (long)wtmax;
				if (fs->maxio >= 4096) fs->maxio &= ~4095L;
				if (fs->maxio < 512) fs->maxio = 512;
			}
		}
	}
	if (!e) {
		fs->base = fs->mroot;
		if (fs->sub[0]) {
			NfsAttr a;
			NfsFh b;
			e = walk(fs, fs->sub, 1, &b, &a);
			if (!e && a.type != NF3DIR) e = LN_ENOTDIR;
			if (e == LN_ENOENT) e = LN_ENOSHARE;
			if (!e) fs->base = b;
			cache_flush(fs);
		}
	}
	if (e) {
		LN_LOG(0, "nfs: %s:%s: %s", fs->host, fs->rootpath, ln_strerror(e));
		rpc_close(&fs->rpc);
		do_umnt(fs);
		ln_free(fs);
		return e;
	}
	*out = fs;
	return LN_OK;
}

static void nfs_unmount(LnFs *fs)
{
	if (!fs) return;
	rpc_close(&fs->rpc);
	do_umnt(fs);
	ln_wipe(fs->cred, sizeof(fs->cred));
	ln_free(fs);
}

static int nfs_ping(LnFs *fs)
{
	NfsXdr x, res;
	rpc_begin(&fs->rpc, &x, NFS3_NULL);
	return rpc_call(&fs->rpc, &x, &res);
}

/* file handles survive server reboots: reconnect TCP, MNT again (some
 * servers want it), keep the handles unless the export root changed */
static int nfs_reconnect(LnFs *fs)
{
	int e;
	NfsFh root;
	rpc_disconnect(&fs->rpc);
	if (!fs->nfsport_fixed || !fs->mntport_fixed) {
		if (find_ports(fs) == LN_OK) fs->rpc.port = fs->nfsport;
	}
	if ((e = rpc_connect(&fs->rpc))) return e;
	if (do_mnt(fs, fs->export, &root) == LN_OK &&
	    (root.len != fs->mroot.len || memcmp(root.data, fs->mroot.data, root.len))) {
		LN_LOG(1, "nfs: export root handle changed");
		if ((e = remount(fs))) return e;
	}
	return nfs_ping(fs);
}

/* ---------------------------------------------------------- stat etc */

static void fill_prot(LnFs *fs, const NfsFh *fh, LnStat *st)
{
	u32 got;
	if (!fs->use_access || st->type == LN_T_LINK) return;
	if (nfs_access(fs, fh, ACCESS3_READ | ACCESS3_LOOKUP | ACCESS3_MODIFY | ACCESS3_EXTEND |
	               ACCESS3_DELETE | ACCESS3_EXECUTE, &got) == LN_OK)
		st->prot = nfs_access_to_prot(got, st->type);
}

static int nfs_stat(LnFs *fs, const char *path, LnStat *st)
{
	NfsFh fh;
	NfsAttr a;
	int e = resolve(fs, path, 0, &fh, &a);
	if (e) return e;
	to_stat(fs, &a, st);
	fill_prot(fs, &fh, st);
	return LN_OK;
}

static int nfs_statfs(LnFs *fs, LnStatFs *sf)
{
	NfsXdr x, res;
	u32 st;
	int e, attempt;
	const char *v;
	memset(sf, 0, sizeof(*sf));
	for (attempt = 0; attempt < 2; attempt++) {
		rpc_begin(&fs->rpc, &x, NFS3_FSSTAT);
		xdr_put_fh(&x, &fs->base);
		if ((e = nfs_call(fs, &x, &res, &st))) return e;
		if (st != NFS3ERR_STALE && st != NFS3ERR_BADHANDLE) break;
		if (remount(fs)) return LN_ESTALE;
	}
	if (st) return nfs_stat_to_ln(st);
	xdr_get_post_attr(&res, NULL);
	sf->total_bytes = xdr_get_u64(&res);
	xdr_get_u64(&res);               /* fbytes (includes root's reserve) */
	sf->free_bytes = xdr_get_u64(&res);
	if (res.err) return LN_EPROTO;
	sf->block_size = 4096;
	sf->readonly = fs->readonly;
	v = ln_path_base(fs->rootpath);
	ln_strlcpy(sf->volume, *v ? v : fs->host, sizeof(sf->volume));
	return LN_OK;
}

/* ------------------------------------------------------- directories */

static int nfs_opendir(LnFs *fs, const char *path, LnDir **out)
{
	NfsFh fh;
	NfsAttr a;
	LnDir *d;
	int e = resolve(fs, path, 1, &fh, &a);
	if (e) return e;
	if (a.type != NF3DIR) return LN_ENOTDIR;
	d = ln_alloc(sizeof(*d));
	if (!d) return LN_ENOMEM;
	d->fs = fs;
	d->fh = fh;
	d->plus = fs->rdplus;
	*out = d;
	return LN_OK;
}

/* fetch the next batch of entries into d->buf */
static int dir_fetch(LnDir *d)
{
	LnFs *fs = d->fs;
	NfsXdr x, res;
	u32 st;
	int e;
	size_t n;
	for (;;) {
		rpc_begin(&fs->rpc, &x, d->plus ? NFS3_READDIRPLUS : NFS3_READDIR);
		xdr_put_fh(&x, &d->fh);
		xdr_put_u64(&x, d->cookie);
		xdr_put_fixed(&x, d->verf, 8);
		if (d->plus) {
			xdr_put_u32(&x, (u32)(fs->maxio / 4));   /* dircount: names + cookies */
			xdr_put_u32(&x, (u32)fs->maxio);         /* maxcount: whole reply */
		} else
			xdr_put_u32(&x, (u32)fs->maxio);
		if ((e = nfs_call(fs, &x, &res, &st))) return e;
		if (st == NFS3ERR_NOTSUPP && d->plus) {
			LN_LOG(1, "nfs: no READDIRPLUS, using READDIR + LOOKUP");
			d->plus = fs->rdplus = 0;
			continue;
		}
		break;
	}
	if (st) return nfs_stat_to_ln(st);
	xdr_get_post_attr(&res, NULL);
	xdr_get_fixed(&res, d->verf, 8);
	if (res.err) return LN_EPROTO;
	n = res.len - res.pos;
	if (n > d->cap) {
		u8 *nb = ln_realloc(d->buf, d->cap, n);
		if (!nb) return LN_ENOMEM;
		d->buf = nb;
		d->cap = n;
	}
	memcpy(d->buf, res.buf + res.pos, n);
	xdr_init_dec(&d->x, d->buf, n);
	d->have = 1;
	return LN_OK;
}

static int nfs_readdir(LnDir *d, char *name, size_t namemax, LnStat *st)
{
	char nm[256];
	for (;;) {
		u32 more;
		int e, hasattr = 0;
		NfsAttr a;
		NfsFh fh;
		if (!d->have) {
			if (d->eof) return 0;
			if ((e = dir_fetch(d))) return e;
		}
		more = xdr_get_u32(&d->x);
		if (d->x.err) return LN_EPROTO;
		if (!more) {
			d->eof = (int)xdr_get_u32(&d->x);
			d->have = 0;
			if (d->x.err) return LN_EPROTO;
			continue;
		}
		xdr_get_u64(&d->x);          /* fileid */
		e = xdr_get_string(&d->x, nm, sizeof(nm));
		d->cookie = xdr_get_u64(&d->x);
		fh.len = 0;
		if (d->plus) {
			hasattr = xdr_get_post_attr(&d->x, &a);
			if (xdr_get_u32(&d->x)) xdr_get_fh(&d->x, &fh);
		}
		if (d->x.err || e == LN_EPROTO) return LN_EPROTO;
		if (e) continue;             /* name longer than 255 bytes */
		if (!strcmp(nm, ".") || !strcmp(nm, "..")) continue;
		if (strlen(nm) >= namemax) {
			LN_LOG(1, "nfs: skipping long name %s", nm);
			continue;
		}
		if (!hasattr) {
			e = nfs_lookup(d->fs, &d->fh, nm, &fh, &a);
			if (e == LN_ENOENT) continue;   /* deleted meanwhile */
			if (e) return e;
		}
		to_stat(d->fs, &a, st);
		ln_strlcpy(name, nm, namemax);
		return 1;
	}
}

static void nfs_closedir(LnDir *d)
{
	if (!d) return;
	ln_free(d->buf);
	ln_free(d);
}

/* ------------------------------------------------------------- files */

static int nfs_create(LnFs *fs, const NfsFh *dir, const char *name, int excl, NfsFh *out, NfsAttr *a)
{
	NfsXdr x, res;
	u32 st;
	int e, how = excl ? 2 : 1;       /* EXCLUSIVE : GUARDED */
	u8 verf[8];
	ln_random(verf, sizeof(verf));
again:
	rpc_begin(&fs->rpc, &x, NFS3_CREATE);
	xdr_put_fh(&x, dir);
	xdr_put_string(&x, name);
	xdr_put_u32(&x, (u32)how);
	if (how == 2) xdr_put_fixed(&x, verf, 8);
	else put_sattr(&x, 1, fs->fmode, 0, 0, 0, 0, 0);
	if ((e = nfs_call(fs, &x, &res, &st))) return e;
	if (st == NFS3ERR_NOTSUPP && how == 2) { how = 1; goto again; }
	if (st) return nfs_stat_to_ln(st);
	out->len = 0;
	if (xdr_get_u32(&res)) xdr_get_fh(&res, out);
	if (res.err) return LN_EPROTO;
	if (!out->len) return nfs_lookup(fs, dir, name, out, a);
	if (how == 2) {
		/* the verifier lives in the times: set the real attributes now */
		if ((e = nfs_setattr_fh(fs, out, 1, fs->fmode, 0, 0, 1, 0, 1))) return e;
		return nfs_getattr(fs, out, a);
	}
	if (xdr_get_post_attr(&res, a)) return LN_OK;
	return nfs_getattr(fs, out, a);
}

static int nfs_open(LnFs *fs, const char *path, int flags, LnFile **out)
{
	NfsFh fh;
	NfsAttr a;
	LnFile *f;
	int e;
	if (fs->readonly && (flags & (LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC))) return LN_EROFS;
	e = resolve(fs, path, 1, &fh, &a);
	if (!e) {
		if (flags & LN_O_EXCL) return LN_EEXIST;
		if (a.type == NF3DIR) return LN_EISDIR;
		if ((flags & LN_O_TRUNC) && a.size)
			if ((e = nfs_setattr_fh(fs, &fh, 0, 0, 1, 0, 0, 0, 0))) return e;
	} else if (e == LN_ENOENT && (flags & LN_O_CREATE)) {
		NfsFh dir;
		const char *name;
		if ((e = resolve_parent(fs, path, fs->pa, &dir, &name))) return e;
		e = nfs_create(fs, &dir, name, (flags & LN_O_EXCL) != 0, &fh, &a);
		if (e == LN_EEXIST && !(flags & LN_O_EXCL))   /* lost a race: open it */
			e = nfs_lookup(fs, &dir, name, &fh, &a);
		if (e) return e;
	} else
		return e;
	f = ln_alloc(sizeof(*f));
	if (!f) return LN_ENOMEM;
	f->path = ln_strdup(path);
	if (!f->path) { ln_free(f); return LN_ENOMEM; }
	f->fs = fs;
	f->fh = fh;
	f->flags = flags;
	*out = f;
	return LN_OK;
}

/* after NFS3ERR_STALE on an open file: find it again by path */
static int reopen(LnFile *f)
{
	NfsAttr a;
	NfsFh fh;
	int e;
	LN_LOG(1, "nfs: stale handle for %s, looking it up again", f->path);
	cache_flush(f->fs);
	e = resolve(f->fs, f->path, 1, &fh, &a);
	if (e) return e;
	f->fh = fh;
	return LN_OK;
}

static long read1(LnFile *f, u64 off, void *buf, u32 n, int *eof)
{
	LnFs *fs = f->fs;
	NfsXdr x, res;
	u32 st, len;
	const u8 *p;
	int e;
	rpc_begin(&fs->rpc, &x, NFS3_READ);
	xdr_put_fh(&x, &f->fh);
	xdr_put_u64(&x, off);
	xdr_put_u32(&x, n);
	if ((e = nfs_call(fs, &x, &res, &st))) return e;
	if (st) return nfs_stat_to_ln(st);
	xdr_get_post_attr(&res, NULL);
	xdr_get_u32(&res);               /* count */
	*eof = (int)xdr_get_u32(&res);
	p = xdr_get_opaque(&res, &len, n);
	if (!p) return LN_EPROTO;
	memcpy(buf, p, len);
	return (long)len;
}

static long nfs_read(LnFile *f, u64 off, void *buf, long n)
{
	long done = 0;
	while (done < n) {
		u32 chunk = (u32)LN_MIN(n - done, f->fs->maxio);
		int eof = 0;
		long r = read1(f, off + (u64)done, (u8 *)buf + done, chunk, &eof);
		if (r == LN_ESTALE && reopen(f) == LN_OK)
			r = read1(f, off + (u64)done, (u8 *)buf + done, chunk, &eof);
		if (r < 0) return done ? done : r;
		done += r;
		if (eof || r == 0) break;
	}
	return done;
}

static long write1(LnFile *f, u64 off, const void *buf, u32 n, int stable, u32 *committed, u8 *verf)
{
	LnFs *fs = f->fs;
	NfsXdr x, res;
	u32 st, cnt;
	int e;
	rpc_begin(&fs->rpc, &x, NFS3_WRITE);
	xdr_put_fh(&x, &f->fh);
	xdr_put_u64(&x, off);
	xdr_put_u32(&x, n);
	xdr_put_u32(&x, (u32)stable);
	xdr_put_opaque(&x, buf, n);
	if ((e = nfs_call(fs, &x, &res, &st))) return e;
	if (st) return nfs_stat_to_ln(st);
	xdr_get_wcc(&res, NULL);
	cnt = xdr_get_u32(&res);
	*committed = xdr_get_u32(&res);
	xdr_get_fixed(&res, verf, 8);
	if (res.err || cnt > n) return LN_EPROTO;
	if (!cnt && n) return LN_EIO;
	return (long)cnt;
}

/* write all of buf, retrying a stale handle once */
static int write_all(LnFile *f, u64 off, const u8 *buf, u32 n, int stable, u32 *committed, u8 *verf)
{
	int stale = 0;
	while (n) {
		long w = write1(f, off, buf, n, stable, committed, verf);
		if (w == LN_ESTALE && !stale++ && reopen(f) == LN_OK) continue;
		if (w < 0) return (int)w;
		off += (u64)w; buf += w; n -= (u32)w;
	}
	return LN_OK;
}

static void wq_free(LnFile *f)
{
	WChunk *c = f->wq;
	while (c) {
		WChunk *nx = c->next;
		ln_free(c);
		c = nx;
	}
	f->wq = f->wtail = NULL;
	f->wbytes = 0;
	f->have_verf = 0;
}

/* the server lost uncommitted data (new write verifier): write it again, stable */
static int wq_resend(LnFile *f)
{
	WChunk *c;
	u32 committed;
	u8 verf[8];
	LN_LOG(1, "nfs: server write verifier changed, resending %ld bytes of %s", f->wbytes, f->path);
	for (c = f->wq; c; c = c->next) {
		int e = write_all(f, c->off, c->data, c->len, NFS_FILE_SYNC, &committed, verf);
		if (e) { wq_free(f); return e; }
	}
	wq_free(f);
	return LN_OK;
}

static int commit(LnFile *f)
{
	LnFs *fs = f->fs;
	NfsXdr x, res;
	u32 st;
	u8 verf[8];
	int e, attempt;
	if (!f->wq) return LN_OK;
	for (attempt = 0; attempt < 2; attempt++) {
		rpc_begin(&fs->rpc, &x, NFS3_COMMIT);
		xdr_put_fh(&x, &f->fh);
		xdr_put_u64(&x, 0);
		xdr_put_u32(&x, 0);          /* to the end of the file */
		if ((e = nfs_call(fs, &x, &res, &st))) return e;
		if (st == NFS3ERR_STALE && !attempt && reopen(f) == LN_OK) continue;
		break;
	}
	if (st) { wq_free(f); return nfs_stat_to_ln(st); }
	xdr_get_wcc(&res, NULL);
	xdr_get_fixed(&res, verf, 8);
	if (res.err) return LN_EPROTO;
	if (memcmp(verf, f->verf, 8)) return wq_resend(f);
	wq_free(f);
	return LN_OK;
}

static long nfs_write(LnFile *f, u64 off, const void *buf, long n)
{
	LnFs *fs = f->fs;
	long done = 0;
	if (fs->readonly) return LN_EROFS;
	while (done < n) {
		u32 chunk = (u32)LN_MIN(n - done, fs->maxio), committed = 0;
		u8 verf[8];
		const u8 *p = (const u8 *)buf + done;
		long w = write1(f, off + (u64)done, p, chunk, fs->file_sync ? NFS_FILE_SYNC : NFS_UNSTABLE,
		                &committed, verf);
		if (w == LN_ESTALE && reopen(f) == LN_OK)
			w = write1(f, off + (u64)done, p, chunk, fs->file_sync ? NFS_FILE_SYNC : NFS_UNSTABLE,
			           &committed, verf);
		if (w < 0) return done ? done : w;
		if (committed != NFS_FILE_SYNC) {
			WChunk *c;
			int e;
			if (f->have_verf && memcmp(verf, f->verf, 8)) {
				/* server restarted since the earlier unstable writes */
				if ((e = wq_resend(f))) return e;
			}
			if (!f->have_verf) { memcpy(f->verf, verf, 8); f->have_verf = 1; }
			c = ln_alloc(sizeof(WChunk) + (size_t)w);
			if (c) {
				c->off = off + (u64)done;
				c->len = (u32)w;
				memcpy(c->data, p, (size_t)w);
				if (f->wtail) f->wtail->next = c; else f->wq = c;
				f->wtail = c;
				f->wbytes += w;
			}
			if (!c) {
				/* no memory for a copy: make this piece stable right away */
				if ((e = write_all(f, off + (u64)done, p, (u32)w, NFS_FILE_SYNC, &committed, verf)))
					return e;
			} else if (f->wbytes >= NFS_WBUF && (e = commit(f)))
				return e;
		}
		done += w;
	}
	return done;
}

static int nfs_fstat(LnFile *f, LnStat *st)
{
	NfsAttr a;
	int e = nfs_getattr(f->fs, &f->fh, &a);
	if (e == LN_ESTALE && reopen(f) == LN_OK) e = nfs_getattr(f->fs, &f->fh, &a);
	if (e) return e;
	to_stat(f->fs, &a, st);
	fill_prot(f->fs, &f->fh, st);
	return LN_OK;
}

static int nfs_truncate(LnFile *f, u64 size)
{
	int e;
	if (f->fs->readonly) return LN_EROFS;
	if ((e = commit(f))) return e;
	e = nfs_setattr_fh(f->fs, &f->fh, 0, 0, 1, size, 0, 0, 0);
	if (e == LN_ESTALE && reopen(f) == LN_OK) e = nfs_setattr_fh(f->fs, &f->fh, 0, 0, 1, size, 0, 0, 0);
	return e;
}

static int nfs_flush(LnFile *f)
{
	return commit(f);
}

static int nfs_close(LnFile *f)
{
	int e;
	if (!f) return LN_OK;
	e = commit(f);
	wq_free(f);
	ln_free(f->path);
	ln_free(f);
	return e;
}

/* ------------------------------------------------- namespace changes */

static int nfs_mkdir(LnFs *fs, const char *path)
{
	NfsXdr x, res;
	NfsFh dir;
	const char *name;
	u32 st;
	int e;
	if (fs->readonly) return LN_EROFS;
	if ((e = resolve_parent(fs, path, fs->pa, &dir, &name))) return e;
	rpc_begin(&fs->rpc, &x, NFS3_MKDIR);
	xdr_put_fh(&x, &dir);
	xdr_put_string(&x, name);
	put_sattr(&x, 1, fs->dmode, 0, 0, 0, 0, 0);
	if ((e = nfs_call(fs, &x, &res, &st))) return e;
	return nfs_stat_to_ln(st);
}

static int nfs_remove(LnFs *fs, const char *path)
{
	NfsXdr x, res;
	NfsFh dir, fh;
	NfsAttr a;
	const char *name;
	u32 st;
	int e;
	if (fs->readonly) return LN_EROFS;
	if ((e = resolve_parent(fs, path, fs->pa, &dir, &name))) return e;
	if ((e = nfs_lookup(fs, &dir, name, &fh, &a))) return e;
	rpc_begin(&fs->rpc, &x, a.type == NF3DIR ? NFS3_RMDIR : NFS3_REMOVE);
	xdr_put_fh(&x, &dir);
	xdr_put_string(&x, name);
	if ((e = nfs_call(fs, &x, &res, &st))) return e;
	if (st == NFS3ERR_EXIST) st = 66;    /* some servers say EXIST for a non-empty dir */
	if (!st) cache_drop(fs, path);
	return nfs_stat_to_ln(st);
}

static int nfs_rename(LnFs *fs, const char *from, const char *to)
{
	NfsXdr x, res;
	NfsFh fdir, tdir, ffh, tfh;
	NfsAttr fa, ta;
	const char *fname, *tname;
	u32 st;
	int e;
	if (fs->readonly) return LN_EROFS;
	if ((e = resolve_parent(fs, from, fs->pa, &fdir, &fname))) return e;
	if ((e = resolve_parent(fs, to, fs->pb, &tdir, &tname))) return e;
	if ((e = nfs_lookup(fs, &fdir, fname, &ffh, &fa))) return e;
	e = nfs_lookup(fs, &tdir, tname, &tfh, &ta);
	if (e == LN_OK) {
		/* 'to' exists: fine only if it is the same object (case change on
		 * a case-insensitive server) */
		if (ta.fileid != fa.fileid || ta.fsid != fa.fsid || !strcmp(from, to)) return LN_EEXIST;
	} else if (e != LN_ENOENT)
		return e;
	rpc_begin(&fs->rpc, &x, NFS3_RENAME);
	xdr_put_fh(&x, &fdir);
	xdr_put_string(&x, fname);
	xdr_put_fh(&x, &tdir);
	xdr_put_string(&x, tname);
	if ((e = nfs_call(fs, &x, &res, &st))) return e;
	if (!st) { cache_drop(fs, from); cache_drop(fs, to); }
	return nfs_stat_to_ln(st);
}

static int nfs_setattr(LnFs *fs, const char *path, const LnStat *s, u32 mask)
{
	NfsFh fh;
	NfsAttr a;
	int e, setmode = 0;
	u32 mode = 0;
	if (!(mask & (LN_SET_MTIME | LN_SET_PROT | LN_SET_MODE | LN_SET_SIZE)))
		return (mask & LN_SET_COMMENT) ? LN_ENOTSUP : LN_OK;
	if (fs->readonly) return LN_EROFS;
	if ((e = resolve(fs, path, 1, &fh, &a))) return e;
	if (mask & LN_SET_MODE) {
		setmode = 1;
		mode = s->mode & 07777;
	} else if (mask & LN_SET_PROT) {
		/* Amiga RWE -> the owner's rwx; group/other bits stay */
		setmode = 1;
		mode = a.mode & 07077;
		if (s->prot & LN_P_READ) mode |= 0400;
		if (s->prot & LN_P_WRITE) mode |= 0200;
		if (s->prot & LN_P_EXEC) mode |= 0100;
		if (mode == (a.mode & 07777)) setmode = 0;
	}
	if (!setmode && !(mask & (LN_SET_MTIME | LN_SET_SIZE))) return LN_OK;
	return nfs_setattr_fh(fs, &fh, setmode, mode, (mask & LN_SET_SIZE) != 0, s->size,
	                      (mask & LN_SET_MTIME) ? 2 : 0, s->mtime, 0);
}

/* ------------------------------------------------------ list_shares */

static int nfs_list_shares(const LnUrl *u, const LnCreds *cr, ln_share_cb cb, void *ud)
{
	LnFs *fs;
	NfsRpc m;
	NfsXdr x, res;
	int e, cl;
	(void)cr;
	fs = ln_alloc(sizeof(*fs));
	if (!fs) return LN_ENOMEM;
	parse_opts(fs, u);
	fs->nfsport_fixed = 1;           /* only MOUNT is needed */
	cl = rpc_auth_sys(fs->cred, sizeof(fs->cred), ln_time_unix(), ln_hostname(), fs->uid, fs->gid,
	                  fs->gids, fs->ngids);
	fs->credlen = cl > 0 ? (size_t)cl : 0;
	e = find_ports(fs);
	if (!e) e = mnt_rpc(fs, &m, 256 * 1024);
	else { ln_free(fs); return e; }
	if (!e) {
		rpc_begin(&m, &x, MNT3_EXPORT);
		e = rpc_call(&m, &x, &res);
	}
	while (!e && xdr_get_u32(&res)) {
		char *dir = fs->p1, *groups = fs->p2;
		if (xdr_get_string(&res, dir, NFS_PATHMAX) == LN_EPROTO) { e = LN_EPROTO; break; }
		groups[0] = 0;
		while (xdr_get_u32(&res)) {
			if (xdr_get_string(&res, fs->lnk, NFS_PATHMAX) == LN_EPROTO) { e = LN_EPROTO; break; }
			if (groups[0]) ln_strlcat(groups, " ", NFS_PATHMAX);
			ln_strlcat(groups, fs->lnk, NFS_PATHMAX);
		}
		if (res.err) e = LN_EPROTO;
		if (!e) cb(ud, dir, groups[0] ? groups : "(everyone)");
	}
	if (!e && res.err) e = LN_EPROTO;
	rpc_close(&m);
	ln_free(fs);
	return e;
}

static long nfs_max_io(LnFs *fs)
{
	return fs->maxio;
}

const LnOps ln_nfs_ops = {
	"nfs", "NFS v3 (Unix, Linux, NAS)", 2049,
	nfs_mount, nfs_unmount, nfs_reconnect, nfs_ping,
	nfs_statfs, nfs_stat,
	nfs_opendir, nfs_readdir, nfs_closedir,
	nfs_open, nfs_read, nfs_write, nfs_fstat, nfs_truncate, nfs_flush, nfs_close,
	nfs_mkdir, nfs_remove, nfs_rename, nfs_setattr,
	nfs_list_shares, nfs_max_io
};
