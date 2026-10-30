/*
 * Lagoon - "mem" backend: an in-memory file system behind the LnOps
 * interface, for testing the handler, C:Lagoon and the prefs without a
 * server. It behaves like a careful server: every LnOps call is implemented
 * with the documented errors (LN_ENOTEMPTY, LN_EEXIST on rename, LN_ENOSPC,
 * LN_EACCES from the protection bits, LN_EROFS ...).
 *
 *   mem://host/share[?options]
 *
 * Mounts of the same host/share in one program share the same tree (it is
 * freed when the last mount goes away). Options:
 *   size=N         capacity in bytes (default 64 MB): writes past it fail
 *                  with LN_ENOSPC
 *   ro=1           read-only share (LN_EROFS)
 *   casefold=1     case-insensitive names like SMB/AFP (default: case
 *                  sensitive like NFS)
 *   maxio=N        max_io() result (default 16384)
 *   label=X        statfs volume label (default: the share name)
 *   pass=X         mount fails with LN_EAUTH unless the password is X
 *   dropevery=N    every Nth call loses the "connection": that call and all
 *                  later ones return LN_ECONNRESET until reconnect()
 *   refuse=K       after a drop, the first K reconnect() calls fail with
 *                  LN_ECONNREFUSED
 *   stale=1        open files are invalid after a reconnect (LN_ESTALE), so
 *                  the caller must reopen them by path
 *   seed=1         pre-populate the tree with sample files (see seed())
 *   many=N         with seed: also create N files in "Many/"
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../ln_vfs.h"
#include "../ln_sys.h"

typedef struct MNode MNode;
struct MNode {
	MNode *parent, *child, *next;
	char  *name;
	int    type;             /* LN_T_FILE / LN_T_DIR */
	u8    *data;
	u64    size, cap;
	u32    mtime, ctime, prot;
	u64    fileid;
	char   comment[80];
	int    opens;            /* open LnFiles */
	int    unlinked;         /* removed while open: freed on last close */
};

typedef struct MVol MVol;
struct MVol {
	MVol  *next;
	char   key[260];         /* host/share */
	int    refs;
	MNode *root;
	u64    used, capacity;
	u64    nextid;
	int    casefold;
};

struct LnFs {
	MVol  *v;
	char   label[64];
	char   pass[128];
	int    ro, stale, connected;
	long   maxio;
	u32    calls, dropevery;
	int    refuse, refuse_left;
	u32    epoch;
};

struct LnFile {
	LnFs  *fs;
	MNode *n;
	int    flags;
	u32    epoch;
};

typedef struct MEnt { char *name; LnStat st; } MEnt;
struct LnDir {
	LnFs *fs;
	int   n, i;
	MEnt *e;
};

static MVol *vols;

/* ---- connection simulation ---- */
static int gate(LnFs *fs)
{
	if (!fs->connected)
		return LN_ECONNRESET;
	fs->calls++;
	if (fs->dropevery && fs->calls % fs->dropevery == 0) {
		fs->connected = 0;
		fs->refuse_left = fs->refuse;
		LN_LOG(2, "mem: simulated connection drop after %u calls", (unsigned)fs->calls);
		return LN_ECONNRESET;
	}
	return LN_OK;
}

static int fgate(LnFile *f)
{
	int r = gate(f->fs);
	if (r)
		return r;
	if (f->epoch != f->fs->epoch)
		return LN_ESTALE;
	return LN_OK;
}

/* ---- tree helpers ---- */
static int name_eq(const MVol *v, const char *a, const char *b)
{
	return v->casefold ? !ln_strcasecmp(a, b) : !strcmp(a, b);
}

static MNode *node_new(MVol *v, MNode *parent, const char *name, int type)
{
	MNode *n = ln_alloc(sizeof(*n));
	if (!n)
		return NULL;
	n->name = ln_strdup(name);
	if (!n->name) {
		ln_free(n);
		return NULL;
	}
	n->type = type;
	n->mtime = n->ctime = ln_time_unix();
	n->prot = LN_P_READ | LN_P_WRITE | LN_P_EXEC | LN_P_DELETE;
	n->fileid = ++v->nextid;
	n->parent = parent;
	if (parent) {
		/* append (keeps creation order, like most servers' listings) */
		MNode **pp = &parent->child;
		while (*pp)
			pp = &(*pp)->next;
		*pp = n;
		parent->mtime = n->mtime;
	}
	return n;
}

static void node_unlink(MNode *n)
{
	MNode **pp;
	if (!n->parent)
		return;
	for (pp = &n->parent->child; *pp; pp = &(*pp)->next)
		if (*pp == n) {
			*pp = n->next;
			break;
		}
	n->parent->mtime = ln_time_unix();
	n->parent = NULL;
	n->next = NULL;
}

static void node_free(MVol *v, MNode *n)
{
	while (n->child) {
		MNode *c = n->child;
		n->child = c->next;
		node_free(v, c);
	}
	v->used -= n->size;
	ln_free(n->data);
	ln_free(n->name);
	ln_free(n);
}

static MNode *child(MVol *v, MNode *d, const char *name, size_t len)
{
	MNode *c;
	char tmp[256];
	if (len >= sizeof(tmp))
		return NULL;
	memcpy(tmp, name, len);
	tmp[len] = 0;
	for (c = d->child; c; c = c->next)
		if (name_eq(v, c->name, tmp))
			return c;
	return NULL;
}

static int bad_component(const char *s, size_t len)
{
	return len == 0 || len > 255 || (len == 1 && s[0] == '.') || (len == 2 && s[0] == '.' && s[1] == '.');
}

/* walk path; returns LN_OK + node, or error. With parent_out the last
 * component may be missing: *out = NULL, *parent_out = its directory,
 * *last = the last name. */
static int walk(MVol *v, const char *path, MNode **out, MNode **parent_out, const char **last)
{
	MNode *cur = v->root;
	const char *p = path;
	*out = NULL;
	if (parent_out)
		*parent_out = NULL;
	if (!*p) {
		*out = cur;
		return LN_OK;
	}
	for (;;) {
		const char *e = strchr(p, '/');
		size_t len = e ? (size_t)(e - p) : strlen(p);
		MNode *c;
		if (bad_component(p, len))
			return LN_EINVAL;
		if (cur->type != LN_T_DIR)
			return LN_ENOTDIR;
		c = child(v, cur, p, len);
		if (!e) {
			if (parent_out) {
				*parent_out = cur;
				*last = p;
			}
			if (!c)
				return LN_ENOENT;
			*out = c;
			return LN_OK;
		}
		if (!c)
			return LN_ENOENT;
		cur = c;
		p = e + 1;
	}
}

static void fill(const MNode *n, LnStat *st)
{
	memset(st, 0, sizeof(*st));
	st->type = n->type;
	st->size = n->type == LN_T_FILE ? n->size : 0;
	st->mtime = n->mtime;
	st->ctime = n->ctime;
	st->prot = n->prot;
	st->mode = n->type == LN_T_DIR ? 040755 : 0100644;
	st->fileid = n->fileid;
	ln_strlcpy(st->comment, n->comment, sizeof(st->comment));
}

static int set_size(MVol *v, MNode *n, u64 size)
{
	if (size > n->size && v->used + (size - n->size) > v->capacity)
		return LN_ENOSPC;
	if (size > n->cap) {
		u64 cap = n->cap ? n->cap : 1024;
		u8 *d;
		while (cap < size)
			cap *= 2;
		if (cap > 0x7fffffffUL)
			return LN_ENOSPC;
		d = ln_realloc(n->data, (size_t)n->size, (size_t)cap);
		if (!d)
			return LN_ENOMEM;
		n->data = d;
		n->cap = cap;
	}
	if (size > n->size)
		memset(n->data + n->size, 0, (size_t)(size - n->size));
	v->used = v->used - n->size + size;
	n->size = size;
	n->mtime = ln_time_unix();
	return LN_OK;
}

/* ---- sample content for seed=1 ---- */
static void seed_file(MVol *v, MNode *d, const char *name, const char *text, u32 prot)
{
	MNode *n = node_new(v, d, name, LN_T_FILE);
	if (n && text && set_size(v, n, strlen(text)) == LN_OK)
		memcpy(n->data, text, strlen(text));
	if (n && prot)
		n->prot = prot;
}

static void seed(MVol *v, int many)
{
	MNode *r = v->root, *d, *s;
	char name[300];
	int i;
	seed_file(v, r, "ReadMe.txt", "Hello from the Lagoon mem backend.\n", 0);
	seed_file(v, r, "MixedCase.TXT", "mixed case\n", 0);
	/* the handler shows this one as "a%3Ab.txt" */
	seed_file(v, r, "a:b.txt", "colon\n", 0);
	/* U+00DC U+00EF (Latin-1) and U+017F (not Latin-1: escaped) */
	seed_file(v, r, "\xc3\x9cn\xc3\xaf-\xc5\xbf.txt", "unicode\n", 0);
	/* longer than a FileInfoBlock name (107) */
	for (i = 0; i < 130; i++)
		name[i] = (char)('a' + i % 26);
	strcpy(name + 130, ".txt");
	seed_file(v, r, name, "long name\n", 0);
	seed_file(v, r, "script", "Echo \"script from the share ran\"\n",
	          LN_P_READ | LN_P_WRITE | LN_P_EXEC | LN_P_DELETE | LN_P_SCRIPT);
	if ((d = node_new(v, r, "Dir1", LN_T_DIR)) != NULL && (s = node_new(v, d, "sub", LN_T_DIR)) != NULL)
		seed_file(v, s, "deep.txt", "deep\n", 0);
	if (many > 0 && (d = node_new(v, r, "Many", LN_T_DIR)) != NULL)
		for (i = 0; i < many; i++) {
			ln_snprintf(name, sizeof(name), "file%05d", i);
			seed_file(v, d, name, NULL, 0);
		}
}

/* ---- LnOps ---- */
static int m_mount(const LnUrl *u, const LnCreds *cr, LnFs **out)
{
	char key[260], buf[64];
	MVol *v;
	LnFs *fs;
	ln_snprintf(key, sizeof(key), "%s/%s", u->host, u->share);
	if (!u->share[0])
		return LN_ENOSHARE;
	ln_strlcpy(buf, ln_url_opt(u, "pass", "", buf, sizeof(buf)), sizeof(buf));
	if (buf[0] && strcmp(buf, cr ? cr->password : ""))
		return LN_EAUTH;
	fs = ln_alloc(sizeof(*fs));
	if (!fs)
		return LN_ENOMEM;
	for (v = vols; v; v = v->next)
		if (!strcmp(v->key, key))
			break;
	if (!v) {
		v = ln_alloc(sizeof(*v));
		if (!v) {
			ln_free(fs);
			return LN_ENOMEM;
		}
		ln_strlcpy(v->key, key, sizeof(v->key));
		v->capacity = (u64)(unsigned long)ln_url_opt_int(u, "size", 64 * 1024 * 1024);
		v->casefold = ln_url_opt_int(u, "casefold", 0);
		v->root = node_new(v, NULL, "", LN_T_DIR);
		if (!v->root) {
			ln_free(v);
			ln_free(fs);
			return LN_ENOMEM;
		}
		if (ln_url_opt_int(u, "seed", 0))
			seed(v, ln_url_opt_int(u, "many", 0));
		v->next = vols;
		vols = v;
	}
	v->refs++;
	fs->v = v;
	fs->connected = 1;
	fs->ro = ln_url_opt_int(u, "ro", 0);
	fs->stale = ln_url_opt_int(u, "stale", 0);
	fs->maxio = ln_url_opt_int(u, "maxio", 16384);
	if (fs->maxio < 512)
		fs->maxio = 512;
	fs->dropevery = (u32)ln_url_opt_int(u, "dropevery", 0);
	fs->refuse = ln_url_opt_int(u, "refuse", 0);
	ln_strlcpy(fs->label, ln_url_opt(u, "label", u->share, fs->label, sizeof(fs->label)), sizeof(fs->label));
	if (buf[0])
		ln_strlcpy(fs->pass, buf, sizeof(fs->pass));
	*out = fs;
	return LN_OK;
}

static void m_unmount(LnFs *fs)
{
	MVol *v = fs->v, **pp;
	if (--v->refs == 0) {
		for (pp = &vols; *pp; pp = &(*pp)->next)
			if (*pp == v) {
				*pp = v->next;
				break;
			}
		node_free(v, v->root);
		ln_free(v);
	}
	ln_wipe(fs->pass, sizeof(fs->pass));
	ln_free(fs);
}

static int m_reconnect(LnFs *fs)
{
	if (fs->connected)
		return LN_OK;
	if (fs->refuse_left > 0) {
		fs->refuse_left--;
		return LN_ECONNREFUSED;
	}
	fs->connected = 1;
	if (fs->stale)
		fs->epoch++;
	LN_LOG(2, "mem: reconnected");
	return LN_OK;
}

static int m_ping(LnFs *fs) { return gate(fs); }

static int m_statfs(LnFs *fs, LnStatFs *st)
{
	int r = gate(fs);
	if (r)
		return r;
	memset(st, 0, sizeof(*st));
	st->total_bytes = fs->v->capacity;
	st->free_bytes = fs->v->capacity - fs->v->used;
	st->block_size = 1024;
	st->readonly = fs->ro;
	ln_strlcpy(st->volume, fs->label, sizeof(st->volume));
	return LN_OK;
}

static int m_stat(LnFs *fs, const char *path, LnStat *st)
{
	MNode *n;
	int r = gate(fs);
	if (r || (r = walk(fs->v, path, &n, NULL, NULL)))
		return r;
	fill(n, st);
	return LN_OK;
}

static int m_opendir(LnFs *fs, const char *path, LnDir **out)
{
	MNode *n, *c;
	LnDir *d;
	int r = gate(fs), k = 0;
	if (r || (r = walk(fs->v, path, &n, NULL, NULL)))
		return r;
	if (n->type != LN_T_DIR)
		return LN_ENOTDIR;
	d = ln_alloc(sizeof(*d));
	if (!d)
		return LN_ENOMEM;
	for (c = n->child; c; c = c->next)
		d->n++;
	d->e = ln_alloc(sizeof(MEnt) * (size_t)(d->n ? d->n : 1));
	if (!d->e) {
		ln_free(d);
		return LN_ENOMEM;
	}
	for (c = n->child; c; c = c->next, k++) {
		d->e[k].name = ln_strdup(c->name);
		fill(c, &d->e[k].st);
	}
	d->fs = fs;
	*out = d;
	return LN_OK;
}

static int m_readdir(LnDir *d, char *name, size_t namemax, LnStat *st)
{
	int r = gate(d->fs);
	if (r)
		return r;
	if (d->i >= d->n)
		return 0;
	if (!d->e[d->i].name)
		return LN_ENOMEM;
	if (ln_strlcpy(name, d->e[d->i].name, namemax) >= namemax)
		return LN_ENAMETOOLONG;
	*st = d->e[d->i].st;
	d->i++;
	return 1;
}

static void m_closedir(LnDir *d)
{
	int i;
	for (i = 0; i < d->n; i++)
		ln_free(d->e[i].name);
	ln_free(d->e);
	ln_free(d);
}

static int m_open(LnFs *fs, const char *path, int flags, LnFile **out)
{
	MNode *n, *dir;
	const char *last;
	LnFile *f;
	int r = gate(fs);
	if (r)
		return r;
	if (!(flags & (LN_O_READ | LN_O_WRITE)))
		return LN_EINVAL;
	if (fs->ro && (flags & (LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC)))
		return LN_EROFS;
	r = walk(fs->v, path, &n, &dir, &last);
	if (r == LN_ENOENT && dir && (flags & LN_O_CREATE)) {
		if (!(n = node_new(fs->v, dir, last, LN_T_FILE)))
			return LN_ENOMEM;
	} else if (r)
		return r;
	else if (flags & LN_O_EXCL)
		return LN_EEXIST;
	else if (n->type == LN_T_DIR)
		return LN_EISDIR;
	else if (((flags & LN_O_READ) && !(n->prot & LN_P_READ)) ||
	         ((flags & (LN_O_WRITE | LN_O_TRUNC)) && !(n->prot & LN_P_WRITE)))
		return LN_EACCES;
	else if (flags & LN_O_TRUNC) {
		if ((r = set_size(fs->v, n, 0)) != LN_OK)
			return r;
	}
	f = ln_alloc(sizeof(*f));
	if (!f)
		return LN_ENOMEM;
	f->fs = fs;
	f->n = n;
	f->flags = flags;
	f->epoch = fs->epoch;
	n->opens++;
	*out = f;
	return LN_OK;
}

static long m_read(LnFile *f, u64 off, void *buf, long n)
{
	int r = fgate(f);
	MNode *m = f->n;
	if (r)
		return r;
	if (!(f->flags & LN_O_READ))
		return LN_EACCES;
	if (n < 0)
		return LN_EINVAL;
	if (off >= m->size)
		return 0;
	if ((u64)n > m->size - off)
		n = (long)(m->size - off);
	memcpy(buf, m->data + off, (size_t)n);
	return n;
}

static long m_write(LnFile *f, u64 off, const void *buf, long n)
{
	int r = fgate(f);
	MNode *m = f->n;
	if (r)
		return r;
	if (!(f->flags & LN_O_WRITE))
		return LN_EACCES;
	if (n < 0)
		return LN_EINVAL;
	if (off + (u64)n > m->size) {
		r = set_size(f->fs->v, m, off + (u64)n);
		if (r == LN_ENOSPC && off < m->size)
			n = (long)(m->size - off);     /* partial write up to the old end */
		else if (r)
			return r;
	}
	memcpy(m->data + off, buf, (size_t)n);
	m->mtime = ln_time_unix();
	return n;
}

static int m_fstat(LnFile *f, LnStat *st)
{
	int r = fgate(f);
	if (r)
		return r;
	fill(f->n, st);
	return LN_OK;
}

static int m_truncate(LnFile *f, u64 size)
{
	int r = fgate(f);
	if (r)
		return r;
	if (!(f->flags & LN_O_WRITE))
		return LN_EACCES;
	return set_size(f->fs->v, f->n, size);
}

static int m_flush(LnFile *f) { return fgate(f); }

static int m_close(LnFile *f)
{
	/* close always releases the handle, even when "disconnected" */
	MNode *n = f->n;
	if (--n->opens == 0 && n->unlinked)
		node_free(f->fs->v, n);
	ln_free(f);
	return LN_OK;
}

static int m_mkdir(LnFs *fs, const char *path)
{
	MNode *n, *dir;
	const char *last;
	int r = gate(fs);
	if (r)
		return r;
	if (fs->ro)
		return LN_EROFS;
	r = walk(fs->v, path, &n, &dir, &last);
	if (r == LN_OK)
		return LN_EEXIST;
	if (r != LN_ENOENT || !dir)
		return r;
	return node_new(fs->v, dir, last, LN_T_DIR) ? LN_OK : LN_ENOMEM;
}

static int m_remove(LnFs *fs, const char *path)
{
	MNode *n;
	int r = gate(fs);
	if (r || (r = walk(fs->v, path, &n, NULL, NULL)))
		return r;
	if (fs->ro)
		return LN_EROFS;
	if (n == fs->v->root)
		return LN_EINVAL;
	if (n->type == LN_T_DIR && n->child)
		return LN_ENOTEMPTY;
	if (!(n->prot & LN_P_DELETE))
		return LN_EACCES;
	node_unlink(n);
	if (n->opens)
		n->unlinked = 1;           /* Unix semantics: freed on last close */
	else
		node_free(fs->v, n);
	return LN_OK;
}

static int m_rename(LnFs *fs, const char *from, const char *to)
{
	MNode *n, *t, *dir, *a;
	const char *last;
	char *nm;
	int r = gate(fs);
	if (r || (r = walk(fs->v, from, &n, NULL, NULL)))
		return r;
	if (fs->ro)
		return LN_EROFS;
	if (n == fs->v->root)
		return LN_EINVAL;
	r = walk(fs->v, to, &t, &dir, &last);
	if (r == LN_OK && t != n)
		return LN_EEXIST;
	if (r != LN_OK && (r != LN_ENOENT || !dir))
		return r;
	if (r == LN_OK)
		dir = n->parent;           /* case-only rename of the same object */
	for (a = dir; a; a = a->parent)
		if (a == n)
			return LN_EINVAL;      /* into its own subtree */
	nm = ln_strdup(ln_path_base(to));
	if (!nm)
		return LN_ENOMEM;
	if (dir != n->parent) {
		MNode **pp;
		node_unlink(n);
		n->parent = dir;
		for (pp = &dir->child; *pp; pp = &(*pp)->next)
			;
		*pp = n;
	}
	ln_free(n->name);
	n->name = nm;
	dir->mtime = ln_time_unix();
	return LN_OK;
}

static int m_setattr(LnFs *fs, const char *path, const LnStat *st, u32 mask)
{
	MNode *n;
	int r = gate(fs);
	if (r || (r = walk(fs->v, path, &n, NULL, NULL)))
		return r;
	if (fs->ro)
		return LN_EROFS;
	if ((mask & LN_SET_SIZE) && n->type != LN_T_FILE)
		return LN_EISDIR;
	if ((mask & LN_SET_SIZE) && (r = set_size(fs->v, n, st->size)) != LN_OK)
		return r;
	if (mask & LN_SET_PROT)
		n->prot = st->prot & 0xff;
	if (mask & LN_SET_COMMENT)
		ln_strlcpy(n->comment, st->comment, sizeof(n->comment));
	if (mask & LN_SET_MTIME)
		n->mtime = st->mtime;
	return LN_OK;
}

static int m_list_shares(const LnUrl *u, const LnCreds *cr, ln_share_cb cb, void *ud)
{
	MVol *v;
	size_t hl = strlen(u->host);
	int found = 0;
	(void)cr;
	for (v = vols; v; v = v->next)
		if (!strncmp(v->key, u->host, hl) && v->key[hl] == '/') {
			cb(ud, v->key + hl + 1, "in-memory volume");
			if (!strcmp(v->key + hl + 1, "vol"))
				found = 1;
		}
	if (!found)
		cb(ud, "vol", "in-memory volume");
	return LN_OK;
}

static long m_max_io(LnFs *fs) { return fs->maxio; }

const LnOps ln_mem_ops = {
	"mem", "In-memory test file system", 0,
	m_mount, m_unmount, m_reconnect, m_ping,
	m_statfs, m_stat,
	m_opendir, m_readdir, m_closedir,
	m_open, m_read, m_write, m_fstat, m_truncate, m_flush, m_close,
	m_mkdir, m_remove, m_rename, m_setattr,
	m_list_shares, m_max_io
};
