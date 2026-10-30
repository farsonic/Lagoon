/*
 * Lagoon - lagoon-handler's portable core (see hcore.h).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "hcore.h"
#include "ln_sys.h"
#include "ln_charset.h"

/* ------------------------------------------------------------ helpers -- */

static u32 now_ms(void) { return ln_ms(); }
static int older(u32 stamp, u32 ms) { return (u32)(now_ms() - stamp) >= ms; }

static int lat1_lower(int c)
{
	if ((c >= 'A' && c <= 'Z') || (c >= 0xC0 && c <= 0xDE && c != 0xD7))
		return c + 32;
	return c;
}

static u32 fold_hash(const char *s)
{
	u32 h = 2166136261UL;
	while (*s) {
		h ^= (u32)lat1_lower((u8)*s++);
		h *= 16777619UL;
	}
	return h;
}

static u32 str_hash(const char *s)
{
	u32 h = 2166136261UL;
	while (*s) {
		h ^= (u8)*s++;
		h *= 16777619UL;
	}
	return h;
}

/* same object? remote paths compare case-insensitively (Amiga semantics:
 * "Foo" and "foo" are one name) */
static int path_eq(const char *a, const char *b) { return !ln_amiga_stricmp(a, b); }

/* is p inside dir (dir/...)? */
static int path_under(const char *p, const char *dir)
{
	size_t l = strlen(dir);
	if (!l)
		return *p != 0;
	return strlen(p) > l && p[l] == '/' && !ln_strncasecmp(p, dir, l);
}

static u32 path_key(const char *rpath, u64 fileid)
{
	if (fileid)
		return (u32)(fileid ^ (fileid >> 32)) | 1;
	return fold_hash(rpath) | 1;
}

void hc_latin1_to_utf8(const char *in, char *out, size_t n)
{
	size_t k = 0;
	while (*in && k + 2 < n) {
		u8 c = (u8)*in++;
		if (c < 0x80)
			out[k++] = (char)c;
		else {
			out[k++] = (char)(0xC0 | (c >> 6));
			out[k++] = (char)(0x80 | (c & 0x3F));
		}
	}
	if (n)
		out[k < n ? k : n - 1] = 0;
}

void hc_utf8_to_latin1(const char *in, char *out, size_t n)
{
	size_t k = 0, l = strlen(in);
	while (l && k + 1 < n) {
		u32 cp;
		int u = ln_utf8_decode(in, l, &cp);
		out[k++] = (char)(cp <= 0xFF ? cp : '?');
		in += u;
		l -= (size_t)u;
	}
	if (n)
		out[k] = 0;
}

static const char hexd[] = "0123456789ABCDEF";

/* cut an escaped name to at most max bytes without splitting a %XX */
static size_t cut_name(const char *s, size_t max)
{
	size_t l = strlen(s);
	if (l <= max)
		return l;
	l = max;
	if (l >= 1 && s[l - 1] == '%')
		l -= 1;
	else if (l >= 2 && s[l - 2] == '%')
		l -= 2;
	return l;
}

static void add_suffix(char *out, size_t keep, const char *rname, int salt)
{
	u32 h = str_hash(rname) + (u32)salt * 0x9E3779B1UL;
	h ^= h >> 16;
	out[keep] = '~';
	out[keep + 1] = hexd[(h >> 12) & 15];
	out[keep + 2] = hexd[(h >> 8) & 15];
	out[keep + 3] = hexd[(h >> 4) & 15];
	out[keep + 4] = hexd[h & 15];
	out[keep + 5] = 0;
}

void hc_amiga_name(const char *rname, char *out)
{
	char *b = ln_alloc(1024);
	int r;
	if (!b) {
		ln_strlcpy(out, "?", HC_NAMEMAX + 1);
		return;
	}
	r = ln_name_to_amiga(rname, b, 1024);
	if (r < 0) {
		/* absurdly long: escape a prefix only */
		char *t = ln_alloc(256);
		size_t l = 0;
		if (t) {
			while (rname[l] && l < 200)
				l++;
			while (l && ((u8)rname[l] & 0xC0) == 0x80)
				l--;
			memcpy(t, rname, l);
			t[l] = 0;
			r = ln_name_to_amiga(t, b, 1024);
			ln_free(t);
		}
		if (r < 0)
			b[0] = 0;
		r = HC_NAMEMAX + 1;    /* force the suffix */
	}
	if (r <= HC_NAMEMAX && b[0])
		memcpy(out, b, (size_t)r + 1);
	else {
		size_t keep = cut_name(b, HC_NAMEMAX - 5);
		memcpy(out, b, keep);
		add_suffix(out, keep, rname, 0);
	}
	ln_free(b);
}

/* ------------------------------------------------------- string pool -- */

struct HPool {
	struct HPool *next;
	size_t used, size;
	char   data[4];
};

static char *pool_dup(HPool **pp, const char *s)
{
	size_t l = strlen(s) + 1;
	HPool *p = *pp;
	char *r;
	if (!p || p->used + l > p->size) {
		size_t sz = l > 4000 ? l : 4000;
		HPool *q = ln_alloc(sizeof(HPool) + sz);
		if (!q)
			return NULL;
		q->size = sz;
		q->next = p;
		*pp = p = q;
	}
	r = p->data + p->used;
	memcpy(r, s, l);
	p->used += l;
	return r;
}

static void pool_free(HPool *p)
{
	while (p) {
		HPool *n = p->next;
		ln_free(p);
		p = n;
	}
}

/* ------------------------------------------------------------ listings -- */

static void list_unref(HList *l)
{
	if (l && --l->refs == 0) {
		pool_free(l->pool);
		ln_free(l->e);
		ln_free(l->hash);
		ln_free(l->dir);
		ln_free(l);
	}
}

static int list_find_fold(const HList *l, const char *aname, int skip)
{
	u32 i = fold_hash(aname) & (u32)(l->hsize - 1);
	while (l->hash[i] >= 0) {
		if (l->hash[i] != skip && !ln_amiga_stricmp(l->e[l->hash[i]].aname, aname))
			return l->hash[i];
		i = (i + 1) & (u32)(l->hsize - 1);
	}
	return -1;
}

/* find by Amiga name: exact display name first, then the exact remote
 * name (rn: aname decoded, may be NULL; a name shown with a "~XXXX" suffix
 * can still be opened under its real name), then case-insensitive */
static const HEnt *list_lookup(const HList *l, const char *aname, const char *rn)
{
	u32 i;
	int first = -1;
	if (!l->hsize)
		return NULL;
	i = fold_hash(aname) & (u32)(l->hsize - 1);
	while (l->hash[i] >= 0) {
		const HEnt *e = &l->e[l->hash[i]];
		if (!strcmp(e->aname, aname))
			return e;
		if (first < 0 && !ln_amiga_stricmp(e->aname, aname))
			first = l->hash[i];
		i = (i + 1) & (u32)(l->hsize - 1);
	}
	if (rn)
		for (i = 0; i < (u32)l->n; i++)
			if (!strcmp(l->e[i].rname, rn))
				return &l->e[i];
	return first >= 0 ? &l->e[first] : NULL;
}

static int list_index(HList *l)
{
	int i, hs = 16;
	while (hs < l->n * 2)
		hs *= 2;
	l->hash = ln_alloc(sizeof(int) * (size_t)hs);
	if (!l->hash)
		return LN_ENOMEM;
	l->hsize = hs;
	for (i = 0; i < hs; i++)
		l->hash[i] = -1;
	for (i = 0; i < l->n; i++) {
		HEnt *e = &l->e[i];
		u32 j;
		int salt = 0;
		/* two remote names that are one name to the Amiga (case, or a
		 * shared truncated prefix): rename the later one */
		while (list_find_fold(l, e->aname, i) >= 0 && salt < 8) {
			char nm[HC_NAMEMAX + 1];
			size_t keep;
			ln_strlcpy(nm, e->aname, sizeof(nm));
			keep = cut_name(nm, HC_NAMEMAX - 5);
			add_suffix(nm, keep, e->rname, ++salt);
			e->aname = pool_dup(&l->pool, nm);
			if (!e->aname)
				return LN_ENOMEM;
		}
		j = fold_hash(e->aname) & (u32)(hs - 1);
		while (l->hash[j] >= 0)
			j = (j + 1) & (u32)(hs - 1);
		l->hash[j] = i;
	}
	return LN_OK;
}

static void stat_from_ent(const HEnt *e, LnStat *st)
{
	memset(st, 0, sizeof(*st));
	st->type = e->type;
	st->size = e->size;
	st->mtime = e->mtime;
	st->ctime = e->ctime;
	st->prot = e->prot;
	st->uid = e->uid;
	st->gid = e->gid;
	st->fileid = e->fileid;
	if (e->comment)
		ln_strlcpy(st->comment, e->comment, sizeof(st->comment));
}

/* ----------------------------------------------------------- reconnect -- */

void hc_cache_clear(HC *h)
{
	int i;
	for (i = 0; i < HC_NLISTS; i++) {
		list_unref(h->lists[i]);
		h->lists[i] = NULL;
	}
	for (i = 0; i < HC_NATTR; i++) {
		ln_free(h->attr[i].path);
		h->attr[i].path = NULL;
	}
	h->sfs_valid = 0;
}

static int try_reconnect(HC *h)
{
	int r = h->ops->reconnect ? h->ops->reconnect(h->fs) : LN_ENOTSUP;
	h->last_try = now_ms();
	if (r == LN_OK) {
		h->offline = 0;
		h->reconnects++;
		h->last_net = now_ms();
		hc_cache_clear(h);
		LN_LOG(1, "reconnected to the server");
	}
	return r;
}

int hc_reconnect(HC *h)
{
	u32 start = now_ms(), wait = 500;
	int r;
	if (h->offline)           /* already gave up: one quick attempt */
		return try_reconnect(h) == LN_OK ? LN_OK : LN_ECONNRESET;
	LN_LOG(1, "connection lost, reconnecting");
	for (;;) {
		r = try_reconnect(h);
		if (r == LN_OK)
			return LN_OK;
		LN_LOG(1, "reconnect failed: %s", ln_strerror(r));
		if (r == LN_EAUTH || ln_break() || (u32)(now_ms() - start) + wait > h->reconnect_ms)
			break;
		if (h->sleep_ms)
			h->sleep_ms(wait);
		if (wait < 8000)
			wait *= 2;
	}
	h->offline = 1;
	h->last_try = now_ms();
	LN_LOG(0, "server unreachable, giving up for now");
	return LN_ECONNRESET;
}

/* before each request: while offline, fail fast except every retry_ms */
static int ready(HC *h)
{
	h->last_io = now_ms();
	if (!h->offline)
		return LN_OK;
	if (!older(h->last_try, h->retry_ms))
		return LN_ECONNRESET;
	return try_reconnect(h) == LN_OK ? LN_OK : LN_ECONNRESET;
}

/* a backend call; after a lost connection reconnect and try again (up to
 * three times: a listing can be long enough to see two drops) */
#define RETRY(h, r, call) do { \
	int try_ = 0; \
	(r) = (call); \
	while ((r) == LN_ECONNRESET && try_++ < 3 && hc_reconnect(h) == LN_OK) \
		(r) = (call); \
	if ((r) != LN_ECONNRESET) \
		(h)->last_net = now_ms(); \
} while (0)

/* --------------------------------------------------------------- caches -- */

static void attr_put(HC *h, const char *path, const LnStat *st)
{
	int i, slot = -1;
	for (i = 0; i < HC_NATTR; i++)
		if (h->attr[i].path && !strcmp(h->attr[i].path, path)) {
			slot = i;
			break;
		}
	if (slot < 0) {
		slot = h->attr_next;
		h->attr_next = (h->attr_next + 1) % HC_NATTR;
		ln_free(h->attr[slot].path);
		h->attr[slot].path = ln_strdup(path);
		if (!h->attr[slot].path)
			return;
	}
	h->attr[slot].st = *st;
	h->attr[slot].stamp = now_ms();
}

static int attr_get(HC *h, const char *path, LnStat *st)
{
	int i;
	for (i = 0; i < HC_NATTR; i++)
		if (h->attr[i].path && !strcmp(h->attr[i].path, path)) {
			if (older(h->attr[i].stamp, h->ttl_ms))
				return 0;
			*st = h->attr[i].st;
			return 1;
		}
	return 0;
}

static HList *list_cached(HC *h, const char *dir)
{
	int i;
	for (i = 0; i < HC_NLISTS; i++) {
		HList *l = h->lists[i];
		if (l && !strcmp(l->dir, dir)) {
			if (older(l->stamp, h->ttl_ms)) {
				list_unref(l);
				h->lists[i] = NULL;
				return NULL;
			}
			return l;
		}
	}
	return NULL;
}

/* something changed at path (tree: also below it): forget what we know */
static void invalidate(HC *h, const char *path, int tree)
{
	char parent[HC_PATHMAX];
	int i;
	ln_path_parent(parent, sizeof(parent), path);
	for (i = 0; i < HC_NATTR; i++) {
		const char *p = h->attr[i].path;
		if (p && (path_eq(p, path) || (tree && path_under(p, path)))) {
			ln_free(h->attr[i].path);
			h->attr[i].path = NULL;
		}
	}
	for (i = 0; i < HC_NLISTS; i++) {
		HList *l = h->lists[i];
		if (l && (path_eq(l->dir, parent) || path_eq(l->dir, path) || (tree && path_under(l->dir, path)))) {
			list_unref(l);
			h->lists[i] = NULL;
		}
	}
	h->sfs_valid = 0;
}

static int read_listing(HC *h, const char *dir, HList **out)
{
	HList *l;
	LnDir *d = NULL;
	char *name;
	LnStat *st;
	int r;
	name = ln_alloc(1024 + sizeof(LnStat) + HC_NAMEMAX + 1);
	if (!name)
		return LN_ENOMEM;
	st = (LnStat *)(void *)(name + 1024);
	l = ln_alloc(sizeof(*l));
	if (!l || !(l->dir = ln_strdup(dir))) {
		ln_free(l);
		ln_free(name);
		return LN_ENOMEM;
	}
	l->refs = 1;
	r = h->ops->opendir(h->fs, dir, &d);
	while (r == LN_OK) {
		HEnt *e;
		char *an = name + 1024 + sizeof(LnStat);
		r = h->ops->readdir(d, name, 1024, st);
		if (r == LN_ENAMETOOLONG) {          /* skip it, keep listing */
			LN_LOG(1, "skipping an entry with a name over 1023 bytes in \"%s\"", dir);
			r = LN_OK;
			continue;
		}
		if (r <= 0)
			break;
		r = LN_OK;
		if (!strcmp(name, ".") || !strcmp(name, ".."))
			continue;
		if (l->n == l->cap) {
			int nc = l->cap ? l->cap * 2 : 32;
			HEnt *ne = ln_realloc(l->e, sizeof(HEnt) * (size_t)l->cap, sizeof(HEnt) * (size_t)nc);
			if (!ne) {
				r = LN_ENOMEM;
				break;
			}
			l->e = ne;
			l->cap = nc;
		}
		e = &l->e[l->n];
		memset(e, 0, sizeof(*e));
		hc_amiga_name(name, an);
		e->rname = pool_dup(&l->pool, name);
		e->aname = pool_dup(&l->pool, an);
		if (st->comment[0])
			e->comment = pool_dup(&l->pool, st->comment);
		if (!e->rname || !e->aname || (st->comment[0] && !e->comment)) {
			r = LN_ENOMEM;
			break;
		}
		e->type = st->type == LN_T_DIR ? LN_T_DIR : LN_T_FILE;
		e->size = st->size;
		e->mtime = st->mtime;
		e->ctime = st->ctime;
		e->prot = st->prot;
		e->uid = st->uid;
		e->gid = st->gid;
		e->fileid = st->fileid;
		l->n++;
	}
	if (d)
		h->ops->closedir(d);
	ln_free(name);
	if (r == LN_OK)
		r = list_index(l);
	if (r != LN_OK) {
		list_unref(l);
		return r;
	}
	l->stamp = now_ms();
	*out = l;
	return LN_OK;
}

/* listing of dir: from the cache or read now; returned with a reference */
static int get_listing(HC *h, const char *dir, int fresh, HList **out)
{
	HList *l = fresh ? NULL : list_cached(h, dir);
	int r, i, slot = 0;
	if (l) {
		l->refs++;
		*out = l;
		return LN_OK;
	}
	RETRY(h, r, read_listing(h, dir, &l));
	if (r != LN_OK)
		return r;
	/* cache it (replace this dir's old entry, an empty slot, or the oldest) */
	for (i = 0; i < HC_NLISTS; i++) {
		if (h->lists[i] && !strcmp(h->lists[i]->dir, dir)) {
			slot = i;
			break;
		}
		if (!h->lists[i])
			slot = i;
		else if (h->lists[slot] && (u32)(now_ms() - h->lists[i]->stamp) > (u32)(now_ms() - h->lists[slot]->stamp))
			slot = i;
	}
	list_unref(h->lists[slot]);
	h->lists[slot] = l;
	l->refs++;
	*out = l;
	return LN_OK;
}

static int do_stat(HC *h, const char *path, LnStat *st)
{
	int r;
	if (attr_get(h, path, st))
		return LN_OK;
	RETRY(h, r, h->ops->stat(h->fs, path, st));
	if (r == LN_OK) {
		if (st->type != LN_T_DIR)
			st->type = LN_T_FILE;
		attr_put(h, path, st);
	} else if (!path[0] && r != LN_ECONNRESET) {
		/* some servers cannot stat the share root: it is a directory */
		memset(st, 0, sizeof(*st));
		st->type = LN_T_DIR;
		st->prot = LN_P_READ | LN_P_WRITE | LN_P_EXEC | LN_P_DELETE;
		r = LN_OK;
	}
	return r;
}

/* ------------------------------------------------------------ resolving -- */

/* child of dir named aname (Amiga name): fills child rpath + stat */
static int lookup(HC *h, const char *dir, const char *aname, char *child, LnStat *st)
{
	HList *l;
	const HEnt *e;
	char *rn;
	int r, ok;
	if (strlen(aname) > 255)
		return LN_ENOENT;
	rn = ln_alloc(1024);
	if (!rn)
		return LN_ENOMEM;
	ok = ln_name_from_amiga(aname, rn, 1024) >= 0 && !strchr(rn, '/') && rn[0];
	l = list_cached(h, dir);
	if (!l) {
		/* direct: the name as typed (exact on case-insensitive servers too) */
		r = ok ? ln_path_join(child, HC_PATHMAX, dir, rn) : LN_ENOENT;
		if (r == LN_OK) {
			r = do_stat(h, child, st);
			if (r == LN_OK) {
				ln_free(rn);
				return LN_OK;
			}
		}
		if (r != LN_ENOENT && r != LN_EINVAL && r != LN_ENAMETOOLONG) {
			ln_free(rn);
			return r;
		}
		/* not there: maybe another case, a truncated or escaped name */
		r = get_listing(h, dir, 0, &l);
		if (r != LN_OK) {
			ln_free(rn);
			return r;
		}
		l->refs--;            /* the cache keeps it */
	}
	e = list_lookup(l, aname, ok ? rn : NULL);
	ln_free(rn);
	if (!e)
		return LN_ENOENT;
	stat_from_ent(e, st);
	return ln_path_join(child, HC_PATHMAX, dir, e->rname);
}

/* Resolve apath relative to base (rpath, type). On success out = rpath,
 * *st = attributes. With newname != NULL, a missing last component is
 * not an error: returns LN_ENOENT with out = the path to create and
 * *newname = 1 (its directory exists). */
static int resolve(HC *h, const char *base, int btype, const char *apath, char *out, LnStat *st, int *newname)
{
	const char *p = apath, *colon = strchr(apath, ':');
	char *comp, *tmp;
	int r = LN_OK, type = btype;
	if (newname)
		*newname = 0;
	if (colon) {
		if (strchr(colon + 1, ':'))
			return LN_EINVAL;
		p = colon + 1;
		base = "";
		type = LN_T_DIR;
	}
	if (strlen(base) >= HC_PATHMAX)
		return LN_ENAMETOOLONG;
	comp = ln_alloc(256 + HC_PATHMAX);
	if (!comp)
		return LN_ENOMEM;
	tmp = comp + 256;
	strcpy(out, base);
	memset(st, 0, sizeof(*st));
	st->type = type;
	if (!*p) {
		/* the base itself: refresh its attributes */
		r = do_stat(h, out, st);
	}
	while (r == LN_OK && *p == '/') {      /* leading '/' = parent */
		if (!out[0]) {
			r = LN_ENOENT;
			break;
		}
		ln_path_parent(tmp, HC_PATHMAX, out);
		strcpy(out, tmp);
		p++;
		r = do_stat(h, out, st);
	}
	while (r == LN_OK && *p) {
		const char *e = strchr(p, '/');
		size_t len = e ? (size_t)(e - p) : strlen(p);
		if (len > 255) {
			r = newname ? LN_EINVAL : LN_ENOENT;
			break;
		}
		memcpy(comp, p, len);
		comp[len] = 0;
		if (st->type != LN_T_DIR) {
			r = LN_ENOTDIR;
			break;
		}
		r = lookup(h, out, comp, tmp, st);
		if (r == LN_ENOENT && newname && (!e || !e[1])) {
			/* the name to create */
			char *rn = ln_alloc(1024);
			if (!rn) {
				r = LN_ENOMEM;
				break;
			}
			if (!strcmp(comp, ".") || !strcmp(comp, "..") || len > HC_NAMEMAX ||
			    ln_name_from_amiga(comp, rn, 1024) < 0 || strchr(rn, '/') || !rn[0])
				r = LN_EINVAL;
			else if (ln_path_join(tmp, HC_PATHMAX, out, rn) != LN_OK)
				r = LN_ENAMETOOLONG;
			else {
				strcpy(out, tmp);
				*newname = 1;
			}
			ln_free(rn);
			break;
		}
		if (r != LN_OK)
			break;
		strcpy(out, tmp);
		if (!e)
			break;
		p = e + 1;
		while (r == LN_OK && *p == '/') {  /* "a//b": each extra '/' = parent */
			if (!out[0]) {
				r = LN_ENOENT;
				break;
			}
			ln_path_parent(tmp, HC_PATHMAX, out);
			strcpy(out, tmp);
			p++;
			r = do_stat(h, out, st);
		}
	}
	if (newname && *newname)
		r = LN_ENOENT;
	ln_free(comp);
	return r;
}

/* the typed final component of apath, as a remote name */
static int last_remote_name(const char *apath, char *rn, size_t n)
{
	const char *p = strchr(apath, ':'), *s;
	size_t len;
	char comp[256];
	p = p ? p + 1 : apath;
	len = strlen(p);
	while (len && p[len - 1] == '/')
		return LN_EINVAL;
	s = p + len;
	while (s > p && s[-1] != '/')
		s--;
	len = (size_t)(p + strlen(p) - s);
	if (!len || len > HC_NAMEMAX || !strcmp(s, ".") || !strcmp(s, ".."))
		return LN_EINVAL;
	memcpy(comp, s, len);
	comp[len] = 0;
	if (ln_name_from_amiga(comp, rn, n) < 0 || strchr(rn, '/'))
		return LN_EINVAL;
	return LN_OK;
}

/* ---------------------------------------------------- lock bookkeeping -- */

/* would a new (excl or shared) user of rpath conflict with the existing
 * locks and open files? skip_l / skip_f: the object being changed */
static int conflict(HC *h, const char *rpath, int excl, const HLock *skip_l, const HFile *skip_f)
{
	const HLock *l;
	const HFile *f;
	for (l = h->locks; l; l = l->next)
		if (l != skip_l && path_eq(l->rpath, rpath) && (excl || l->excl))
			return LN_EINUSE;
	for (f = h->files; f; f = f->next)
		if (f != skip_f && path_eq(f->rpath, rpath) && (excl || f->excl))
			return LN_EINUSE;
	return LN_OK;
}

static int in_use(HC *h, const char *rpath)
{
	return conflict(h, rpath, 1, NULL, NULL) != LN_OK;
}

static int new_lock(HC *h, const char *rpath, int excl, const LnStat *st, HLock **out)
{
	HLock *l;
	int r = conflict(h, rpath, excl, NULL, NULL);
	if (r)
		return r;
	l = ln_alloc(sizeof(*l));
	if (!l || !(l->rpath = ln_strdup(rpath))) {
		ln_free(l);
		return LN_ENOMEM;
	}
	l->excl = excl;
	l->type = st->type == LN_T_DIR ? LN_T_DIR : LN_T_FILE;
	l->key = rpath[0] ? path_key(rpath, st->fileid) : 1;
	l->next = h->locks;
	h->locks = l;
	h->nlocks++;
	*out = l;
	return LN_OK;
}

static const char *base_path(const HLock *b) { return b ? b->rpath : ""; }
static int base_type(const HLock *b) { return b ? b->type : LN_T_DIR; }

int hc_lock(HC *h, HLock *base, const char *apath, int excl, HLock **out)
{
	char *p;
	LnStat st;
	int r = ready(h);
	if (r)
		return r;
	p = ln_alloc(HC_PATHMAX);
	if (!p)
		return LN_ENOMEM;
	r = resolve(h, base_path(base), base_type(base), apath, p, &st, NULL);
	if (r == LN_OK)
		r = new_lock(h, p, excl, &st, out);
	ln_free(p);
	return r;
}

void hc_unlock(HC *h, HLock *l)
{
	HLock **pp;
	if (!l)
		return;
	for (pp = &h->locks; *pp; pp = &(*pp)->next)
		if (*pp == l) {
			*pp = l->next;
			h->nlocks--;
			break;
		}
	list_unref(l->snap);
	ln_free(l->rpath);
	ln_free(l);
}

int hc_duplock(HC *h, HLock *l, HLock **out)
{
	LnStat st;
	memset(&st, 0, sizeof(st));
	if (!l) {
		st.type = LN_T_DIR;
		return new_lock(h, "", 0, &st, out);
	}
	if (l->excl)
		return LN_EINUSE;
	st.type = l->type;
	{
		int r = new_lock(h, l->rpath, 0, &st, out);
		if (r == LN_OK)
			(*out)->key = l->key;
		return r;
	}
}

static int lock_dir_of(HC *h, const char *rpath, HLock **out)
{
	char *p;
	LnStat st;
	int r;
	if (!rpath[0]) {
		*out = NULL;
		return LN_OK;
	}
	p = ln_alloc(HC_PATHMAX);
	if (!p)
		return LN_ENOMEM;
	ln_path_parent(p, HC_PATHMAX, rpath);
	memset(&st, 0, sizeof(st));
	st.type = LN_T_DIR;
	if (p[0]) {
		/* fl_Key of the parent should match a lock taken by name */
		LnStat s2;
		if (do_stat(h, p, &s2) == LN_OK)
			st.fileid = s2.fileid;
	}
	r = new_lock(h, p, 0, &st, out);
	ln_free(p);
	return r;
}

int hc_parent(HC *h, HLock *l, HLock **out)
{
	*out = NULL;
	if (!l)
		return LN_OK;
	return lock_dir_of(h, l->rpath, out);
}

int hc_lock_file(HC *h, HFile *f, HLock **out)
{
	/* a shared lock even if the file was opened exclusively, so that
	 * NameFromFH() works on MODE_NEWFILE files */
	HLock *l = ln_alloc(sizeof(*l));
	if (!l || !(l->rpath = ln_strdup(f->rpath))) {
		ln_free(l);
		return LN_ENOMEM;
	}
	l->type = LN_T_FILE;
	l->key = f->key;
	l->next = h->locks;
	h->locks = l;
	h->nlocks++;
	*out = l;
	return LN_OK;
}

int hc_parent_file(HC *h, HFile *f, HLock **out)
{
	return lock_dir_of(h, f->rpath, out);
}

int hc_change_lock(HC *h, HLock *l, int excl)
{
	int r;
	if (excl && (r = conflict(h, l->rpath, 1, l, NULL)) != LN_OK)
		return r;
	l->excl = excl;
	return LN_OK;
}

int hc_change_file(HC *h, HFile *f, int excl)
{
	int r;
	if (excl && (r = conflict(h, f->rpath, 1, NULL, f)) != LN_OK)
		return r;
	f->excl = excl;
	return LN_OK;
}

int hc_same_lock(const HLock *a, const HLock *b)
{
	const char *pa = a ? a->rpath : "", *pb = b ? b->rpath : "";
	return path_eq(pa, pb);
}

/* ------------------------------------------------------------- files ---- */

static long fop(HC *h, HFile *f, int op, u64 off, void *buf, long n);

static int flush_file(HC *h, HFile *f)
{
	long done = 0;
	if (!f->dirty)
		return LN_OK;
	while (done < f->blen) {
		long w = fop(h, f, 1, f->boff + (u64)done, f->buf + done, f->blen - done);
		if (w <= 0) {
			f->dirty = 0;
			f->blen = 0;
			f->err = w < 0 ? (int)w : LN_EIO;
			return f->err;
		}
		done += w;
	}
	h->bytes_written += (u64)f->blen;
	f->dirty = 0;
	f->blen = 0;
	invalidate(h, f->rpath, 0);
	return LN_OK;
}

static void flush_path(HC *h, const char *rpath)
{
	HFile *f;
	for (f = h->files; f; f = f->next)
		if (f->dirty && path_eq(f->rpath, rpath))
			flush_file(h, f);
}

/* files directly in dir: a listing should show their real sizes */
static void flush_under(HC *h, const char *dir)
{
	HFile *f;
	char *par = ln_alloc(HC_PATHMAX);
	if (!par)
		return;
	for (f = h->files; f; f = f->next)
		if (f->dirty) {
			ln_path_parent(par, HC_PATHMAX, f->rpath);
			if (path_eq(par, dir))
				flush_file(h, f);
		}
	ln_free(par);
}

static int reopen(HC *h, HFile *f)
{
	LnFile *lf = NULL;
	int r = h->ops->open(h->fs, f->rpath, f->oflags, &lf);
	if (r == LN_OK) {
		LN_LOG(1, "reopened \"%s\" after reconnect", f->rpath);
		f->lf = lf;    /* the old handle died with the connection */
	}
	return r;
}

static long fop1(HC *h, HFile *f, int op, u64 off, void *buf, long n)
{
	if (!f->lf)
		return LN_ESTALE;
	switch (op) {
	case 0: return h->ops->read(f->lf, off, buf, n);
	case 1: return h->ops->write(f->lf, off, buf, n);
	case 2: return h->ops->truncate(f->lf, off);
	case 3: return h->ops->fstat(f->lf, (LnStat *)buf);
	default: return h->ops->flush ? h->ops->flush(f->lf) : LN_OK;
	}
}

/* one backend file operation with reconnect / reopen */
static long fop(HC *h, HFile *f, int op, u64 off, void *buf, long n)
{
	long r = fop1(h, f, op, off, buf, n);
	if (r == LN_ECONNRESET) {
		if (hc_reconnect(h) != LN_OK)
			return LN_ECONNRESET;
		r = fop1(h, f, op, off, buf, n);
	}
	if (r == LN_ESTALE) {
		if (f->lf) {
			h->ops->close(f->lf);
			f->lf = NULL;
		}
		if (reopen(h, f) == LN_OK)
			r = fop1(h, f, op, off, buf, n);
	}
	if (r != LN_ECONNRESET)
		h->last_net = now_ms();
	return r;
}

static int add_file(HC *h, const char *rpath, int excl, int oflags, LnFile *lf, const LnStat *st, HFile **out)
{
	HFile *f = ln_alloc(sizeof(*f));
	if (!f || !(f->rpath = ln_strdup(rpath)) || !(f->buf = ln_alloc((size_t)h->bufsize))) {
		if (f)
			ln_free(f->rpath);
		ln_free(f);
		return LN_ENOMEM;
	}
	f->excl = excl;
	f->oflags = oflags;
	f->lf = lf;
	f->size = st->size;
	f->key = path_key(rpath, st->fileid);
	f->next = h->files;
	h->files = f;
	h->nfiles++;
	*out = f;
	return LN_OK;
}

int hc_open(HC *h, HLock *base, const char *apath, int mode, HFile **out)
{
	char *p;
	LnStat st;
	LnFile *lf = NULL;
	int r = ready(h), isnew = 0, flags, excl = mode == HC_NEW;
	if (r)
		return r;
	p = ln_alloc(HC_PATHMAX);
	if (!p)
		return LN_ENOMEM;
	r = resolve(h, base_path(base), base_type(base), apath, p, &st, mode == HC_OLD ? NULL : &isnew);
	if (r == LN_ENOENT && isnew)
		r = h->readonly ? LN_EROFS : LN_OK;
	else if (r == LN_OK && st.type == LN_T_DIR)
		r = LN_EISDIR;
	if (r == LN_OK)
		r = conflict(h, p, excl, NULL, NULL);
	if (r == LN_OK && mode == HC_NEW && h->readonly)
		r = LN_EROFS;
	if (r == LN_OK) {
		flags = LN_O_READ | LN_O_WRITE;
		if (mode == HC_NEW)
			flags |= LN_O_CREATE | LN_O_TRUNC;
		else if (mode == HC_RW && isnew)
			flags |= LN_O_CREATE;
		if (h->readonly)
			flags = LN_O_READ;
		RETRY(h, r, h->ops->open(h->fs, p, flags, &lf));
		if ((r == LN_EACCES || r == LN_EROFS) && mode != HC_NEW && !isnew && flags != LN_O_READ) {
			/* write protected: MODE_OLDFILE/READWRITE still read */
			flags = LN_O_READ;
			RETRY(h, r, h->ops->open(h->fs, p, flags, &lf));
		}
		if (r == LN_OK) {
			if (isnew || mode == HC_NEW) {
				st.size = 0;
				invalidate(h, p, 0);
			}
			{
				LnStat fs;
				if (h->ops->fstat && h->ops->fstat(lf, &fs) == LN_OK)
					st = fs;
			}
			r = add_file(h, p, excl, flags & (LN_O_READ | LN_O_WRITE), lf, &st, out);
			if (r != LN_OK)
				h->ops->close(lf);
		}
	}
	ln_free(p);
	return r;
}

int hc_open_lock(HC *h, HLock *l, HFile **out)
{
	LnFile *lf = NULL;
	LnStat st;
	int r = ready(h), flags = h->readonly ? LN_O_READ : LN_O_READ | LN_O_WRITE;
	if (r)
		return r;
	if (l->type == LN_T_DIR)
		return LN_EISDIR;
	RETRY(h, r, h->ops->open(h->fs, l->rpath, flags, &lf));
	if ((r == LN_EACCES || r == LN_EROFS) && flags != LN_O_READ) {
		flags = LN_O_READ;
		RETRY(h, r, h->ops->open(h->fs, l->rpath, flags, &lf));
	}
	if (r != LN_OK)
		return r;
	memset(&st, 0, sizeof(st));
	if (h->ops->fstat(lf, &st) != LN_OK)
		do_stat(h, l->rpath, &st);
	r = add_file(h, l->rpath, l->excl, flags, lf, &st, out);
	if (r != LN_OK) {
		h->ops->close(lf);
		return r;
	}
	(*out)->key = l->key;
	hc_unlock(h, l);
	return LN_OK;
}

long hc_read(HC *h, HFile *f, void *buf, long n)
{
	u8 *dst = buf;
	long total = 0;
	h->last_io = now_ms();
	if (f->err) {
		int e = f->err;
		f->err = 0;
		return e;
	}
	if (!(f->oflags & LN_O_READ))
		return LN_EACCES;
	if (f->dirty) {
		int r = flush_file(h, f);
		if (r) {
			f->err = 0;
			return r;
		}
	}
	flush_path(h, f->rpath);     /* other handles' delayed writes first */
	while (n > 0) {
		long got;
		if (f->blen > 0 && f->pos >= f->boff && f->pos < f->boff + (u64)f->blen) {
			long off = (long)(f->pos - f->boff), k = f->blen - off;
			if (k > n)
				k = n;
			memcpy(dst, f->buf + off, (size_t)k);
			dst += k;
			n -= k;
			total += k;
			f->pos += (u64)k;
			continue;
		}
		if (n >= h->bufsize) {
			/* big request: straight into the caller's buffer */
			long chunk = n > h->maxio ? h->maxio : n;
			got = fop(h, f, 0, f->pos, dst, chunk);
			if (got < 0)
				return total ? total : got;
			if (got == 0)
				break;
			h->bytes_read += (u64)got;
			dst += got;
			n -= got;
			total += got;
			f->pos += (u64)got;
			continue;
		}
		f->boff = f->pos;
		f->blen = 0;
		got = fop(h, f, 0, f->pos, f->buf, h->bufsize);
		if (got < 0)
			return total ? total : got;
		if (got == 0)
			break;
		h->bytes_read += (u64)got;
		f->blen = got;
	}
	if (f->pos > f->size)
		f->size = f->pos;
	return total;
}

long hc_write(HC *h, HFile *f, const void *buf, long n)
{
	const u8 *src = buf;
	long total = 0;
	int r;
	h->last_io = now_ms();
	if (f->err) {
		r = f->err;
		f->err = 0;
		return r;
	}
	if (h->readonly)
		return LN_EROFS;
	if (!(f->oflags & LN_O_WRITE))
		return LN_EACCES;
	if (n <= 0)
		return 0;
	if (!f->dirty)
		f->blen = 0;            /* drop read-ahead data */
	{
		HFile *o;               /* and other handles' on the same file */
		for (o = h->files; o; o = o->next)
			if (o != f && !o->dirty && path_eq(o->rpath, f->rpath))
				o->blen = 0;
	}
	invalidate(h, f->rpath, 0);
	if (f->dirty && f->pos == f->boff + (u64)f->blen && f->blen + n <= h->bufsize) {
		memcpy(f->buf + f->blen, src, (size_t)n);
		f->blen += n;
		f->pos += (u64)n;
		if (f->pos > f->size)
			f->size = f->pos;
		return n;
	}
	if ((r = flush_file(h, f)) != LN_OK) {
		f->err = 0;
		return r;
	}
	if (n < h->bufsize) {
		memcpy(f->buf, src, (size_t)n);
		f->boff = f->pos;
		f->blen = n;
		f->dirty = 1;
		f->pos += (u64)n;
		if (f->pos > f->size)
			f->size = f->pos;
		return n;
	}
	while (n > 0) {
		long chunk = n > h->maxio ? h->maxio : n;
		long w = fop(h, f, 1, f->pos, (void *)src, chunk);
		if (w <= 0) {
			if (total)
				break;
			return w < 0 ? w : LN_EIO;
		}
		h->bytes_written += (u64)w;
		src += w;
		n -= w;
		total += w;
		f->pos += (u64)w;
		if (f->pos > f->size)
			f->size = f->pos;
		if (w < chunk)
			break;
	}
	return total;
}

int hc_seek(HC *h, HFile *f, s64 off, int mode, u64 *oldpos)
{
	s64 np;
	h->last_io = now_ms();
	*oldpos = f->pos;
	if (mode == HC_SEEK_END && !f->dirty) {
		/* someone else may have changed the file */
		LnStat st;
		if (fop(h, f, 3, 0, &st, 0) == LN_OK && st.size > f->size)
			f->size = st.size;
	}
	if (mode == HC_SEEK_SET)
		np = off;
	else if (mode == HC_SEEK_CUR)
		np = (s64)f->pos + off;
	else if (mode == HC_SEEK_END)
		np = (s64)f->size + off;
	else
		return LN_EINVAL;
	if (np < 0 || (u64)np > f->size)
		return LN_EINVAL;
	f->pos = (u64)np;
	return LN_OK;
}

int hc_set_size(HC *h, HFile *f, s64 off, int mode, u64 *newsize)
{
	s64 ns;
	int r;
	h->last_io = now_ms();
	if (h->readonly)
		return LN_EROFS;
	if (!(f->oflags & LN_O_WRITE))
		return LN_EACCES;
	if ((r = flush_file(h, f)) != LN_OK) {
		f->err = 0;
		return r;
	}
	if (mode == HC_SEEK_SET)
		ns = off;
	else if (mode == HC_SEEK_CUR)
		ns = (s64)f->pos + off;
	else if (mode == HC_SEEK_END)
		ns = (s64)f->size + off;
	else
		return LN_EINVAL;
	if (ns < 0)
		return LN_EINVAL;
	r = (int)fop(h, f, 2, (u64)ns, NULL, 0);
	if (r != LN_OK)
		return r;
	f->blen = 0;
	f->size = (u64)ns;
	if (f->pos > f->size)
		f->pos = f->size;
	invalidate(h, f->rpath, 0);
	*newsize = f->size;
	return LN_OK;
}

int hc_close(HC *h, HFile *f)
{
	HFile **pp;
	int r = flush_file(h, f), c;
	if (!r)
		r = f->err;
	if (f->oflags & LN_O_WRITE)
		invalidate(h, f->rpath, 0);
	c = f->lf ? h->ops->close(f->lf) : LN_OK;
	if (!r && c != LN_ECONNRESET && c != LN_ESTALE)
		r = c;
	for (pp = &h->files; *pp; pp = &(*pp)->next)
		if (*pp == f) {
			*pp = f->next;
			h->nfiles--;
			break;
		}
	ln_free(f->buf);
	ln_free(f->rpath);
	ln_free(f);
	return r;
}

int hc_flush_all(HC *h)
{
	HFile *f;
	int r = LN_OK;
	for (f = h->files; f; f = f->next) {
		int e = flush_file(h, f);
		if (e && !r)
			r = e;
	}
	return r;
}

int hc_dirty(const HC *h)
{
	const HFile *f;
	for (f = h->files; f; f = f->next)
		if (f->dirty)
			return 1;
	return 0;
}

int hc_stat_file(HC *h, HFile *f, LnStat *st)
{
	long r;
	flush_file(h, f);
	r = fop(h, f, 3, 0, st, 0);
	if (r != LN_OK)
		r = do_stat(h, f->rpath, st);
	if (r == LN_OK && st->size < f->size)
		st->size = f->size;
	if (r == LN_OK && st->type != LN_T_DIR)
		st->type = LN_T_FILE;
	return (int)r;
}

int hc_stat_lock(HC *h, HLock *l, LnStat *st)
{
	int r = ready(h);
	const char *p = base_path(l);
	if (r)
		return r;
	flush_path(h, p);
	r = do_stat(h, p, st);
	if (r == LN_OK && l)
		l->type = st->type;
	return r;
}

int hc_next(HC *h, HLock *l, u32 *idx, const HEnt **e)
{
	int r;
	if (l && l->type != LN_T_DIR)
		return 0;
	if (*idx == 0 || !l || !l->snap) {
		HList *s;
		if ((r = ready(h)) != LN_OK)
			return r;
		if (!l)
			return LN_EINVAL;
		flush_under(h, l->rpath);
		r = get_listing(h, l->rpath, 0, &s);
		if (r != LN_OK)
			return r;
		list_unref(l->snap);
		l->snap = s;
		if (*idx > (u32)s->n)
			*idx = (u32)s->n;
	}
	if (*idx >= (u32)l->snap->n) {
		hc_end_scan(h, l);
		return 0;
	}
	*e = &l->snap->e[*idx];
	(*idx)++;
	return 1;
}

void hc_end_scan(HC *h, HLock *l)
{
	(void)h;
	if (l) {
		list_unref(l->snap);
		l->snap = NULL;
	}
}

/* ---------------------------------------------------------- namespace -- */

int hc_delete(HC *h, HLock *base, const char *apath)
{
	char *p;
	LnStat st;
	int r = ready(h);
	if (r)
		return r;
	p = ln_alloc(HC_PATHMAX);
	if (!p)
		return LN_ENOMEM;
	r = resolve(h, base_path(base), base_type(base), apath, p, &st, NULL);
	if (r == LN_OK && !p[0])
		r = LN_EINUSE;
	if (r == LN_OK && in_use(h, p))
		r = LN_EINUSE;
	if (r == LN_OK && h->readonly)
		r = LN_EROFS;
	if (r == LN_OK) {
		RETRY(h, r, h->ops->remove(h->fs, p));
		invalidate(h, p, st.type == LN_T_DIR);
	}
	ln_free(p);
	return r;
}

static void repath(char **pp, const char *from, const char *to, char *tmp)
{
	char *d;
	if (!path_eq(*pp, from) && !path_under(*pp, from))
		return;
	ln_snprintf(tmp, HC_PATHMAX, "%s%s", to, *pp + strlen(from));
	if ((d = ln_strdup(tmp)) != NULL) {
		ln_free(*pp);
		*pp = d;
	}
}

/* locks and open files follow a rename of their object or a parent */
static void rename_paths(HC *h, const char *from, const char *to)
{
	HLock *l;
	HFile *f;
	char *tmp = ln_alloc(HC_PATHMAX);
	if (!tmp)
		return;
	for (l = h->locks; l; l = l->next)
		repath(&l->rpath, from, to, tmp);
	for (f = h->files; f; f = f->next)
		repath(&f->rpath, from, to, tmp);
	ln_free(tmp);
}

int hc_rename(HC *h, HLock *b1, const char *a1, HLock *b2, const char *a2)
{
	char *from, *to, *rn;
	LnStat st, st2;
	int r = ready(h), isnew = 0;
	if (r)
		return r;
	from = ln_alloc(HC_PATHMAX * 2 + 1024);
	if (!from)
		return LN_ENOMEM;
	to = from + HC_PATHMAX;
	rn = to + HC_PATHMAX;
	r = resolve(h, base_path(b1), base_type(b1), a1, from, &st, NULL);
	if (r == LN_OK && !from[0])
		r = LN_EINUSE;
	if (r == LN_OK && h->readonly)
		r = LN_EROFS;
	if (r == LN_OK) {
		r = resolve(h, base_path(b2), base_type(b2), a2, to, &st2, &isnew);
		if (r == LN_ENOENT && isnew)
			r = LN_OK;
		else if (r == LN_OK) {
			if (!path_eq(from, to))
				r = LN_EEXIST;
			else if ((r = last_remote_name(a2, rn, 1024)) == LN_OK) {
				/* the same object under another case: rename to the typed name */
				ln_path_parent(to, HC_PATHMAX, from);
				r = ln_path_join(to, HC_PATHMAX, to, rn);
				if (r == LN_OK && !strcmp(from, to)) {
					ln_free(from);
					return LN_OK;
				}
			}
		} else if (r == LN_ENOENT && !isnew)
			r = LN_ENOENT;
	}
	if (r == LN_OK && path_under(to, from))
		r = LN_EINUSE;    /* a directory into itself */
	if (r == LN_OK) {
		flush_path(h, from);
		RETRY(h, r, h->ops->rename(h->fs, from, to));
		invalidate(h, from, 1);
		invalidate(h, to, 1);
		if (r == LN_OK)
			rename_paths(h, from, to);
	}
	ln_free(from);
	return r;
}

int hc_mkdir(HC *h, HLock *base, const char *apath, HLock **out)
{
	char *p;
	LnStat st;
	int r = ready(h), isnew = 0;
	if (r)
		return r;
	p = ln_alloc(HC_PATHMAX);
	if (!p)
		return LN_ENOMEM;
	r = resolve(h, base_path(base), base_type(base), apath, p, &st, &isnew);
	if (r == LN_OK)
		r = LN_EEXIST;
	else if (r == LN_ENOENT && isnew)
		r = h->readonly ? LN_EROFS : LN_OK;
	if (r == LN_OK) {
		RETRY(h, r, h->ops->mkdir(h->fs, p));
		invalidate(h, p, 0);
		if (r == LN_OK) {
			LnStat s2;
			memset(&s2, 0, sizeof(s2));
			s2.type = LN_T_DIR;
			do_stat(h, p, &s2);
			s2.type = LN_T_DIR;
			r = new_lock(h, p, 1, &s2, out);
		}
	}
	ln_free(p);
	return r;
}

int hc_setattr(HC *h, HLock *base, const char *apath, const LnStat *st, u32 mask)
{
	char *p;
	LnStat cur;
	int r = ready(h);
	if (r)
		return r;
	p = ln_alloc(HC_PATHMAX);
	if (!p)
		return LN_ENOMEM;
	r = resolve(h, base_path(base), base_type(base), apath, p, &cur, NULL);
	if (r == LN_OK && h->readonly)
		r = LN_EROFS;
	if (r == LN_OK) {
		LnStat ns = *st;
		/* the Amiga has no "hidden" bit: keep the server's */
		if (mask & LN_SET_PROT)
			ns.prot = (ns.prot & ~(u32)LN_P_HIDDEN) | (cur.prot & LN_P_HIDDEN);
		flush_path(h, p);
		RETRY(h, r, h->ops->setattr(h->fs, p, &ns, mask));
		invalidate(h, p, 0);
	}
	ln_free(p);
	return r;
}

int hc_statfs(HC *h, LnStatFs *st)
{
	int r = ready(h);
	if (r)
		return r;
	if (h->sfs_valid && !older(h->sfs_stamp, 5000)) {
		*st = h->sfs;
		return LN_OK;
	}
	RETRY(h, r, h->ops->statfs(h->fs, st));
	if (r == LN_OK) {
		h->sfs = *st;
		h->sfs_stamp = now_ms();
		h->sfs_valid = 1;
	}
	return r;
}

/* ---------------------------------------------------------------- misc -- */

int hc_idle(HC *h)
{
	int r = LN_OK;
	HFile *f;
	if (h->offline)
		return LN_ECONNRESET;
	if (older(h->last_io, 1000))
		for (f = h->files; f; f = f->next)
			if (f->dirty && (r = flush_file(h, f)) != LN_OK)
				LN_LOG(0, "delayed write to \"%s\" failed: %s", f->rpath, ln_strerror(r));
	if (h->ops->ping && older(h->last_net, h->ping_ms)) {
		RETRY(h, r, h->ops->ping(h->fs));
		LN_LOG(2, "keep-alive: %s", ln_strerror(r));
		h->last_net = now_ms();    /* do not hammer a dead server */
	}
	return r;
}

int hc_init(HC *h, const LnOps *ops, LnFs *fs, int readonly)
{
	memset(h, 0, sizeof(*h));
	h->ops = ops;
	h->fs = fs;
	h->readonly = readonly;
	h->maxio = ops->max_io ? ops->max_io(fs) : 16384;
	if (h->maxio < 512)
		h->maxio = 512;
	if (h->maxio > 1024 * 1024)
		h->maxio = 1024 * 1024;
	/* read-ahead / write-behind unit: one backend request, at most 64 KB */
	h->bufsize = h->maxio > 65536 ? 65536 : h->maxio;
	h->ttl_ms = 3000;
	h->reconnect_ms = 30000;
	h->retry_ms = 10000;
	h->ping_ms = 60000;
	h->last_net = h->last_io = now_ms();
	return LN_OK;
}

void hc_free(HC *h)
{
	while (h->files)
		hc_close(h, h->files);
	while (h->locks)
		hc_unlock(h, h->locks);
	hc_cache_clear(h);
}
