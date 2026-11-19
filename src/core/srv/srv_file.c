/*
 * Lagoon - SMB2 server: TREE_CONNECT/DISCONNECT, CREATE, CLOSE, FLUSH,
 * READ, WRITE, LOCK (granted, not enforced), QUERY_DIRECTORY, QUERY_INFO,
 * SET_INFO and IOCTL, on the shares' LnOps backends (MS-SMB2 3.3.5,
 * MS-FSCC 2.4/2.5 for the information classes).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "srv_int.h"
#include "../ln_charset.h"
#include "../ln_conf.h"

/* CREATE dispositions and options */
#define FILE_SUPERSEDE    0
#define FILE_OPEN         1
#define FILE_CREATE       2
#define FILE_OPEN_IF      3
#define FILE_OVERWRITE    4
#define FILE_OVERWRITE_IF 5
#define CO_DIRECTORY      0x00000001u
#define CO_NON_DIRECTORY  0x00000040u
#define CO_DELETE_ON_CLOSE 0x00001000u

typedef struct Info {
	u64 ctime, mtime, size, alloc, fileid;
	u32 attrs;
	int dir;
} Info;

static LnSrvShare *share_of(LnSrvConn *c, SrvTree *t)
{
	return t && t->share >= 0 ? &c->srv->share[t->share] : NULL;
}

u32 srv_status(int e)
{
	switch (e) {
	case LN_OK: return ST_OK;
	case LN_ENOENT: return ST_OBJECT_NAME_NOT_FOUND;
	case LN_EEXIST: return ST_OBJECT_NAME_COLLISION;
	case LN_ENOTDIR: return ST_OBJECT_PATH_NOT_FOUND;
	case LN_EISDIR: return ST_FILE_IS_A_DIRECTORY;
	case LN_ENOTEMPTY: return ST_DIRECTORY_NOT_EMPTY;
	case LN_EACCES: return ST_ACCESS_DENIED;
	case LN_EROFS: return ST_MEDIA_WRITE_PROTECTED;
	case LN_ENOSPC: return ST_DISK_FULL;
	case LN_EINUSE: return ST_SHARING_VIOLATION;
	case LN_EINVAL: return ST_OBJECT_NAME_INVALID;
	case LN_ENAMETOOLONG: return ST_NAME_TOO_LONG;
	case LN_ENOMEM: return ST_INSUFFICIENT_RESOURCES;
	case LN_ENOTSUP: return ST_NOT_SUPPORTED;
	}
	return ST_IO_DEVICE_ERROR;
}

static u64 path_id(const char *p)
{
	u64 h = 1469598103934665603ULL;
	while (*p)
		h = (h ^ (u8)*p++) * 1099511628211ULL;
	return h ? h : 1;
}

static void info_from(const LnStat *st, const char *path, Info *in)
{
	memset(in, 0, sizeof(*in));
	in->dir = st->type == LN_T_DIR;
	in->mtime = smb_unix2ft(st->mtime);
	in->ctime = smb_unix2ft(st->ctime ? st->ctime : st->mtime);
	in->size = in->dir ? 0 : st->size;
	in->alloc = (in->size + 4095) & ~(u64)4095;
	in->fileid = st->fileid ? st->fileid : path_id(path);
	if (in->dir)
		in->attrs |= FA_DIRECTORY;
	if (!(st->prot & LN_P_WRITE) && !in->dir)
		in->attrs |= FA_READONLY;
	if (st->prot & LN_P_HIDDEN)
		in->attrs |= FA_HIDDEN;
	if (!(st->prot & LN_P_ARCHIVE) && !in->dir)
		in->attrs |= FA_ARCHIVE;
	if (!in->attrs)
		in->attrs = FA_NORMAL;
}

/* -------------------------------------------------------------- paths */

u32 srv_path(LnSrvConn *c, const u8 *p16, size_t bytes, char *out, size_t max)
{
	char *raw = ln_alloc(1100), *nfc = ln_alloc(1100);
	size_t i, k = 0, comp = 0;
	u32 st = ST_OK;
	int n;
	if (!raw || !nfc) {
		ln_free(raw); ln_free(nfc);
		return ST_INSUFFICIENT_RESOURCES;
	}
	if (bytes > 2000 || srv_utf16_to_utf8(p16, bytes, raw, 1100) < 0) {
		st = ST_NAME_TOO_LONG;
		goto out;
	}
	n = ln_utf8_nfc(raw, nfc, 1100);
	if (n < 0) {
		st = ST_NAME_TOO_LONG;
		goto out;
	}
	nfc[n] = 0;
	/* streams: only the unnamed data stream */
	{
		size_t l = strlen(nfc);
		if (l >= 7 && !ln_strcasecmp(nfc + l - 7, "::$DATA"))
			nfc[l - 7] = 0;
	}
	for (i = 0;; i++) {
		char ch = nfc[i];
		if (ch == '\\' || ch == '/' || ch == 0) {
			/* end of a component */
			size_t cl = k - comp;
			if (cl == 0) {
				/* empty component: skip */
			} else if (cl == 1 && out[comp] == '.') {
				k = comp;
			} else if (cl == 2 && out[comp] == '.' && out[comp + 1] == '.') {
				st = ST_OBJECT_PATH_SYNTAX_BAD;
				goto out;
			} else {
				if (cl > (size_t)c->srv->cfg.name_max) {
					st = ST_NAME_TOO_LONG;
					goto out;
				}
				if (k + 1 >= max) {
					st = ST_NAME_TOO_LONG;
					goto out;
				}
				out[k++] = '/';
			}
			comp = k;
			if (!ch)
				break;
			continue;
		}
		if ((u8)ch < 0x20 || ch == ':' || ch == '*' || ch == '?' || ch == '"' || ch == '<' || ch == '>' || ch == '|') {
			st = ST_OBJECT_NAME_INVALID;
			goto out;
		}
		if (k + 2 >= max) {
			st = ST_NAME_TOO_LONG;
			goto out;
		}
		out[k++] = ch;
	}
	while (k && out[k - 1] == '/')
		k--;
	out[k] = 0;
out:
	if (st)
		out[0] = 0;
	ln_free(raw);
	ln_free(nfc);
	return st;
}

/* -------------------------------------------------------------- trees */

void srv_tree_free(LnSrvConn *c, SrvSession *s, SrvTree *t)
{
	SrvTree **pp;
	SrvOpen *o, *on;
	for (o = c->opens; o; o = on) {
		on = o->next;
		if (o->tree == t)
			srv_close_open(c, o);
	}
	for (pp = &s->trees; *pp; pp = &(*pp)->next)
		if (*pp == t) {
			*pp = t->next;
			break;
		}
	if (c->tree == t)
		c->tree = NULL;
	ln_free(t);
}

void srv_tree_connect(LnSrvConn *c)
{
	const u8 *b = c->body;
	SrvSession *s = c->sess;
	char path[300], *nm;
	u16 off, len;
	int i, idx = -2, ro = 0;
	SrvTree *t;
	u8 *r;
	if (c->blen < 8 || ln_le16(b) != 9) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	off = ln_le16(b + 4);
	len = ln_le16(b + 6);
	if (off < SMB2_HDR + 8 || (u32)off + len > c->reqlen || srv_utf16_to_utf8(c->req + off, len, path, sizeof(path)) < 0) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	nm = strrchr(path, '\\');
	nm = nm ? nm + 1 : path;
	if (!ln_strcasecmp(nm, "IPC$"))
		idx = -1;
	else
		for (i = 0; i < c->srv->nshares; i++)
			if (!ln_strcasecmp(c->srv->share[i].name, nm)) {
				idx = i;
				break;
			}
	if (idx == -2) {
		LN_LOG(1, "server: %s: no share \"%s\"", c->peer, nm);
		srv_error(c, ST_BAD_NETWORK_NAME, NULL, 0);
		return;
	}
	if (idx >= 0) {
		LnSrvShare *sh = &c->srv->share[idx];
		int ok;
		if (s->guest || s->anon)
			ok = sh->guest;
		else
			ok = !sh->users[0] || ln_conf_user_listed(sh->users, s->user) || sh->guest;
		if (!ok) {
			LN_LOG(1, "server: %s: %s may not use \"%s\"", c->peer, s->guest || s->anon ? "guest" : s->user, sh->name);
			srv_error(c, ST_ACCESS_DENIED, NULL, 0);
			return;
		}
		ro = sh->readonly;
	}
	t = ln_alloc(sizeof(SrvTree));
	if (!t) {
		srv_error(c, ST_INSUFFICIENT_RESOURCES, NULL, 0);
		return;
	}
	t->id = s->next_tid++;
	t->share = idx;
	t->readonly = ro;
	t->maxacc = ro || idx < 0 ? A_ALL_RO : A_ALL_RW;
	t->next = s->trees;
	s->trees = t;
	c->tree = t;
	ln_put_le32(c->tx + c->resp_off + 36, t->id);
	r = srv_body(c, 16);
	if (!r)
		return;
	ln_put_le16(r, 16);
	r[2] = idx < 0 ? 2 : 1;
	ln_put_le32(r + 4, idx < 0 ? 0x30u : 0);   /* IPC$: no caching */
	ln_put_le32(r + 8, 0);
	ln_put_le32(r + 12, t->maxacc);
	LN_LOG(2, "server: %s: tree %u = %s", c->peer, t->id, idx < 0 ? "IPC$" : c->srv->share[idx].name);
}

void srv_tree_disconnect(LnSrvConn *c)
{
	u8 *r;
	srv_tree_free(c, c->sess, c->tree);
	r = srv_body(c, 4);
	if (r)
		ln_put_le16(r, 4);
}

/* -------------------------------------------------------------- opens */

void srv_close_open(LnSrvConn *c, SrvOpen *o)
{
	SrvOpen **pp;
	LnSrvShare *sh = share_of(c, o->tree);
	if (sh) {
		if (o->f)
			sh->ops->close(o->f);
		o->f = NULL;
		if (o->dir && o->dir->d)
			sh->ops->closedir(o->dir->d);
		if (o->set_mtime && !o->delete_on_close) {
			LnStat st;
			memset(&st, 0, sizeof(st));
			st.mtime = o->mtime;
			sh->ops->setattr(sh->fs, o->path, &st, LN_SET_MTIME);
		}
		if (o->delete_on_close) {
			/* deleted when the last handle goes (Windows semantics) */
			SrvOpen *x;
			for (x = c->opens; x; x = x->next)
				if (x != o && x->tree == o->tree && !strcmp(x->path, o->path))
					break;
			if (x)
				x->delete_on_close = 1;
			else {
				int r = sh->ops->remove(sh->fs, o->path);
				if (r)
					LN_LOG(1, "server: %s: delete \"%s\" on close: %s", c->peer, o->path, ln_strerror(r));
				else
					LN_LOG(2, "server: %s: deleted \"%s\"", c->peer, o->path);
			}
		}
	}
	for (pp = &c->opens; *pp; pp = &(*pp)->next)
		if (*pp == o) {
			*pp = o->next;
			break;
		}
	if (o->dir) ln_free(o->dir);
	if (o->pout) ln_free(o->pout);
	ln_free(o->path);
	ln_free(o);
	if (c->nopens > 0)
		c->nopens--;
}

static SrvOpen *new_open(LnSrvConn *c, const char *path)
{
	SrvOpen *o = ln_alloc(sizeof(SrvOpen));
	if (!o)
		return NULL;
	o->path = ln_strdup(path);
	if (!o->path) {
		ln_free(o);
		return NULL;
	}
	o->id = c->next_fid++;
	o->tree = c->tree;
	o->next = c->opens;
	c->opens = o;
	c->nopens++;
	return o;
}

static void put_times(u8 *p, const Info *in)
{
	ln_put_le64(p, in->ctime);
	ln_put_le64(p + 8, in->mtime);       /* last access: we only know the write time */
	ln_put_le64(p + 16, in->mtime);
	ln_put_le64(p + 24, in->mtime);
}

static int stat_open(LnSrvConn *c, SrvOpen *o, Info *in)
{
	LnSrvShare *sh = share_of(c, o->tree);
	LnStat st;
	int r;
	memset(&st, 0, sizeof(st));
	if (!sh) {
		memset(in, 0, sizeof(*in));
		in->attrs = FA_NORMAL;
		in->fileid = o->id;
		return LN_OK;
	}
	r = o->f ? sh->ops->fstat(o->f, &st) : sh->ops->stat(sh->fs, o->path, &st);
	if (r == LN_OK && o->f && !st.fileid) {
		LnStat s2;
		if (sh->ops->stat(sh->fs, o->path, &s2) == LN_OK)
			st.fileid = s2.fileid;
	}
	if (r == LN_OK)
		info_from(&st, o->path, in);
	return r;
}

static u32 map_access(u32 a, int ro)
{
	if (a & A_MAX_ALLOWED)
		a |= ro ? A_ALL_RO : A_ALL_RW;
	if (a & A_GENERIC_ALL)
		a |= ro ? A_ALL_RO : A_ALL_RW;
	if (a & A_GENERIC_READ)
		a |= A_ALL_RO;
	if (a & A_GENERIC_WRITE)
		a |= A_WRITE_DATA | A_APPEND_DATA | A_WRITE_EA | A_WRITE_ATTR | A_READ_CONTROL | A_SYNCHRONIZE;
	if (a & A_GENERIC_EXEC)
		a |= A_EXECUTE | A_READ_ATTR | A_READ_CONTROL | A_SYNCHRONIZE;
	return a & 0x001F01FFu;
}

/* the create contexts we answer: MxAc (maximal access) and QFid (file id) */
static void create_contexts(LnSrvConn *c, size_t body_off, u32 maxacc, const Info *in)
{
	const u8 *b = c->body;
	u32 off = ln_le32(b + 48), len = ln_le32(b + 52);
	int mxac = 0, qfid = 0;
	size_t start;
	u8 *p, *prev = NULL;
	if (!len || off < SMB2_HDR + 56 || off + len > c->reqlen)
		return;
	while (len >= 16) {
		const u8 *x = c->req + off;
		u32 next = ln_le32(x);
		u16 no = ln_le16(x + 4), nl = ln_le16(x + 6);
		if (no + nl <= len && nl == 4) {
			if (!memcmp(x + no, "MxAc", 4)) mxac = 1;
			if (!memcmp(x + no, "QFid", 4)) qfid = 1;
		}
		if (!next || next >= len)
			break;
		off += next;
		len -= next;
	}
	if (!mxac && !qfid)
		return;
	while ((c->txlen - c->resp_off) & 7)
		c->tx[c->txlen++] = 0;
	start = c->txlen;
	if (mxac && (p = srv_body(c, 32)) != NULL) {
		ln_put_le16(p + 4, 16); ln_put_le16(p + 6, 4);
		ln_put_le16(p + 10, 24); ln_put_le32(p + 12, 8);
		memcpy(p + 16, "MxAc", 4);
		ln_put_le32(p + 24, 0);
		ln_put_le32(p + 28, maxacc);
		prev = p;
	}
	if (qfid && (p = srv_body(c, 56)) != NULL) {
		if (prev)
			ln_put_le32(prev, (u32)(p - prev));
		ln_put_le16(p + 4, 16); ln_put_le16(p + 6, 4);
		ln_put_le16(p + 10, 24); ln_put_le32(p + 12, 32);
		memcpy(p + 16, "QFid", 4);
		ln_put_le64(p + 24, in->fileid);
		ln_put_le64(p + 32, 0x4c61676f6f6eULL);    /* volume id */
	}
	ln_put_le32(c->tx + body_off + 80, (u32)(start - c->resp_off));
	ln_put_le32(c->tx + body_off + 84, (u32)(c->txlen - start));
}

void srv_create(LnSrvConn *c)
{
	const u8 *b = c->body;
	SrvTree *t = c->tree;
	LnSrvShare *sh = share_of(c, t);
	u32 access, attrs, disp, opts, maxacc;
	u16 noff, nlen;
	char *path = NULL;
	LnStat st;
	Info in;
	int exists, r, is_dir = 0, created = 0, trunc = 0, action = 1, data;
	LnFile *f = NULL;
	SrvOpen *o;
	size_t body_off;
	u8 *rb;

	if (c->blen < 56 || ln_le16(b) != 57) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	access = ln_le32(b + 24);
	attrs = ln_le32(b + 28);
	disp = ln_le32(b + 36);
	opts = ln_le32(b + 40);
	noff = ln_le16(b + 44);
	nlen = ln_le16(b + 46);
	if (nlen && (noff < SMB2_HDR + 56 || (u32)noff + nlen > c->reqlen)) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	if (disp > FILE_OVERWRITE_IF) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	if (c->nopens >= c->srv->cfg.max_opens) {
		srv_error(c, ST_TOO_MANY_OPENED_FILES, NULL, 0);
		return;
	}
	path = ln_alloc(1024);
	if (!path) {
		srv_error(c, ST_INSUFFICIENT_RESOURCES, NULL, 0);
		return;
	}
	if (!sh) {
		/* IPC$: \PIPE\srvsvc only */
		char nm[64];
		const char *q;
		srv_utf16_to_utf8(c->req + noff, nlen, nm, sizeof(nm));
		q = nm;
		while (*q == '\\') q++;
		if (!ln_strncasecmp(q, "PIPE\\", 5)) q += 5;
		if (ln_strcasecmp(q, "srvsvc")) {
			ln_free(path);
			srv_error(c, ST_OBJECT_NAME_NOT_FOUND, NULL, 0);
			return;
		}
		o = new_open(c, "srvsvc");
		ln_free(path);
		if (!o) {
			srv_error(c, ST_INSUFFICIENT_RESOURCES, NULL, 0);
			return;
		}
		o->is_pipe = 1;
		o->access = map_access(access, 0);
		memset(&in, 0, sizeof(in));
		in.attrs = FA_NORMAL;
		action = 1;
		maxacc = A_ALL_RW;
		goto reply;
	}
	{
		u32 e = srv_path(c, c->req + noff, nlen, path, 1024);
		if (e) {
			ln_free(path);
			srv_error(c, e, NULL, 0);
			return;
		}
	}
	maxacc = t->maxacc;
	access = map_access(access, t->readonly);
	if (t->readonly && ((access & A_WRITE_ANY) || (opts & CO_DELETE_ON_CLOSE) ||
	                    (disp != FILE_OPEN && disp != FILE_OPEN_IF))) {
		ln_free(path);
		srv_error(c, ST_ACCESS_DENIED, NULL, 0);
		return;
	}
	memset(&st, 0, sizeof(st));
	r = sh->ops->stat(sh->fs, path, &st);
	if (r != LN_OK && r != LN_ENOENT) {
		ln_free(path);
		srv_error(c, r == LN_ENOTDIR ? ST_OBJECT_PATH_NOT_FOUND : srv_status(r), NULL, 0);
		return;
	}
	exists = r == LN_OK;
	if (t->readonly && !exists) {
		ln_free(path);
		srv_error(c, disp == FILE_OPEN ? ST_OBJECT_NAME_NOT_FOUND : ST_ACCESS_DENIED, NULL, 0);
		return;
	}
	if (exists) {
		if (disp == FILE_CREATE) {
			ln_free(path);
			srv_error(c, ST_OBJECT_NAME_COLLISION, NULL, 0);
			return;
		}
		if (st.type == LN_T_DIR) {
			if (opts & CO_NON_DIRECTORY) {
				ln_free(path);
				srv_error(c, ST_FILE_IS_A_DIRECTORY, NULL, 0);
				return;
			}
			if (disp == FILE_OVERWRITE || disp == FILE_OVERWRITE_IF || disp == FILE_SUPERSEDE) {
				ln_free(path);
				srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
				return;
			}
			is_dir = 1;
		} else {
			if (opts & CO_DIRECTORY) {
				ln_free(path);
				srv_error(c, ST_NOT_A_DIRECTORY, NULL, 0);
				return;
			}
			if (!(st.prot & LN_P_WRITE)) {
				/* write-protected on the Amiga: read-only for clients */
				u32 asked = ln_le32(b + 24);
				maxacc = A_ALL_RO | A_DELETE;
				if ((access & (A_WRITE_DATA | A_APPEND_DATA)) && !(asked & (A_MAX_ALLOWED | A_GENERIC_ALL)))
					maxacc = 0;
				if (!maxacc || disp == FILE_OVERWRITE || disp == FILE_OVERWRITE_IF || disp == FILE_SUPERSEDE) {
					ln_free(path);
					srv_error(c, ST_ACCESS_DENIED, NULL, 0);
					return;
				}
				access &= A_ALL_RO | A_DELETE | A_WRITE_ATTR;
			}
			if (disp == FILE_OVERWRITE || disp == FILE_OVERWRITE_IF || disp == FILE_SUPERSEDE) {
				trunc = 1;
				action = disp == FILE_SUPERSEDE ? 0 : 3;
			}
		}
	} else {
		if (disp == FILE_OPEN || disp == FILE_OVERWRITE || !path[0]) {
			char par[1024];
			LnStat ps;
			u32 e = ST_OBJECT_NAME_NOT_FOUND;
			ln_path_parent(par, sizeof(par), path);
			if (par[0] && (sh->ops->stat(sh->fs, par, &ps) != LN_OK || ps.type != LN_T_DIR))
				e = ST_OBJECT_PATH_NOT_FOUND;
			ln_free(path);
			srv_error(c, e, NULL, 0);
			return;
		}
		if (opts & CO_DIRECTORY) {
			r = sh->ops->mkdir(sh->fs, path);
			if (r) {
				ln_free(path);
				srv_error(c, r == LN_ENOENT ? ST_OBJECT_PATH_NOT_FOUND : srv_status(r), NULL, 0);
				return;
			}
			is_dir = 1;
		} else
			created = 1;
		action = 2;
	}
	data = !is_dir && (access & (A_READ_DATA | A_WRITE_DATA | A_APPEND_DATA | A_EXECUTE));
	if (!is_dir && (data || created || trunc)) {
		int fl = LN_O_READ;
		if ((access & (A_WRITE_DATA | A_APPEND_DATA)) || created || trunc)
			fl |= LN_O_WRITE;
		if (created)
			fl |= LN_O_CREATE | LN_O_EXCL;
		if (trunc)
			fl |= LN_O_TRUNC;
		r = sh->ops->open(sh->fs, path, fl, &f);
		if (r == LN_EACCES && (fl & LN_O_WRITE) && !created && !trunc && (ln_le32(b + 24) & A_MAX_ALLOWED)) {
			fl = LN_O_READ;
			access &= A_ALL_RO | A_DELETE;
			r = sh->ops->open(sh->fs, path, fl, &f);
		}
		if (r) {
			ln_free(path);
			srv_error(c, r == LN_ENOENT && created ? ST_OBJECT_PATH_NOT_FOUND : srv_status(r), NULL, 0);
			return;
		}
		if (!data) {
			sh->ops->close(f);
			f = NULL;
		} else if (!(fl & LN_O_WRITE))
			access &= ~(u32)(A_WRITE_DATA | A_APPEND_DATA);
		if (created && (attrs & FA_READONLY) && !f) {
			LnStat ps;
			memset(&ps, 0, sizeof(ps));
			ps.prot = LN_P_READ | LN_P_EXEC | LN_P_DELETE;
			sh->ops->setattr(sh->fs, path, &ps, LN_SET_PROT);
		}
		if (f) {
			memset(&st, 0, sizeof(st));
			sh->ops->fstat(f, &st);
			if (!exists || trunc) {
				LnStat s2;
				if (sh->ops->stat(sh->fs, path, &s2) == LN_OK)
					st.fileid = s2.fileid;
			}
		}
	}
	if (!f && (created || is_dir || trunc || !exists)) {
		memset(&st, 0, sizeof(st));
		if ((r = sh->ops->stat(sh->fs, path, &st)) != LN_OK) {
			ln_free(path);
			srv_error(c, srv_status(r), NULL, 0);
			return;
		}
	}
	o = new_open(c, path);
	ln_free(path);
	if (!o) {
		if (f)
			sh->ops->close(f);
		srv_error(c, ST_INSUFFICIENT_RESOURCES, NULL, 0);
		return;
	}
	o->f = f;
	o->fflags = f ? ((access & (A_WRITE_DATA | A_APPEND_DATA)) ? LN_O_READ | LN_O_WRITE : LN_O_READ) : 0;
	o->is_dir = is_dir;
	o->access = access;
	if ((opts & CO_DELETE_ON_CLOSE) && (access & A_DELETE)) {
		if (!is_dir && !(st.prot & LN_P_WRITE) && exists) {
			srv_close_open(c, o);
			srv_error(c, ST_CANNOT_DELETE, NULL, 0);
			return;
		}
		o->delete_on_close = 1;
	}
	info_from(&st, o->path, &in);
	LN_LOG(2, "server: %s: open \"%s\" (%s, access %08x) -> %llu", c->peer, o->path,
	       action == 2 ? "created" : action == 3 || action == 0 ? "overwritten" : "opened", access,
	       (unsigned long long)o->id);
reply:
	body_off = c->txlen;
	rb = srv_body(c, 88);
	if (!rb)
		return;
	ln_put_le16(rb, 89);
	ln_put_le32(rb + 4, (u32)action);
	put_times(rb + 8, &in);
	ln_put_le64(rb + 40, in.alloc);
	ln_put_le64(rb + 48, in.size);
	ln_put_le32(rb + 56, in.attrs);
	ln_put_le64(rb + 64, o->id);
	ln_put_le64(rb + 72, o->id);
	if (!o->is_pipe)
		create_contexts(c, body_off, maxacc, &in);
}

void srv_close(LnSrvConn *c)
{
	const u8 *b = c->body;
	SrvOpen *o;
	u8 *r;
	u16 fl;
	char *path = NULL;
	LnSrvShare *sh;
	if (c->blen < 24 || ln_le16(b) != 24 || !(o = srv_find_open(c, b + 8))) {
		srv_error(c, c->blen < 24 ? ST_INVALID_PARAMETER : ST_FILE_CLOSED, NULL, 0);
		return;
	}
	fl = ln_le16(b + 2);
	sh = share_of(c, o->tree);
	if ((fl & 1) && sh && !o->delete_on_close)
		path = ln_strdup(o->path);
	srv_close_open(c, o);
	r = srv_body(c, 60);
	if (!r) {
		ln_free(path);
		return;
	}
	ln_put_le16(r, 60);
	if (path) {
		LnStat st;
		Info in;
		if (sh->ops->stat(sh->fs, path, &st) == LN_OK) {
			info_from(&st, path, &in);
			ln_put_le16(r + 2, 1);
			put_times(r + 8, &in);
			ln_put_le64(r + 40, in.alloc);
			ln_put_le64(r + 48, in.size);
			ln_put_le32(r + 56, in.attrs);
		}
		ln_free(path);
	}
}

void srv_flush(LnSrvConn *c)
{
	const u8 *b = c->body;
	SrvOpen *o;
	LnSrvShare *sh;
	u8 *r;
	if (c->blen < 24 || !(o = srv_find_open(c, b + 8))) {
		srv_error(c, c->blen < 24 ? ST_INVALID_PARAMETER : ST_FILE_CLOSED, NULL, 0);
		return;
	}
	sh = share_of(c, o->tree);
	if (sh && o->f) {
		int e = sh->ops->flush(o->f);
		if (e) {
			srv_error(c, srv_status(e), NULL, 0);
			return;
		}
	}
	r = srv_body(c, 4);
	if (r)
		ln_put_le16(r, 4);
}

void srv_lock(LnSrvConn *c)
{
	const u8 *b = c->body;
	u8 *r;
	if (c->blen < 24 || !srv_find_open(c, b + 8)) {
		srv_error(c, c->blen < 24 ? ST_INVALID_PARAMETER : ST_FILE_CLOSED, NULL, 0);
		return;
	}
	/* byte range locks are granted and not enforced: one user, one Amiga */
	r = srv_body(c, 4);
	if (r)
		ln_put_le16(r, 4);
}

/* ------------------------------------------------------- READ / WRITE */

/* hand out pending pipe output */
static void pipe_read(LnSrvConn *c, SrvOpen *o, u32 len)
{
	size_t avail = o->poutlen - o->poutoff, n = avail < len ? avail : len;
	u8 *r;
	if (!avail) {
		srv_error(c, ST_END_OF_FILE, NULL, 0);
		return;
	}
	r = srv_body(c, 16 + n);
	if (!r)
		return;
	ln_put_le16(r, 17);
	r[2] = 0x50;
	ln_put_le32(r + 4, (u32)n);
	memcpy(r + 16, o->pout + o->poutoff, n);
	o->poutoff += n;
	if (o->poutoff < o->poutlen)
		srv_set_status(c, ST_BUFFER_OVERFLOW);
	else {
		ln_free(o->pout);
		o->pout = NULL;
		o->poutlen = o->poutoff = 0;
	}
}

void srv_read(LnSrvConn *c)
{
	const u8 *b = c->body;
	SrvOpen *o;
	LnSrvShare *sh;
	u32 len, minc;
	u64 off;
	long got;
	u8 *r;
	if (c->blen < 48 || ln_le16(b) != 49) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	len = ln_le32(b + 4);
	off = ln_le64(b + 8);
	minc = ln_le32(b + 32);
	if (!(o = srv_find_open(c, b + 16))) {
		srv_error(c, ST_FILE_CLOSED, NULL, 0);
		return;
	}
	if (len > srv_max_io(c)) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	if (o->is_pipe) {
		pipe_read(c, o, len);
		return;
	}
	if (o->is_dir) {
		srv_error(c, ST_INVALID_DEVICE_REQUEST, NULL, 0);
		return;
	}
	sh = share_of(c, o->tree);
	if (!o->f || !(o->access & (A_READ_DATA | A_EXECUTE))) {
		srv_error(c, ST_ACCESS_DENIED, NULL, 0);
		return;
	}
	r = srv_body(c, 16 + len);
	if (!r) {
		srv_error(c, ST_INSUFFICIENT_RESOURCES, NULL, 0);
		return;
	}
	got = len ? sh->ops->read(o->f, off, r + 16, (long)len) : 0;
	if (got < 0) {
		srv_error(c, srv_status((int)got), NULL, 0);
		return;
	}
	if ((got == 0 && len) || (u32)got < minc) {
		srv_error(c, ST_END_OF_FILE, NULL, 0);
		return;
	}
	c->txlen -= len - (u32)got;
	ln_put_le16(r, 17);
	r[2] = 0x50;
	ln_put_le32(r + 4, (u32)got);
	o->pos = off + (u64)got;
}

void srv_write(LnSrvConn *c)
{
	const u8 *b = c->body;
	SrvOpen *o;
	LnSrvShare *sh;
	u16 doff;
	u32 len;
	u64 off;
	u8 *r;
	if (c->blen < 48 || ln_le16(b) != 49) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	doff = ln_le16(b + 2);
	len = ln_le32(b + 4);
	off = ln_le64(b + 8);
	if (!(o = srv_find_open(c, b + 16))) {
		srv_error(c, ST_FILE_CLOSED, NULL, 0);
		return;
	}
	if ((len && doff < SMB2_HDR + 48) || (u64)doff + len > c->reqlen || len > srv_max_io(c)) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	if (o->is_pipe) {
		int e = srv_rpc_input(c, o, c->req + doff, len);
		if (e) {
			srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
			return;
		}
	} else {
		long done = 0;
		if (o->is_dir) {
			srv_error(c, ST_INVALID_DEVICE_REQUEST, NULL, 0);
			return;
		}
		sh = share_of(c, o->tree);
		if (o->tree->readonly || !o->f || !(o->fflags & LN_O_WRITE)) {
			srv_error(c, ST_ACCESS_DENIED, NULL, 0);
			return;
		}
		if (off == 0xffffffffffffffffULL) {
			LnStat st;
			if (sh->ops->fstat(o->f, &st) != LN_OK) {
				srv_error(c, ST_IO_DEVICE_ERROR, NULL, 0);
				return;
			}
			off = st.size;
		}
		while ((u32)done < len) {
			long w = sh->ops->write(o->f, off + (u64)done, c->req + doff + done, (long)len - done);
			if (w <= 0) {
				srv_error(c, w < 0 ? srv_status((int)w) : ST_DISK_FULL, NULL, 0);
				return;
			}
			done += w;
		}
		o->written = 1;
		o->pos = off + len;
	}
	r = srv_body(c, 16);
	if (!r)
		return;
	ln_put_le16(r, 17);
	ln_put_le32(r + 4, len);
}

/* ---------------------------------------------------- QUERY_DIRECTORY */

static int lc(int ch)
{
	return ch >= 'A' && ch <= 'Z' ? ch + 32 : ch;
}

/* * and ? (and the DOS forms < > ") against a UTF-8 name, ASCII case-insensitive */
static int wild(const char *p, const char *s)
{
	for (; *p; p++, s++) {
		char pc = *p;
		if (pc == '<') pc = '*';
		if (pc == '>') pc = '?';
		if (pc == '"') pc = '.';
		if (pc == '*') {
			while (p[1] == '*' || p[1] == '<') p++;
			if (!p[1])
				return 1;
			for (; *s; s++)
				if (wild(p + 1, s))
					return 1;
			return 0;
		}
		if (!*s)
			return pc == '.' && !p[1] ? 1 : 0;
		if (pc == '?') {
			/* one character (a whole UTF-8 sequence) */
			while ((s[1] & 0xc0) == 0x80) s++;
			continue;
		}
		if (lc((u8)pc) != lc((u8)*s))
			return 0;
	}
	return *s == 0;
}

static int has_wild(const char *p)
{
	for (; *p; p++)
		if (*p == '*' || *p == '?' || *p == '<' || *p == '>' || *p == '"')
			return 1;
	return 0;
}

/* one directory entry of info class cls at p (room bytes): its length, 0 if it does not fit */
static size_t put_entry(u8 *p, size_t room, int cls, const char *name, const Info *in, u32 index)
{
	u8 n16[600];
	int nl = ln_utf8_to_utf16le(name, strlen(name), n16, sizeof(n16));
	size_t hdr;
	if (nl < 0)
		return 0;
	switch (cls) {
	case 1: hdr = 64; break;
	case 2: hdr = 68; break;
	case 3: hdr = 94; break;
	case 12: hdr = 12; break;
	case 37: hdr = 104; break;
	case 38: hdr = 80; break;
	default: return 0;
	}
	if (hdr + (size_t)nl > room)
		return 0;
	memset(p, 0, hdr);
	ln_put_le32(p + 4, index);
	if (cls == 12) {
		ln_put_le32(p + 8, (u32)nl);
	} else {
		put_times(p + 8, in);
		ln_put_le64(p + 40, in->size);
		ln_put_le64(p + 48, in->alloc);
		ln_put_le32(p + 56, in->attrs);
		ln_put_le32(p + 60, (u32)nl);
		if (cls == 38)
			ln_put_le64(p + 72, in->fileid);
		if (cls == 37)
			ln_put_le64(p + 96, in->fileid);
	}
	memcpy(p + hdr, n16, (size_t)nl);
	return hdr + (size_t)nl;
}

void srv_query_directory(LnSrvConn *c)
{
	const u8 *b = c->body;
	SrvOpen *o;
	LnSrvShare *sh;
	SrvDirState *d;
	int cls, fl, single, count = 0, first = 0, r;
	u32 maxlen;
	u16 noff, nlen;
	u8 *out, *data;
	size_t used = 0, last = 0;
	char *name = NULL, *full = NULL;
	LnStat st;
	Info in;

	if (c->blen < 32 || ln_le16(b) != 33) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	cls = b[2];
	fl = b[3];
	single = (fl & 2) != 0;
	noff = ln_le16(b + 24);
	nlen = ln_le16(b + 26);
	maxlen = ln_le32(b + 28);
	if (!(o = srv_find_open(c, b + 8))) {
		srv_error(c, ST_FILE_CLOSED, NULL, 0);
		return;
	}
	if (!o->is_dir || o->is_pipe) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	if (cls != 1 && cls != 2 && cls != 3 && cls != 12 && cls != 37 && cls != 38) {
		srv_error(c, ST_INVALID_INFO_CLASS, NULL, 0);
		return;
	}
	if (nlen && (noff < SMB2_HDR + 32 || (u32)noff + nlen > c->reqlen)) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	if (maxlen > srv_max_io(c))
		maxlen = srv_max_io(c);
	sh = share_of(c, o->tree);
	if (!o->dir) {
		o->dir = ln_alloc(sizeof(SrvDirState));
		if (!o->dir) {
			srv_error(c, ST_INSUFFICIENT_RESOURCES, NULL, 0);
			return;
		}
	}
	d = o->dir;
	if (!d->started || (fl & (1 | 0x10))) {
		if (d->d) {
			sh->ops->closedir(d->d);
			d->d = NULL;
		}
		memset(d, 0, sizeof(*d));
		d->started = 1;
		first = 1;
		if (nlen)
			srv_utf16_to_utf8(c->req + noff, nlen, d->pattern, sizeof(d->pattern));
		if (!d->pattern[0])
			ln_strlcpy(d->pattern, "*", sizeof(d->pattern));
		if (!strcmp(d->pattern, "*") || !strcmp(d->pattern, "*.*") || !strcmp(d->pattern, "<.*"))
			d->dots = 2;
	}
	name = ln_alloc(512);
	full = ln_alloc(1024);
	out = srv_body(c, 8 + maxlen);
	if (!name || !full || !out) {
		ln_free(name); ln_free(full);
		srv_error(c, ST_INSUFFICIENT_RESOURCES, NULL, 0);
		return;
	}
	data = out + 8;

#define EMIT(nm, info) do { \
		size_t pos = (used + 7) & ~(size_t)7, k; \
		k = (pos <= maxlen) ? put_entry(data + pos, maxlen - pos, cls, (nm), (info), d->index) : 0; \
		if (!k) goto full_; \
		if (count) ln_put_le32(data + last, (u32)(pos - last)); \
		last = pos; used = pos + k; count++; d->index++; \
	} while (0)

	if (!has_wild(d->pattern)) {
		/* one name: look it up */
		if (!d->done) {
			ln_path_join(full, 1024, o->path, d->pattern);
			if (sh->ops->stat(sh->fs, full, &st) == LN_OK) {
				info_from(&st, full, &in);
				EMIT(d->pattern, &in);
			}
			d->done = 1;
		}
		goto end;
	}
	if (d->dots) {
		if (sh->ops->stat(sh->fs, o->path, &st) == LN_OK) {
			info_from(&st, o->path, &in);
			while (d->dots) {
				EMIT(d->dots == 2 ? "." : "..", &in);
				d->dots--;
				if (single)
					goto end;
			}
		} else
			d->dots = 0;
	}
	if (d->have_pending) {
		ln_path_join(full, 1024, o->path, d->pname);
		info_from(&d->pst, full, &in);
		EMIT(d->pname, &in);
		d->have_pending = 0;
		if (single)
			goto end;
	}
	if (!d->done && !d->d) {
		r = sh->ops->opendir(sh->fs, o->path, &d->d);
		if (r) {
			ln_free(name); ln_free(full);
			srv_error(c, srv_status(r), NULL, 0);
			return;
		}
	}
	while (!d->done) {
		memset(&st, 0, sizeof(st));
		r = sh->ops->readdir(d->d, name, 512, &st);
		if (r <= 0) {
			d->done = 1;
			break;
		}
		if (!wild(d->pattern, name))
			continue;
		ln_path_join(full, 1024, o->path, name);
		info_from(&st, full, &in);
		ln_strlcpy(d->pname, name, sizeof(d->pname));
		d->pst = st;
		d->have_pending = 1;
		EMIT(name, &in);
		d->have_pending = 0;
		if (single)
			break;
	}
	goto end;
full_:
	if (!count) {
		ln_free(name); ln_free(full);
		srv_error(c, ST_INFO_LENGTH_MISMATCH, NULL, 0);
		return;
	}
end:
#undef EMIT
	ln_free(name);
	ln_free(full);
	if (!count) {
		srv_error(c, first ? ST_NO_SUCH_FILE : ST_NO_MORE_FILES, NULL, 0);
		return;
	}
	c->txlen = (size_t)(data - c->tx) + used;
	ln_put_le16(out, 9);
	ln_put_le16(out + 2, SMB2_HDR + 8);
	ln_put_le32(out + 4, (u32)used);
}

/* --------------------------------------------------------- QUERY_INFO */

/* minimal security descriptor: owner/group Everyone, a DACL granting
 * Everyone full (or read) access */
static size_t make_sd(u8 *p, u32 addl, int ro)
{
	static const u8 everyone[12] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
	size_t k = 20;
	memset(p, 0, 72);
	p[0] = 1;
	ln_put_le16(p + 2, 0x8004);
	if (addl & 1) { ln_put_le32(p + 4, (u32)k); memcpy(p + k, everyone, 12); k += 12; }
	if (addl & 2) { ln_put_le32(p + 8, (u32)k); memcpy(p + k, everyone, 12); k += 12; }
	if (addl & 4 || !(addl & 3)) {
		ln_put_le32(p + 16, (u32)k);
		p[k] = 2;
		ln_put_le16(p + k + 2, 28);
		ln_put_le16(p + k + 4, 1);
		p[k + 8] = 0;
		p[k + 9] = 0;
		ln_put_le16(p + k + 10, 20);
		ln_put_le32(p + k + 12, ro ? A_ALL_RO : A_ALL_RW);
		memcpy(p + k + 16, everyone, 12);
		k += 28;
	}
	return k;
}

static void qi_reply(LnSrvConn *c, u8 *out, size_t n, u32 maxlen, int may_truncate)
{
	if (n > maxlen) {
		if (!may_truncate) {
			srv_error(c, ST_INFO_LENGTH_MISMATCH, NULL, 0);
			return;
		}
		n = maxlen;
		srv_set_status(c, ST_BUFFER_OVERFLOW);
	}
	c->txlen = (size_t)(out + 8 - c->tx) + n;
	ln_put_le16(out, 9);
	ln_put_le16(out + 2, SMB2_HDR + 8);
	ln_put_le32(out + 4, (u32)n);
}

void srv_query_info(LnSrvConn *c)
{
	const u8 *b = c->body;
	SrvOpen *o;
	LnSrvShare *sh;
	int type, cls;
	u32 maxlen, addl;
	u8 *out, *p;
	Info in;
	size_t n = 0;
	int r;

	if (c->blen < 40 || ln_le16(b) != 41) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	type = b[2];
	cls = b[3];
	maxlen = ln_le32(b + 4);
	addl = ln_le32(b + 16);
	if (!(o = srv_find_open(c, b + 24))) {
		srv_error(c, ST_FILE_CLOSED, NULL, 0);
		return;
	}
	if (maxlen > srv_max_io(c))
		maxlen = srv_max_io(c);
	sh = share_of(c, o->tree);
	out = srv_body(c, 8 + 1200);
	if (!out)
		return;
	p = out + 8;
	if (type == 1) {
		if ((r = stat_open(c, o, &in)) != LN_OK) {
			srv_error(c, srv_status(r), NULL, 0);
			return;
		}
		if (o->is_pipe)
			in.alloc = in.size = 0;
		switch (cls) {
		case 4:                                    /* FileBasicInformation */
			put_times(p, &in);
			ln_put_le32(p + 32, in.attrs);
			n = 40;
			break;
		case 5:                                    /* FileStandardInformation */
			ln_put_le64(p, in.alloc);
			ln_put_le64(p + 8, in.size);
			ln_put_le32(p + 16, 1);
			p[20] = (u8)o->delete_on_close;
			p[21] = (u8)in.dir;
			n = 24;
			break;
		case 6:                                    /* FileInternalInformation */
			ln_put_le64(p, in.fileid);
			n = 8;
			break;
		case 7: case 16: case 17:                  /* EA size, mode, alignment */
			n = 4;
			break;
		case 8:                                    /* FileAccessInformation */
			ln_put_le32(p, o->access);
			n = 4;
			break;
		case 14:                                   /* FilePositionInformation */
			ln_put_le64(p, o->pos);
			n = 8;
			break;
		case 18: {                                 /* FileAllInformation */
			char nm[1024];
			int nl;
			put_times(p, &in);
			ln_put_le32(p + 32, in.attrs);
			ln_put_le64(p + 40, in.alloc);
			ln_put_le64(p + 48, in.size);
			ln_put_le32(p + 56, 1);
			p[60] = (u8)o->delete_on_close;
			p[61] = (u8)in.dir;
			ln_put_le64(p + 64, in.fileid);
			ln_put_le32(p + 76, o->access);
			ln_put_le64(p + 80, o->pos);
			ln_snprintf(nm, sizeof(nm), "\\%s", o->path);
			{
				char *q;
				for (q = nm; *q; q++)
					if (*q == '/') *q = '\\';
			}
			nl = ln_utf8_to_utf16le(nm, strlen(nm), p + 100, 1100);
			if (nl < 0) nl = 0;
			ln_put_le32(p + 96, (u32)nl);
			n = 100 + (size_t)nl;
			if (maxlen < 100) {
				srv_error(c, ST_INFO_LENGTH_MISMATCH, NULL, 0);
				return;
			}
			qi_reply(c, out, n, maxlen, 1);
			return;
		}
		case 21:                                   /* no 8.3 short names */
			srv_error(c, ST_NOT_SUPPORTED, NULL, 0);
			return;
		case 22:                                   /* FileStreamInformation */
			if (!in.dir) {
				int nl = ln_utf8_to_utf16le("::$DATA", 7, p + 24, 64);
				ln_put_le32(p + 4, (u32)nl);
				ln_put_le64(p + 8, in.size);
				ln_put_le64(p + 16, in.alloc);
				n = 24 + (size_t)nl;
			}
			break;
		case 28:                                   /* FileCompressionInformation */
			ln_put_le64(p, in.size);
			n = 16;
			break;
		case 34:                                   /* FileNetworkOpenInformation */
			put_times(p, &in);
			ln_put_le64(p + 32, in.alloc);
			ln_put_le64(p + 40, in.size);
			ln_put_le32(p + 48, in.attrs);
			n = 56;
			break;
		case 35:                                   /* FileAttributeTagInformation */
			ln_put_le32(p, in.attrs);
			n = 8;
			break;
		default:
			srv_error(c, ST_INVALID_INFO_CLASS, NULL, 0);
			return;
		}
		qi_reply(c, out, n, maxlen, 0);
		return;
	}
	if (type == 2) {
		LnStatFs fs;
		u64 total, avail;
		u32 bs;
		memset(&fs, 0, sizeof(fs));
		if (sh && (r = sh->ops->statfs(sh->fs, &fs)) != LN_OK) {
			srv_error(c, srv_status(r), NULL, 0);
			return;
		}
		bs = fs.block_size >= 512 ? fs.block_size : 4096;
		total = fs.total_bytes / bs;
		avail = fs.free_bytes / bs;
		switch (cls) {
		case 1: {                                  /* FileFsVolumeInformation */
			const char *label = fs.volume[0] ? fs.volume : sh ? sh->name : "IPC$";
			int nl = ln_utf8_to_utf16le(label, strlen(label), p + 18, 200);
			if (nl < 0) nl = 0;
			ln_put_le64(p, c->srv->start_ft);
			ln_put_le32(p + 8, (u32)path_id(sh ? sh->name : "IPC$"));
			ln_put_le32(p + 12, (u32)nl);
			n = 18 + (size_t)nl;
			qi_reply(c, out, n, maxlen, 1);
			return;
		}
		case 3:                                    /* FileFsSizeInformation */
			ln_put_le64(p, total);
			ln_put_le64(p + 8, avail);
			ln_put_le32(p + 16, bs / 512);
			ln_put_le32(p + 20, 512);
			n = 24;
			break;
		case 4:                                    /* FileFsDeviceInformation */
			ln_put_le32(p, 7);
			ln_put_le32(p + 4, 0x20 | (o->tree->readonly ? 0x2 : 0));
			n = 8;
			break;
		case 5: {                                  /* FileFsAttributeInformation */
			int nl = ln_utf8_to_utf16le("NTFS", 4, p + 12, 16);
			/* case preserved, Unicode names; read-only volume flag */
			ln_put_le32(p, 0x2 | 0x4 | (o->tree->readonly || fs.readonly ? 0x00080000u : 0));
			ln_put_le32(p + 4, (u32)c->srv->cfg.name_max);
			ln_put_le32(p + 8, (u32)nl);
			n = 12 + (size_t)nl;
			qi_reply(c, out, n, maxlen, 1);
			return;
		}
		case 7:                                    /* FileFsFullSizeInformation */
			ln_put_le64(p, total);
			ln_put_le64(p + 8, avail);
			ln_put_le64(p + 16, avail);
			ln_put_le32(p + 24, bs / 512);
			ln_put_le32(p + 28, 512);
			n = 32;
			break;
		case 8:                                    /* FileFsObjectIdInformation */
			n = 64;
			break;
		case 11:                                   /* FileFsSectorSizeInformation */
			ln_put_le32(p, 512); ln_put_le32(p + 4, 512); ln_put_le32(p + 8, 512); ln_put_le32(p + 12, 512);
			ln_put_le32(p + 16, 0x3);
			n = 28;
			break;
		default:
			srv_error(c, ST_INVALID_INFO_CLASS, NULL, 0);
			return;
		}
		qi_reply(c, out, n, maxlen, 0);
		return;
	}
	if (type == 3) {
		n = make_sd(p, addl, o->tree->readonly);
		if (n > maxlen) {
			u8 need[4];
			ln_put_le32(need, (u32)n);
			srv_error(c, ST_BUFFER_TOO_SMALL, need, 4);
			return;
		}
		qi_reply(c, out, n, maxlen, 0);
		return;
	}
	srv_error(c, ST_NOT_SUPPORTED, NULL, 0);
}

/* ----------------------------------------------------------- SET_INFO */

static int dir_empty(LnSrvShare *sh, const char *path)
{
	LnDir *d;
	char nm[300];
	LnStat st;
	int r;
	if (sh->ops->opendir(sh->fs, path, &d) != LN_OK)
		return 1;
	r = sh->ops->readdir(d, nm, sizeof(nm), &st);
	sh->ops->closedir(d);
	return r <= 0;
}

static void ok_reply(LnSrvConn *c)
{
	u8 *r = srv_body(c, 2);
	if (r)
		ln_put_le16(r, 2);
}

static u32 do_rename(LnSrvConn *c, SrvOpen *o, LnSrvShare *sh, const u8 *buf, u32 blen)
{
	u32 nl, e;
	int replace, r;
	char *to;
	LnStat st;
	SrvOpen *x;
	if (blen < 20)
		return ST_INFO_LENGTH_MISMATCH;
	replace = buf[0] != 0;
	nl = ln_le32(buf + 16);
	if (nl > blen - 20 || !o->path[0])
		return ST_INVALID_PARAMETER;
	to = ln_alloc(1024);
	if (!to)
		return ST_INSUFFICIENT_RESOURCES;
	if ((e = srv_path(c, buf + 20, nl, to, 1024)) != 0 || !to[0]) {
		ln_free(to);
		return e ? e : ST_OBJECT_NAME_INVALID;
	}
	/* a bare name (no backslash) renames within the same directory */
	{
		size_t k;
		int bs = 0;
		for (k = 0; k + 1 < nl; k += 2)
			if (buf[20 + k] == '\\' && buf[21 + k] == 0)
				bs = 1;
		if (!bs && strchr(o->path, '/')) {
			char par[1024], j[1024];
			ln_path_parent(par, sizeof(par), o->path);
			ln_path_join(j, sizeof(j), par, to);
			ln_strlcpy(to, j, 1024);
		}
	}
	if (!strcmp(to, o->path)) {
		ln_free(to);
		return ST_OK;
	}
	if (ln_strcasecmp(to, o->path) && sh->ops->stat(sh->fs, to, &st) == LN_OK) {
		if (!replace || st.type == LN_T_DIR) {
			ln_free(to);
			return replace ? ST_ACCESS_DENIED : ST_OBJECT_NAME_COLLISION;
		}
		for (x = c->opens; x; x = x->next)
			if (x->tree == o->tree && !strcmp(x->path, to)) {
				ln_free(to);
				return ST_ACCESS_DENIED;
			}
		if ((r = sh->ops->remove(sh->fs, to)) != LN_OK) {
			ln_free(to);
			return srv_status(r);
		}
	}
	/* the Amiga cannot rename an open file everywhere: close, rename, reopen */
	if (o->f) {
		sh->ops->close(o->f);
		o->f = NULL;
	}
	r = sh->ops->rename(sh->fs, o->path, to);
	if (o->fflags) {
		const char *p = r == LN_OK ? to : o->path;
		if (sh->ops->open(sh->fs, p, o->fflags, &o->f) != LN_OK)
			o->f = NULL;
	}
	if (r != LN_OK) {
		ln_free(to);
		return r == LN_ENOENT ? ST_OBJECT_PATH_NOT_FOUND : srv_status(r);
	}
	LN_LOG(2, "server: %s: renamed \"%s\" to \"%s\"", c->peer, o->path, to);
	{
		char *np = ln_strdup(to);
		if (np) {
			ln_free(o->path);
			o->path = np;
		}
	}
	ln_free(to);
	return ST_OK;
}

void srv_set_info(LnSrvConn *c)
{
	const u8 *b = c->body;
	SrvOpen *o;
	LnSrvShare *sh;
	int type, cls, r;
	u32 blen;
	u16 boff;
	const u8 *buf;
	u32 st = ST_OK;

	if (c->blen < 32 || ln_le16(b) != 33) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	type = b[2];
	cls = b[3];
	blen = ln_le32(b + 4);
	boff = ln_le16(b + 8);
	if (!(o = srv_find_open(c, b + 16))) {
		srv_error(c, ST_FILE_CLOSED, NULL, 0);
		return;
	}
	if ((blen && boff < SMB2_HDR + 32) || (u64)boff + blen > c->reqlen) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	buf = c->req + boff;
	sh = share_of(c, o->tree);
	if (type == 3) {                     /* security: accepted, not stored */
		ok_reply(c);
		return;
	}
	if (type != 1 || !sh || o->is_pipe) {
		srv_error(c, ST_NOT_SUPPORTED, NULL, 0);
		return;
	}
	if (o->tree->readonly) {
		srv_error(c, ST_ACCESS_DENIED, NULL, 0);
		return;
	}
	switch (cls) {
	case 4: {                            /* FileBasicInformation */
		u64 wt;
		u32 at;
		LnStat s;
		u32 mask = 0;
		if (blen < 36) { st = ST_INFO_LENGTH_MISMATCH; break; }
		if (!(o->access & (A_WRITE_ATTR | A_WRITE_DATA))) { st = ST_ACCESS_DENIED; break; }
		wt = ln_le64(buf + 16);
		at = ln_le32(buf + 32);
		memset(&s, 0, sizeof(s));
		if (wt && wt != 0xffffffffffffffffULL && wt != 0xfffffffffffffffeULL) {
			s.mtime = smb_ft2unix(wt);
			mask |= LN_SET_MTIME;
			o->set_mtime = 1;
			o->mtime = s.mtime;
		}
		if (at && !o->is_dir) {
			LnStat cur;
			if (sh->ops->stat(sh->fs, o->path, &cur) == LN_OK) {
				u32 np = cur.prot | LN_P_READ | LN_P_DELETE;
				if (at & FA_READONLY) np &= ~(u32)LN_P_WRITE; else np |= LN_P_WRITE;
				if (at & FA_ARCHIVE) np &= ~(u32)LN_P_ARCHIVE; else np |= LN_P_ARCHIVE;
				if (np != cur.prot) {
					s.prot = np;
					mask |= LN_SET_PROT;
				}
			}
		}
		if (mask && (r = sh->ops->setattr(sh->fs, o->path, &s, mask)) != LN_OK)
			st = srv_status(r);
		break;
	}
	case 10:                             /* FileRenameInformation */
		if (!(o->access & A_DELETE)) { st = ST_ACCESS_DENIED; break; }
		st = do_rename(c, o, sh, buf, blen);
		break;
	case 13: case 64: {                  /* FileDispositionInformation(Ex) */
		int del;
		if (blen < (cls == 13 ? 1u : 4u)) { st = ST_INFO_LENGTH_MISMATCH; break; }
		del = cls == 13 ? buf[0] != 0 : (ln_le32(buf) & 1) != 0;
		if (del) {
			LnStat s;
			if (!(o->access & A_DELETE)) { st = ST_ACCESS_DENIED; break; }
			if (!o->path[0]) { st = ST_ACCESS_DENIED; break; }
			if (o->is_dir && !dir_empty(sh, o->path)) { st = ST_DIRECTORY_NOT_EMPTY; break; }
			if (!o->is_dir && sh->ops->stat(sh->fs, o->path, &s) == LN_OK &&
			    (!(s.prot & LN_P_WRITE) || !(s.prot & LN_P_DELETE))) { st = ST_CANNOT_DELETE; break; }
		}
		o->delete_on_close = del;
		break;
	}
	case 14:                             /* FilePositionInformation */
		if (blen < 8) { st = ST_INFO_LENGTH_MISMATCH; break; }
		o->pos = ln_le64(buf);
		break;
	case 19:                             /* FileAllocationInformation: nothing to reserve */
		if (blen < 8) st = ST_INFO_LENGTH_MISMATCH;
		break;
	case 20: {                           /* FileEndOfFileInformation */
		u64 sz;
		if (blen < 8) { st = ST_INFO_LENGTH_MISMATCH; break; }
		if (o->is_dir) { st = ST_INVALID_PARAMETER; break; }
		if (!(o->access & (A_WRITE_DATA | A_APPEND_DATA))) { st = ST_ACCESS_DENIED; break; }
		sz = ln_le64(buf);
		if (o->f && (o->fflags & LN_O_WRITE))
			r = sh->ops->truncate(o->f, sz);
		else {
			LnFile *f;
			r = sh->ops->open(sh->fs, o->path, LN_O_READ | LN_O_WRITE, &f);
			if (r == LN_OK) {
				r = sh->ops->truncate(f, sz);
				sh->ops->close(f);
			}
		}
		if (r)
			st = srv_status(r);
		else
			o->written = 1;
		break;
	}
	default:
		st = ST_INVALID_INFO_CLASS;
	}
	if (st)
		srv_error(c, st, NULL, 0);
	else
		ok_reply(c);
}

/* -------------------------------------------------------------- IOCTL */

void srv_ioctl(LnSrvConn *c)
{
	const u8 *b = c->body;
	u32 code, ioff, icnt, maxout;
	u8 *r;
	if (c->blen < 56 || ln_le16(b) != 57) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	code = ln_le32(b + 4);
	ioff = ln_le32(b + 24);
	icnt = ln_le32(b + 28);
	maxout = ln_le32(b + 44);
	if (icnt && (ioff < SMB2_HDR + 56 || (u64)ioff + icnt > c->reqlen)) {
		srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
		return;
	}
	if (code == 0x00140204) {            /* FSCTL_VALIDATE_NEGOTIATE_INFO */
		const u8 *in = c->req + ioff;
		u16 nd, i;
		if (icnt < 24 || (nd = ln_le16(in + 22)) == 0 || 24u + 2u * nd > icnt || maxout < 24) {
			srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
			return;
		}
		/* the client's NEGOTIATE must match what we saw */
		if (memcmp(in + 4, c->cli_guid, 16) || ln_le16(in + 20) != c->cli_secmode || ln_le32(in) != c->cli_caps ||
		    nd != c->ncli_dialects) {
			LN_LOG(0, "server: %s: VALIDATE_NEGOTIATE mismatch (a man in the middle?)", c->peer);
			srv_error(c, ST_ACCESS_DENIED, NULL, 0);
			return;
		}
		for (i = 0; i < nd; i++)
			if (ln_le16(in + 24 + 2 * i) != c->cli_dialects[i]) {
				srv_error(c, ST_ACCESS_DENIED, NULL, 0);
				return;
			}
		r = srv_body(c, 48 + 24);
		if (!r)
			return;
		ln_put_le16(r, 49);
		ln_put_le32(r + 4, code);
		memset(r + 8, 0xff, 16);
		ln_put_le32(r + 32, SMB2_HDR + 48);
		ln_put_le32(r + 36, 24);
		ln_put_le32(r + 48, 0);                          /* capabilities */
		memcpy(r + 52, c->srv->guid, 16);
		ln_put_le16(r + 68, (u16)(c->srv->cfg.sign_required ? 3 : 1));
		ln_put_le16(r + 70, c->dialect);
		return;
	}
	if (code == 0x0011C017) {            /* FSCTL_PIPE_TRANSCEIVE */
		SrvOpen *o = srv_find_open(c, b + 8);
		size_t n;
		if (!o) {
			srv_error(c, ST_FILE_CLOSED, NULL, 0);
			return;
		}
		if (!o->is_pipe) {
			srv_error(c, ST_INVALID_DEVICE_REQUEST, NULL, 0);
			return;
		}
		if (srv_rpc_input(c, o, c->req + ioff, icnt)) {
			srv_error(c, ST_INVALID_PARAMETER, NULL, 0);
			return;
		}
		if (maxout > srv_max_io(c))
			maxout = srv_max_io(c);
		n = o->poutlen - o->poutoff;
		if (n > maxout)
			n = maxout;
		r = srv_body(c, 48 + n);
		if (!r)
			return;
		ln_put_le16(r, 49);
		ln_put_le32(r + 4, code);
		memcpy(r + 8, b + 8, 16);
		ln_put_le32(r + 32, SMB2_HDR + 48);
		ln_put_le32(r + 36, (u32)n);
		memcpy(r + 48, o->pout + o->poutoff, n);
		o->poutoff += n;
		if (o->poutoff < o->poutlen)
			srv_set_status(c, ST_BUFFER_OVERFLOW);
		else {
			ln_free(o->pout);
			o->pout = NULL;
			o->poutlen = o->poutoff = 0;
		}
		return;
	}
	if (code == 0x00060194 || code == 0x000601B0) {     /* DFS referrals: no DFS */
		srv_error(c, ST_FS_DRIVER_REQUIRED, NULL, 0);
		return;
	}
	if (code == 0x000900A8) {            /* FSCTL_GET_REPARSE_POINT */
		srv_error(c, ST_NOT_A_REPARSE_POINT, NULL, 0);
		return;
	}
	srv_error(c, ST_NOT_SUPPORTED, NULL, 0);
}
