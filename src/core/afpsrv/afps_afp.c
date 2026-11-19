/*
 * Lagoon - the AFP 2.1 calls of the server, on Lagoon's VFS.
 *
 * What System 7's AppleShare client asks of a server, from Inside AppleTalk, second edition,
 * chapter 13 (the call formats) and what Lagoon's own AFP client sends to AFP 3 servers
 * (src/core/afp): logging in (guest or clear-text password), the volume list and parameters,
 * catalog calls by directory ID and path, forks, and the desktop database calls answered as
 * "nothing stored" (the Finder then draws its generic icons). Every reply is built with the AFP
 * client's AfpBuf, the request read with the small reader below.
 *
 * Files and folders: the share's names, through afps_names.c; Finder info and resource forks,
 * through the AppleDouble files of afps_adouble.c. A file without a "._" file gets a type and
 * creator from its extension, so that a text file opens in SimpleText.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "afps_int.h"
#include "../ln_sys.h"

/* ---- reading a request ---- */
typedef struct Rd {
	const u8 *p;
	size_t    n, o;
	int       err;
} Rd;
static unsigned r8(Rd *r) { if (r->o + 1 > r->n) { r->err = 1; return 0; } return r->p[r->o++]; }
static unsigned r16(Rd *r) { unsigned v; if (r->o + 2 > r->n) { r->err = 1; return 0; } v = ln_be16(r->p + r->o); r->o += 2; return v; }
static u32 r32(Rd *r) { u32 v; if (r->o + 4 > r->n) { r->err = 1; return 0; } v = ln_be32(r->p + r->o); r->o += 4; return v; }
static const u8 *rpstr(Rd *r, size_t *len)
{
	const u8 *s;
	size_t l = r8(r);
	if (r->err || r->o + l > r->n) {
		r->err = 1;
		*len = 0;
		return (const u8 *)"";
	}
	s = r->p + r->o;
	r->o += l;
	*len = l;
	return s;
}
static void ralign(Rd *r) { if (r->o & 1) r->o++; }

/* ---- calls into the VFS, once more after a reconnect when the connection was lost ---- */
#define RETRY(s, rc, expr) do { rc = (expr); \
	if (rc == LN_ECONNRESET && (s)->ops->reconnect((s)->fs) == LN_OK) rc = (expr); } while (0)

static s32 fperr(int r)
{
	switch (r) {
	case LN_OK: return kFPNoErr;
	case LN_ENOENT: case LN_ENOSHARE: case LN_ESTALE: return kFPObjectNotFound;
	case LN_EEXIST: return kFPObjectExists;
	case LN_ENOTDIR: case LN_EISDIR: return kFPObjectTypeErr;
	case LN_ENOTEMPTY: return kFPDirNotEmpty;
	case LN_EACCES: case LN_EAUTH: return kFPAccessDenied;
	case LN_EROFS: return kFPVolLocked;
	case LN_ENOSPC: return kFPDiskFull;
	case LN_EINUSE: return kFPFileBusy;
	case LN_EINVAL: case LN_ENAMETOOLONG: return kFPParamErr;
	case LN_ENOMEM: return kFPMiscErr;
	default: return kFPMiscErr;
	}
}

static int vstat(AfpsServer *s, const char *path, LnStat *st)
{
	int rc;
	RETRY(s, rc, s->ops->stat(s->fs, path, st));
	return rc;
}

static void win_close(AfpsServer *s);

/* a modification: what was cached about the folders no longer holds */
static void changed(AfpsServer *s)
{
	win_close(s);
	memset(s->offs, 0, sizeof s->offs);
}

/* ---- pathnames (Inside AppleTalk 13-11): from directory did, elements separated by a NUL,
 * each further NUL in a row one level up ---- */
/* a mangled name whose file was put away (afps_names.c): the name in the folder with the same
 * hash and the same Mac name is the one, and is known again under its ID */
static int find_again(AfpsServer *s, u32 parent, u32 id, const u8 *mac, size_t n, char *out, size_t max)
{
	u32 h = afps_names_put_away(&s->names, id);
	char path[AFPS_PATH_MAX], nm[256];
	LnDir *d;
	LnStat st;
	int r, found = 0;
	if (!h || afps_names_path(&s->names, parent, path, sizeof path) != LN_OK)
		return 0;
	RETRY(s, r, s->ops->opendir(s->fs, path, &d));
	if (r != LN_OK)
		return 0;
	while (!found && s->ops->readdir(d, nm, sizeof nm, &st) > 0) {
		u8 m[AFPS_NAME_MAX + 1];
		int l;
		if (afps_names_hash(nm) != h)
			continue;
		l = afps_to_mac(nm, id, m, AFPS_NAME_MAX);
		found = l == (int)n && !memcmp(m, mac, n) && afps_names_revive(&s->names, id, parent, nm);
	}
	s->ops->closedir(d);
	if (found)
		ln_strlcpy(out, nm, max);
	return found;
}

static void elem_name(AfpsServer *s, u32 parent, const u8 *mac, size_t n, char *out, size_t max)
{
	u32 id = afps_mangled_id(mac, n);
	const AfpsNode *nd = afps_names_node(&s->names, id);
	if (id && nd && nd->parent == parent) {
		ln_strlcpy(out, nd->name, max);
		return;
	}
	if (id && !nd && find_again(s, parent, id, mac, n, out, max))
		return;
	if (afps_mac_to_utf8(mac, n, out, max) < 0)
		out[0] = 0;
}

static s32 resolve(AfpsServer *s, u32 did, Rd *r, AfpsPath *pa)
{
	size_t n, i = 0;
	const u8 *p;
	unsigned type = r8(r);
	u32 cur = did;
	p = rpstr(r, &n);
	memset(pa, 0, sizeof *pa);
	if (r->err || (type != AFPS_PATH_LONG && type != AFPS_PATH_SHORT))
		return kFPParamErr;
	if (cur != AFPS_PARENT_OF_ROOT && !afps_names_node(&s->names, cur))
		return kFPObjectNotFound;
	while (i < n) {
		size_t e;
		char nm[256];
		if (p[i] == 0) {
			i++;
			while (i < n && p[i] == 0) {         /* up one level for each further NUL */
				const AfpsNode *nd = afps_names_node(&s->names, cur);
				if (!nd || cur == AFPS_ROOT)
					return kFPObjectNotFound;
				cur = nd->parent;
				i++;
			}
			continue;
		}
		for (e = i; e < n && p[e]; e++)
			;
		if (cur == AFPS_PARENT_OF_ROOT) {
			/* the volume itself, by its name in the parent of the root */
			char vol[64];
			if (afps_mac_to_utf8(p + i, e - i, nm, sizeof nm) < 0 ||
			    afps_mac_to_utf8((const u8 *)s->cfg.volume, strlen(s->cfg.volume), vol, sizeof vol) < 0 ||
			    ln_strcasecmp(nm, vol))
				return kFPObjectNotFound;
			cur = AFPS_ROOT;
			i = e;
			continue;
		}
		elem_name(s, cur, p + i, e - i, nm, sizeof nm);
		if (!nm[0] || afps_hidden_name(nm))
			return kFPObjectNotFound;
		if (e < n) {                             /* a folder on the way */
			cur = afps_names_id(&s->names, cur, nm, 1);
			if (!cur)
				return kFPMiscErr;
		} else {                                 /* the last element */
			pa->parent = cur;
			ln_strlcpy(pa->name, nm, sizeof pa->name);
			memcpy(pa->mac, p + i, LN_MIN(e - i, sizeof pa->mac - 1));
			pa->id = afps_names_find(&s->names, cur, nm);
			return kFPNoErr;
		}
		i = e;
	}
	if (cur == AFPS_PARENT_OF_ROOT)
		return kFPObjectNotFound;
	pa->id = cur;
	pa->parent = afps_names_node(&s->names, cur)->parent;
	return kFPNoErr;
}

/* the server path of a resolved pathname */
static s32 path_of(AfpsServer *s, const AfpsPath *pa, char *out, size_t max)
{
	char dir[AFPS_PATH_MAX];
	if (!pa->name[0])
		return afps_names_path(&s->names, pa->id, out, max) == LN_OK ? kFPNoErr : kFPObjectNotFound;
	if (afps_names_path(&s->names, pa->parent, dir, sizeof dir) != LN_OK)
		return kFPObjectNotFound;
	return ln_path_join(out, max, dir, pa->name) == LN_OK ? kFPNoErr : kFPParamErr;
}

/* resolve and stat: the object must exist; *id is its ID (made now if it was not known) */
static s32 lookup(AfpsServer *s, u32 did, Rd *r, AfpsPath *pa, char *path, size_t max, LnStat *st, u32 *id)
{
	s32 e = resolve(s, did, r, pa);
	int rc;
	if (e == kFPNoErr)
		e = path_of(s, pa, path, max);
	if (e != kFPNoErr)
		return e;
	rc = vstat(s, path, st);
	if (rc != LN_OK)
		return fperr(rc);
	if (pa->name[0])
		*id = afps_names_id(&s->names, pa->parent, pa->name, st->type == LN_T_DIR);
	else
		*id = pa->id;
	return *id ? kFPNoErr : kFPMiscErr;
}

/* ---- Finder info ---- */
/* a type and creator for files that have no Finder info, from the extension */
static void guess_finfo(const char *name, u8 fi[32])
{
	static const struct { const char *ext; const char tc[9]; } map[] = {
		{ "txt", "TEXTttxt" }, { "text", "TEXTttxt" }, { "c", "TEXTttxt" }, { "h", "TEXTttxt" },
		{ "md", "TEXTttxt" }, { "conf", "TEXTttxt" }, { "log", "TEXTttxt" }, { "csv", "TEXTttxt" },
		{ "html", "TEXTMOSS" }, { "htm", "TEXTMOSS" }, { "pict", "PICTttxt" }, { "pct", "PICTttxt" },
		{ "gif", "GIFfogle" }, { "jpg", "JPEGogle" }, { "jpeg", "JPEGogle" }, { "png", "PNGfogle" },
		{ "pdf", "PDF CARO" }, { "sit", "SIT!SIT!" }, { "hqx", "TEXTSITx" }, { "zip", "ZIP SITx" },
		{ "bin", "BINASITx" }, { "mov", "MooVTVOD" }, { "aif", "AIFFTVOD" }, { "aiff", "AIFFTVOD" },
		{ "mp3", "MPG3TVOD" }, { "wav", "WAVETVOD" }, { "rtf", "RTF MSWD" }, { "doc", "WDBNMSWD" },
		{ "docx", "WXBNMSWD" }, { "xls", "XLS8XCEL" }, { "img", "rohdddsk" }, { "dsk", "dImgdCpy" },
	};
	const char *dot = strrchr(name, '.');
	size_t i;
	memset(fi, 0, 32);
	if (!dot || dot == name)
		return;
	for (i = 0; i < LN_ARRAY_SIZE(map); i++)
		if (!ln_strcasecmp(dot + 1, map[i].ext)) {
			memcpy(fi, map[i].tc, 8);
			return;
		}
}

/* Finder flags: kIsInvisible */
#define FINFO_INVISIBLE 0x4000

static void finfo_of(AfpsServer *s, const char *path, const char *name, int isdir, AfpsAd *ad)
{
	if (!s->no_ad)
		afps_ad_read(s->ops, s->fs, path, ad);
	if (!ad->exists && !isdir)
		guess_finfo(name, ad->finfo);
	if (name[0] == '.') {                        /* Unix dot files stay out of the Finder's way */
		unsigned fl = ln_be16(ad->finfo + 8) | FINFO_INVISIBLE;
		ln_put_be16(ad->finfo + 8, (u16)fl);
	}
}

/* ---- folders: offspring counts ---- */
static int offspring(AfpsServer *s, u32 id, const char *path)
{
	LnDir *d;
	char nm[256];
	LnStat st;
	unsigned i;
	int n = 0, r;
	u32 now = ln_ms();
	for (i = 0; i < LN_ARRAY_SIZE(s->offs); i++)
		if (s->offs[i].id == id && now - s->offs[i].when < 5000)
			return s->offs[i].n;
	RETRY(s, r, s->ops->opendir(s->fs, path, &d));
	if (r != LN_OK)
		return 0;
	while (s->ops->readdir(d, nm, sizeof nm, &st) > 0)
		if (!afps_hidden_name(nm))
			n++;
	s->ops->closedir(d);
	i = s->offs_pos++ % LN_ARRAY_SIZE(s->offs);
	s->offs[i].id = id;
	s->offs[i].when = now;
	s->offs[i].n = (u16)LN_MIN(n, 0xFFFF);
	return n;
}

static int fork_open_on(AfpsServer *s, u32 node, int rsrc)
{
	int i;
	for (i = 0; i < AFPS_MAXFORK; i++)
		if (s->fork[i].used && s->fork[i].node == node && (rsrc < 0 || s->fork[i].rsrc == rsrc))
			return 1;
	return 0;
}

/* ---- file and folder parameters (Inside AppleTalk 13-21, 13-22): the fixed fields in bitmap
 * order, the names after them, their offsets counted from the start of the block ---- */
static void put_params(AfpsServer *s, AfpBuf *b, u16 bm, int isdir, u32 id, u32 parent, const char *name,
                       const char *path, const LnStat *st)
{
	size_t start = b->len, lname_at = 0, sname_at = 0;
	AfpsAd ad;
	u8 mac[32];
	int ml;
	unsigned attr = 0;
	memset(&ad, 0, sizeof ad);
	if (bm & (FDBIT_FINFO | FBIT_RFLEN))
		finfo_of(s, path, name, isdir, &ad);
	if (bm & FDBIT_ATTR) {
		if ((st->prot & LN_P_HIDDEN) || name[0] == '.')
			attr |= ATTR_INVISIBLE;
		if (!isdir) {
			if (fork_open_on(s, id, 0)) attr |= ATTR_DOPEN;
			if (fork_open_on(s, id, 1)) attr |= ATTR_ROPEN;
			if (!(st->prot & LN_P_WRITE) && st->prot) attr |= ATTR_WRITEINHIBIT;
		}
		afp_b_u16(b, attr);
	}
	if (bm & FDBIT_PDID)  afp_b_u32(b, parent);
	if (bm & FDBIT_CDATE) afp_b_u32(b, afp_date_from_unix(st->ctime ? st->ctime : st->mtime));
	if (bm & FDBIT_MDATE) afp_b_u32(b, afp_date_from_unix(st->mtime));
	if (bm & FDBIT_BDATE) afp_b_u32(b, AFP_DATE_NONE);
	if (bm & FDBIT_FINFO) afp_b_mem(b, ad.finfo, 32);
	if (bm & FDBIT_LNAME) { lname_at = b->len; afp_b_u16(b, 0); }
	if (bm & FDBIT_SNAME) { sname_at = b->len; afp_b_u16(b, 0); }
	if (isdir) {
		if (bm & FDBIT_NODEID) afp_b_u32(b, id);
		if (bm & DBIT_OFFCNT)  afp_b_u16(b, (unsigned)offspring(s, id, path));
		if (bm & DBIT_OWNERID) afp_b_u32(b, 0);
		if (bm & DBIT_GROUPID) afp_b_u32(b, 0);
		/* access rights: the user owns everything and may search, read and write (or not
		 * write, on a read-only share); world, group and owner the same */
		if (bm & DBIT_ACCESS)  afp_b_u32(b, s->cfg.readonly ? 0x83030303u : 0x87070707u);
	} else {
		if (bm & FDBIT_NODEID) afp_b_u32(b, id);
		if (bm & FBIT_DFLEN)   afp_b_u32(b, (u32)LN_MIN(st->size, (u64)0x7FFFFFFF));
		if (bm & FBIT_RFLEN)   afp_b_u32(b, ad.rsrc_len);
	}
	if (bm & FDBIT_PRODOS) { afp_b_u32(b, 0); afp_b_u16(b, 0); }
	if (lname_at || sname_at) {
		if (id == AFPS_ROOT) {
			ml = (int)strlen(s->cfg.volume);
			memcpy(mac, s->cfg.volume, (size_t)ml);
		} else
			ml = afps_to_mac(name, id, mac, AFPS_NAME_MAX);
		if (ml < 0)
			ml = 0;
		if (lname_at) {
			if (b->p && lname_at + 2 <= b->max) ln_put_be16(b->p + lname_at, (u16)(b->len - start));
			afp_b_u8(b, (unsigned)ml);
			afp_b_mem(b, mac, (size_t)ml);
		}
		if (sname_at) {
			int sl = ml > 12 ? 12 : ml;          /* a short name: the first twelve bytes */
			if (b->p && sname_at + 2 <= b->max) ln_put_be16(b->p + sname_at, (u16)(b->len - start));
			afp_b_u8(b, (unsigned)sl);
			afp_b_mem(b, mac, (size_t)sl);
		}
	}
}

/* ---- volume parameters (Inside AppleTalk 13-17) ---- */
static s32 put_volparms(AfpsServer *s, AfpBuf *b, u16 bm)
{
	size_t start = b->len, name_at = 0;
	LnStatFs fs;
	u32 now = afp_date_from_unix(ln_time_unix());
	int rc;
	memset(&fs, 0, sizeof fs);
	if (bm & ~0x0FFFu)
		return kFPBitmapErr;
	if (bm & (VOLBIT_BFREE | VOLBIT_BTOTAL | VOLBIT_XBFREE | VOLBIT_XBTOTAL))
		RETRY(s, rc, s->ops->statfs(s->fs, &fs));
	if (bm & VOLBIT_ATTR)   afp_b_u16(b, s->cfg.readonly ? VOLATTR_READONLY : 0);
	if (bm & VOLBIT_SIG)    afp_b_u16(b, 2);             /* fixed directory IDs */
	if (bm & VOLBIT_CDATE)  afp_b_u32(b, now);
	if (bm & VOLBIT_MDATE)  afp_b_u32(b, now);
	if (bm & VOLBIT_BDATE)  afp_b_u32(b, AFP_DATE_NONE);
	if (bm & VOLBIT_ID)     afp_b_u16(b, AFPS_VOLID);
	/* AFP 2.0 and 2.1 count bytes in 32 bits: a share larger than 2 GB shows as 2 GB, as
	 * System 7.1 can show no more */
	if (bm & VOLBIT_BFREE)  afp_b_u32(b, (u32)LN_MIN(fs.free_bytes, (u64)0x7FFFFFFF));
	if (bm & VOLBIT_BTOTAL) afp_b_u32(b, (u32)LN_MIN(fs.total_bytes, (u64)0x7FFFFFFF));
	if (bm & VOLBIT_NAME)   { name_at = b->len; afp_b_u16(b, 0); }
	if (bm & VOLBIT_XBFREE) afp_b_u64(b, fs.free_bytes);
	if (bm & VOLBIT_XBTOTAL) afp_b_u64(b, fs.total_bytes);
	if (bm & VOLBIT_BSIZE)  afp_b_u32(b, fs.block_size ? fs.block_size : 4096);
	if (name_at) {
		if (b->p && name_at + 2 <= b->max) ln_put_be16(b->p + name_at, (u16)(b->len - start));
		afp_b_pstr(b, s->cfg.volume);
	}
	return kFPNoErr;
}

/* ---- forks ---- */
static AfpsFork *fork_of(AfpsServer *s, AfpsSess *se, unsigned ref)
{
	AfpsFork *f;
	if (ref < 1 || ref > AFPS_MAXFORK)
		return NULL;
	f = &s->fork[ref - 1];
	return f->used && f->sess == se->id ? f : NULL;
}

static void fork_close(AfpsServer *s, AfpsFork *f)
{
	if (f->f) {
		s->ops->flush(f->f);
		s->ops->close(f->f);
	}
	afps_names_pin(&s->names, f->node, -1);
	memset(f, 0, sizeof *f);
}

static u32 fork_len(AfpsServer *s, AfpsFork *f)
{
	LnStat st;
	if (f->rsrc)
		return f->ad.rsrc_len;
	if (!f->f || s->ops->fstat(f->f, &st) != LN_OK)
		return 0;
	return (u32)LN_MIN(st.size, (u64)0x7FFFFFFF);
}

static int fork_path(AfpsServer *s, AfpsFork *f, char *path, size_t max)
{
	return afps_names_path(&s->names, f->node, path, max);
}

void afps_afp_close_session(AfpsServer *s, AfpsSess *se)
{
	int i;
	for (i = 0; i < AFPS_MAXFORK; i++)
		if (s->fork[i].used && s->fork[i].sess == se->id)
			fork_close(s, &s->fork[i]);
}

void afps_afp_free(AfpsServer *s)
{
	int i;
	for (i = 0; i < AFPS_MAXFORK; i++)
		if (s->fork[i].used)
			fork_close(s, &s->fork[i]);
	win_close(s);
}

void afps_afp_tick(AfpsServer *s)
{
	if (s->win.d && ln_ms() - s->win.when > AFPS_WIN_IDLE_MS) {
		s->ops->closedir(s->win.d);          /* the window stays; a page past it lists again */
		s->win.d = NULL;
		s->win.dir = 0;
	}
}

/* ---- the calls ---- */
static s32 do_login(AfpsServer *s, AfpsSess *se, Rd *r)
{
	size_t vl, ul, nl = 0;
	const u8 *v = rpstr(r, &vl), *uam = rpstr(r, &ul), *name;
	u8 pw[8];
	if (r->err)
		return kFPParamErr;
	if (!(vl == 14 && (!memcmp(v, "AFPVersion 2.0", 14) || !memcmp(v, "AFPVersion 2.1", 14))))
		return kFPBadVersNum;
	if (ul == 15 && !ln_strncasecmp((const char *)uam, "No User Authent", 15)) {
		if (s->cfg.no_guest)
			return kFPBadUAM;
		se->logged_in = 1;
		LN_LOG(1, "afpsrv: session %u logged in as guest", se->id);
		return kFPNoErr;
	}
	if (ul == 16 && !ln_strncasecmp((const char *)uam, "Cleartxt Passwrd", 16) && s->cfg.user[0]) {
		name = rpstr(r, &nl);
		ralign(r);
		if (r->o + 8 > r->n)
			return kFPParamErr;
		memcpy(pw, r->p + r->o, 8);
		if (nl == strlen(s->cfg.user) && !ln_strncasecmp((const char *)name, s->cfg.user, nl) &&
		    ln_memeq_ct(pw, s->cfg.password, 8)) {
			ln_wipe(pw, sizeof pw);
			se->logged_in = 1;
			LN_LOG(1, "afpsrv: session %u logged in as a registered user", se->id);
			return kFPNoErr;
		}
		ln_wipe(pw, sizeof pw);
		return kFPUserNotAuth;
	}
	return kFPBadUAM;
}

static s32 do_getfiledirparms(AfpsServer *s, Rd *r, AfpBuf *b)
{
	unsigned vol = r16(r);
	u32 did = r32(r), id;
	unsigned fbm = r16(r), dbm = r16(r);
	AfpsPath pa;
	char path[AFPS_PATH_MAX];
	LnStat st;
	s32 e;
	if (r->err || vol != AFPS_VOLID)
		return kFPParamErr;
	if ((fbm & ~AFPS_FBITS) || (dbm & ~AFPS_DBITS))
		return kFPBitmapErr;
	e = lookup(s, did, r, &pa, path, sizeof path, &st, &id);
	if (e != kFPNoErr)
		return e;
	afp_b_u16(b, fbm);
	afp_b_u16(b, dbm);
	if (st.type == LN_T_DIR) {
		const AfpsNode *nd = afps_names_node(&s->names, id);
		afp_b_u8(b, 0x80);
		afp_b_u8(b, 0);
		put_params(s, b, (u16)dbm, 1, id, nd ? nd->parent : AFPS_PARENT_OF_ROOT, nd ? nd->name : "", path, &st);
	} else {
		afp_b_u8(b, 0);
		afp_b_u8(b, 0);
		put_params(s, b, (u16)fbm, 0, id, pa.parent, pa.name, path, &st);
	}
	return b->err ? kFPMiscErr : kFPNoErr;
}

/* ---- FPEnumerate's window (afps_int.h, AfpsWin) ----
 * An entry in the window: this header, then the name and its NUL, the whole padded to four
 * bytes. What put_params needs of the entry's LnStat is kept, nothing more. */
typedef struct WinEnt {
	u16 len;                 /* the whole entry, a multiple of 4 */
	u8  isdir, pad;
	u32 size, mtime, ctime, prot;
} WinEnt;
#define WIN_HDR   ((size_t)sizeof(WinEnt))
#define WIN_MAXENT (WIN_HDR + 256 + 4)

static void win_close(AfpsServer *s)
{
	if (s->win.d)
		s->ops->closedir(s->win.d);
	s->win.d = NULL;
	s->win.dir = 0;
	s->win.used = 0;
	s->win.files_before = s->win.dirs_before = 0;
	s->win.adknown = 0;
}

/* the window's bits for "._" files (afps_int.h): name's bit */
static unsigned ad_bit(const char *name)
{
	return (unsigned)(afps_names_hash(name) % AFPS_AD_BITS);
}

/* may name have a "._" file? Unless the first look found none */
static int ad_maybe(const AfpsServer *s, const char *name)
{
	unsigned k = ad_bit(name);
	return !s->win.adknown || (s->win.ad[k / 8] & (1u << (k % 8)));
}

/* name has a "._" file now (the server has just written it) */
static void ad_mark(AfpsServer *s, const char *name)
{
	unsigned k = ad_bit(name);
	s->win.ad[k / 8] |= (u8)(1u << (k % 8));
}

/* the first look: which names in the folder have a "._" file */
static void win_prescan(AfpsServer *s, const char *path)
{
	LnDir *d;
	char nm[256];
	LnStat st;
	int r;
	memset(s->win.ad, 0, sizeof s->win.ad);
	s->win.adknown = 0;
	if (s->ops->opendir(s->fs, path, &d) != LN_OK)
		return;
	while ((r = s->ops->readdir(d, nm, sizeof nm, &st)) > 0)
		if (nm[0] == '.' && nm[1] == '_' && nm[2])
			ad_mark(s, nm + 2);
	s->ops->closedir(d);
	s->win.adknown = r == 0;
}

static int win_open(AfpsServer *s, u32 id, const char *path)
{
	int r;
	win_close(s);
	RETRY(s, r, s->ops->opendir(s->fs, path, &s->win.d));
	if (r != LN_OK) {
		s->win.d = NULL;
		return r;
	}
	s->win.dir = id;
	return LN_OK;
}

static const u8 *win_at(const AfpsServer *s, size_t pos, WinEnt *e)
{
	const u8 *p = (const u8 *)s->win.buf + pos;
	memcpy(e, p, WIN_HDR);
	return p + WIN_HDR;
}

/* entries [0, upto) go out of the front of the window */
static void win_drop(AfpsServer *s, size_t upto)
{
	size_t pos = 0;
	u8 *b = (u8 *)s->win.buf;
	while (pos < upto) {
		WinEnt e;
		win_at(s, pos, &e);
		if (e.isdir)
			s->win.dirs_before++;
		else
			s->win.files_before++;
		pos += e.len;
	}
	memmove(b, b + upto, s->win.used - upto);
	s->win.used -= upto;
}

/* read on in the listing until the window is full or the folder ends (the listing closes) */
static int win_more(AfpsServer *s)
{
	char nm[256];
	LnStat st;
	int r;
	while (s->win.d && s->win.used + WIN_MAXENT <= sizeof s->win.buf) {
		WinEnt e;
		size_t nl;
		r = s->ops->readdir(s->win.d, nm, sizeof nm, &st);
		if (r <= 0) {
			s->ops->closedir(s->win.d);
			s->win.d = NULL;
			if (r < 0) {
				s->win.dir = 0;              /* half a listing: the next call starts again */
				return r;
			}
			break;
		}
		if (afps_hidden_name(nm) || (st.type != LN_T_DIR && st.type != LN_T_FILE))
			continue;
		nl = strlen(nm);
		memset(&e, 0, sizeof e);
		e.len = (u16)((WIN_HDR + nl + 1 + 3) & ~(size_t)3);
		e.isdir = st.type == LN_T_DIR;
		e.size = (u32)LN_MIN(st.size, (u64)0x7FFFFFFF);
		e.mtime = st.mtime;
		e.ctime = st.ctime;
		e.prot = st.prot;
		memcpy((u8 *)s->win.buf + s->win.used, &e, WIN_HDR);
		memcpy((u8 *)s->win.buf + s->win.used + WIN_HDR, nm, nl + 1);
		s->win.used += e.len;
	}
	return LN_OK;
}

static s32 do_enumerate(AfpsServer *s, Rd *r, AfpBuf *b, size_t rmax)
{
	unsigned vol = r16(r);
	u32 did = r32(r), id;
	unsigned fbm = r16(r), dbm = r16(r), want = r16(r), start = r16(r), maxrep = r16(r);
	AfpsPath pa;
	char path[AFPS_PATH_MAX], cpath[AFPS_PATH_MAX];
	LnStat st;
	s32 e;
	int got = 0, rc, retried = 0;
	long skip, page = -1;
	size_t limit, cnt_at, pos = 0;
	if (r->err || vol != AFPS_VOLID)
		return kFPParamErr;
	if ((fbm & ~AFPS_FBITS) || (dbm & ~AFPS_DBITS) || (!fbm && !dbm))
		return kFPBitmapErr;
	if (!want || !start)
		return kFPParamErr;
	e = lookup(s, did, r, &pa, path, sizeof path, &st, &id);
	if (e != kFPNoErr)
		return e == kFPObjectNotFound ? kFPDirNotFound : e;
	if (st.type != LN_T_DIR)
		return kFPObjectTypeErr;
	/* StartIndex counts only what was asked for (files, folders or both): how many of those
	 * to pass over in the window. StartIndex 1, another folder, or a page before the window:
	 * the folder is listed from its start */
	skip = (long)start - 1 - (long)((fbm ? s->win.files_before : 0) + (dbm ? s->win.dirs_before : 0));
	if (s->win.dir != id || start == 1 || skip < 0) {
		rc = win_open(s, id, path);
		if (rc != LN_OK)
			return fperr(rc);
		if ((fbm | dbm) & (FDBIT_FINFO | FBIT_RFLEN))
			win_prescan(s, path);
		skip = (long)start - 1;
	}
	s->win.when = ln_ms();
	limit = LN_MIN((size_t)maxrep, rmax);
	afp_b_u16(b, fbm);
	afp_b_u16(b, dbm);
	cnt_at = b->len;
	afp_b_u16(b, 0);
	while (got < (int)want) {
		WinEnt en;
		const char *name;
		size_t at, l;
		u32 cid;
		LnStat cst;
		if (pos >= s->win.used) {
			/* past the window: what came before this page goes, the listing reads on */
			size_t drop = page >= 0 ? (size_t)page : pos;
			if (!s->win.d)
				break;                           /* the end of the folder */
			if (drop == 0 && s->win.used + WIN_MAXENT > sizeof s->win.buf)
				drop = pos;                      /* the page alone fills the window */
			win_drop(s, drop);
			pos -= drop;
			if (page >= 0)
				page -= (long)drop;
			rc = win_more(s);
			if (rc != LN_OK) {
				if (got)
					break;                       /* this much; the next call lists again */
				if (retried++ || win_open(s, id, path) != LN_OK)
					return fperr(rc);
				skip = (long)start - 1;          /* the listing went (a reconnect): again */
				pos = 0;
				page = -1;
			}
			continue;
		}
		name = (const char *)win_at(s, pos, &en);
		at = pos;
		pos += en.len;
		if ((en.isdir && !dbm) || (!en.isdir && !fbm))
			continue;
		if (skip > 0) {
			skip--;
			continue;
		}
		if (page < 0)
			page = (long)at;
		cid = afps_names_id(&s->names, id, name, en.isdir);
		if (!cid)
			return got ? kFPNoErr : kFPMiscErr;  /* out of memory: say so, show what fitted */
		if (ln_path_join(cpath, sizeof cpath, path, name) != LN_OK)
			continue;
		memset(&cst, 0, sizeof cst);
		cst.type = en.isdir ? LN_T_DIR : LN_T_FILE;
		cst.size = en.size;
		cst.mtime = en.mtime;
		cst.ctime = en.ctime;
		cst.prot = en.prot;
		at = b->len;
		afp_b_u8(b, 0);
		afp_b_u8(b, en.isdir ? 0x80 : 0);
		s->no_ad = (u8)!ad_maybe(s, name);
		put_params(s, b, (u16)(en.isdir ? dbm : fbm), en.isdir, cid, id, name, cpath, &cst);
		s->no_ad = 0;
		afp_b_pad(b);
		l = b->len - at;
		if (b->err || b->len > limit || l > 255) {
			b->len = at;                         /* this one does not fit: the next call gets it */
			b->err = 0;
			break;
		}
		b->p[at] = (u8)l;
		got++;
	}
	LN_LOG(2, "afpsrv: enumerate %lu from %u (%u asked, %u bytes): %d", (unsigned long)id, start, want, maxrep, got);
	if (!got)
		return kFPObjectNotFound;
	ln_put_be16(b->p + cnt_at, (u16)got);
	return kFPNoErr;
}

static s32 do_create(AfpsServer *s, Rd *r, AfpBuf *b, int dir, int hard)
{
	unsigned vol = r16(r);
	u32 did = r32(r), id;
	AfpsPath pa;
	char path[AFPS_PATH_MAX], adp[AFPS_PATH_MAX];
	LnFile *f;
	s32 e;
	int rc;
	if (r->err || vol != AFPS_VOLID)
		return kFPParamErr;
	if (s->cfg.readonly)
		return kFPVolLocked;
	e = resolve(s, did, r, &pa);
	if (e == kFPNoErr && !pa.name[0])
		e = kFPObjectExists;
	if (e == kFPNoErr)
		e = path_of(s, &pa, path, sizeof path);
	if (e != kFPNoErr)
		return e;
	changed(s);
	if (dir) {
		RETRY(s, rc, s->ops->mkdir(s->fs, path));
		if (rc != LN_OK)
			return fperr(rc);
		id = afps_names_id(&s->names, pa.parent, pa.name, 1);
		afp_b_u32(b, id);
		return kFPNoErr;
	}
	id = afps_names_find(&s->names, pa.parent, pa.name);
	if (hard && id && fork_open_on(s, id, -1))
		return kFPFileBusy;
	RETRY(s, rc, s->ops->open(s->fs, path, LN_O_READ | LN_O_WRITE | LN_O_CREATE | (hard ? LN_O_TRUNC : LN_O_EXCL), &f));
	if (rc != LN_OK)
		return fperr(rc);
	s->ops->close(f);
	if (hard && afps_ad_name(path, adp, sizeof adp) == LN_OK)
		s->ops->remove(s->fs, adp);              /* a new file has no old Finder info */
	afps_names_id(&s->names, pa.parent, pa.name, 0);
	return kFPNoErr;
}

/* remove a folder's AppleDouble leftovers, so that a folder the Mac emptied can go */
static void clean_dir(AfpsServer *s, const char *path)
{
	LnDir *d;
	char nm[256], p[AFPS_PATH_MAX];
	LnStat st;
	char (*gone)[256] = NULL;
	int n = 0, i, other = 0;
	if (s->ops->opendir(s->fs, path, &d) != LN_OK)
		return;
	gone = ln_alloc(sizeof(*gone) * 16);
	while (s->ops->readdir(d, nm, sizeof nm, &st) > 0) {
		if (afps_hidden_name(nm) && st.type == LN_T_FILE && gone && n < 16)
			ln_strlcpy(gone[n++], nm, sizeof gone[0]);
		else
			other = 1;
	}
	s->ops->closedir(d);
	for (i = 0; !other && i < n; i++)
		if (ln_path_join(p, sizeof p, path, gone[i]) == LN_OK)
			s->ops->remove(s->fs, p);
	ln_free(gone);
}

static s32 do_delete(AfpsServer *s, Rd *r)
{
	unsigned vol = r16(r);
	u32 did = r32(r), id;
	AfpsPath pa;
	char path[AFPS_PATH_MAX], adp[AFPS_PATH_MAX];
	LnStat st;
	s32 e;
	int rc;
	if (r->err || vol != AFPS_VOLID)
		return kFPParamErr;
	if (s->cfg.readonly)
		return kFPVolLocked;
	e = lookup(s, did, r, &pa, path, sizeof path, &st, &id);
	if (e != kFPNoErr)
		return e;
	if (id == AFPS_ROOT)
		return kFPAccessDenied;
	if (st.type != LN_T_DIR && fork_open_on(s, id, -1))
		return kFPFileBusy;
	changed(s);
	RETRY(s, rc, s->ops->remove(s->fs, path));
	if (rc == LN_ENOTEMPTY && st.type == LN_T_DIR) {
		clean_dir(s, path);
		rc = s->ops->remove(s->fs, path);
	}
	if (rc != LN_OK)
		return fperr(rc);
	if (afps_ad_name(path, adp, sizeof adp) == LN_OK)
		s->ops->remove(s->fs, adp);
	afps_names_forget(&s->names, id);
	return kFPNoErr;
}

/* rename or move id (at path) to newname in the folder dst */
static s32 move_to(AfpsServer *s, u32 id, const char *path, u32 dst, const char *newname)
{
	char dpath[AFPS_PATH_MAX], np[AFPS_PATH_MAX], a1[AFPS_PATH_MAX], a2[AFPS_PATH_MAX];
	int rc;
	if (afps_names_path(&s->names, dst, dpath, sizeof dpath) != LN_OK)
		return kFPObjectNotFound;
	if (ln_path_join(np, sizeof np, dpath, newname) != LN_OK)
		return kFPParamErr;
	if (!strcmp(np, path))
		return kFPNoErr;
	changed(s);
	RETRY(s, rc, s->ops->rename(s->fs, path, np));
	if (rc != LN_OK)
		return rc == LN_EEXIST ? kFPObjectExists : fperr(rc);
	if (afps_ad_name(path, a1, sizeof a1) == LN_OK && afps_ad_name(np, a2, sizeof a2) == LN_OK)
		s->ops->rename(s->fs, a1, a2);           /* its Finder info and resource fork go along */
	afps_names_move(&s->names, id, dst, newname);
	return kFPNoErr;
}

static s32 newname_of(AfpsServer *s, Rd *r, u32 parent, char *out, size_t max)
{
	size_t n;
	unsigned type = r8(r);
	const u8 *p = rpstr(r, &n);
	if (r->err || (type != AFPS_PATH_LONG && type != AFPS_PATH_SHORT))
		return kFPParamErr;
	out[0] = 0;
	if (n)
		elem_name(s, parent, p, n, out, max);
	return out[0] || !n ? kFPNoErr : kFPParamErr;
}

static s32 do_rename(AfpsServer *s, Rd *r)
{
	unsigned vol = r16(r);
	u32 did = r32(r), id;
	AfpsPath pa;
	char path[AFPS_PATH_MAX], nn[256];
	LnStat st;
	s32 e;
	if (r->err || vol != AFPS_VOLID)
		return kFPParamErr;
	if (s->cfg.readonly)
		return kFPVolLocked;
	e = lookup(s, did, r, &pa, path, sizeof path, &st, &id);
	if (e != kFPNoErr)
		return e;
	if (id == AFPS_ROOT)
		return kFPCantRename;
	e = newname_of(s, r, afps_names_node(&s->names, id)->parent, nn, sizeof nn);
	if (e != kFPNoErr || !nn[0])
		return kFPParamErr;
	return move_to(s, id, path, afps_names_node(&s->names, id)->parent, nn);
}

static s32 do_moveandrename(AfpsServer *s, Rd *r)
{
	unsigned vol = r16(r);
	u32 sdid = r32(r), ddid = r32(r), id, dst;
	AfpsPath pa, pd;
	char path[AFPS_PATH_MAX], dpath[AFPS_PATH_MAX], nn[256];
	LnStat st, dst_st;
	s32 e;
	if (r->err || vol != AFPS_VOLID)
		return kFPParamErr;
	if (s->cfg.readonly)
		return kFPVolLocked;
	e = lookup(s, sdid, r, &pa, path, sizeof path, &st, &id);
	if (e != kFPNoErr)
		return e;
	if (id == AFPS_ROOT)
		return kFPCantMove;
	e = lookup(s, ddid, r, &pd, dpath, sizeof dpath, &dst_st, &dst);
	if (e != kFPNoErr)
		return e;
	if (dst_st.type != LN_T_DIR)
		return kFPObjectTypeErr;
	e = newname_of(s, r, dst, nn, sizeof nn);
	if (e != kFPNoErr)
		return e;
	if (!nn[0])
		ln_strlcpy(nn, afps_names_node(&s->names, id)->name, sizeof nn);
	/* a folder cannot go into itself or below itself */
	if (st.type == LN_T_DIR) {
		u32 x = dst;
		for (; x && x != AFPS_PARENT_OF_ROOT; x = afps_names_node(&s->names, x) ? afps_names_node(&s->names, x)->parent : 0)
			if (x == id)
				return kFPCantMove;
	}
	return move_to(s, id, path, dst, nn);
}

/* the parameters of FPSetFileDirParms (and FPSetFileParms, FPSetDirParms): dates and Finder
 * info are kept, the rest (attributes, owners, access) is accepted and left as the share has it */
static s32 do_setparms(AfpsServer *s, Rd *r, int want)
{
	unsigned vol = r16(r);
	u32 did = r32(r), id;
	unsigned bm = r16(r);
	AfpsPath pa;
	char path[AFPS_PATH_MAX];
	LnStat st, ns;
	s32 e;
	int isdir, rc;
	if (r->err || vol != AFPS_VOLID)
		return kFPParamErr;
	e = lookup(s, did, r, &pa, path, sizeof path, &st, &id);
	if (e != kFPNoErr)
		return e;
	isdir = st.type == LN_T_DIR;
	if ((want == 1 && isdir) || (want == 2 && !isdir))
		return kFPObjectTypeErr;
	if (s->cfg.readonly)
		return kFPVolLocked;
	ralign(r);
	memset(&ns, 0, sizeof ns);
	if (bm & FDBIT_ATTR)  r16(r);
	if (bm & FDBIT_PDID)  return kFPBitmapErr;
	if (bm & FDBIT_CDATE) r32(r);
	if (bm & FDBIT_MDATE) ns.mtime = afp_date_to_unix(r32(r));
	if (bm & FDBIT_BDATE) r32(r);
	if (bm & FDBIT_FINFO) {
		u8 fi[32];
		if (r->o + 32 > r->n)
			return kFPParamErr;
		memcpy(fi, r->p + r->o, 32);
		r->o += 32;
		/* in a "._" file, which no listing shows: what the server keeps of the folder
		 * (FPEnumerate's window, offspring counts) still holds. The Finder writes Finder
		 * info for the items of a window it opens, between the pages of its listing */
		if (id != AFPS_ROOT && afps_ad_set_finfo(s->ops, s->fs, path, fi) != LN_OK)
			LN_LOG(1, "afpsrv: no Finder info kept for %s", path);
		ad_mark(s, pa.name[0] ? pa.name : (afps_names_node(&s->names, id) ? afps_names_node(&s->names, id)->name : ""));
	}
	if (r->err)
		return kFPParamErr;
	if ((bm & FDBIT_MDATE) && ns.mtime && id != AFPS_ROOT)
		RETRY(s, rc, s->ops->setattr(s->fs, path, &ns, LN_SET_MTIME));
	return kFPNoErr;
}

static s32 do_openfork(AfpsServer *s, AfpsSess *se, Rd *r, AfpBuf *b, int rsrc)
{
	unsigned vol = r16(r);
	u32 did = r32(r), id;
	unsigned bm = r16(r), acc = r16(r);
	AfpsPath pa;
	char path[AFPS_PATH_MAX];
	LnStat st;
	AfpsFork *f = NULL;
	s32 e;
	int i, rc, wr = (acc & AFP_ACC_WRITE) != 0;
	if (r->err || vol != AFPS_VOLID)
		return kFPParamErr;
	if (bm & ~AFPS_FBITS)
		return kFPBitmapErr;
	e = lookup(s, did, r, &pa, path, sizeof path, &st, &id);
	if (e != kFPNoErr)
		return e;
	if (st.type == LN_T_DIR)
		return kFPObjectTypeErr;
	if (wr && s->cfg.readonly)
		return kFPVolLocked;
	for (i = 0; i < AFPS_MAXFORK && !f; i++)
		if (!s->fork[i].used)
			f = &s->fork[i];
	if (!f)
		return kFPTooManyFilesOpen;
	memset(f, 0, sizeof *f);
	if (rsrc) {
		RETRY(s, rc, afps_ad_open(s->ops, s->fs, path, wr, wr, &f->f, &f->ad));
		if (wr)
			ad_mark(s, pa.name);
		if (rc == LN_ENOENT && !wr)
			rc = LN_OK;                          /* no "._" file: an empty resource fork */
		else if (rc == LN_EPROTO)
			rc = LN_EACCES;
	} else
		RETRY(s, rc, s->ops->open(s->fs, path, wr ? LN_O_READ | LN_O_WRITE : LN_O_READ, &f->f));
	if (rc != LN_OK) {
		memset(f, 0, sizeof *f);
		return fperr(rc);
	}
	f->used = 1;
	f->rsrc = (u8)rsrc;
	f->write = (u8)wr;
	f->sess = se->id;
	f->node = id;
	afps_names_pin(&s->names, id, 1);           /* the file's name stays known while it is open */
	afp_b_u16(b, bm);
	afp_b_u16(b, (unsigned)(f - s->fork) + 1);
	if (bm)
		put_params(s, b, (u16)bm, 0, id, pa.parent, pa.name, path, &st);
	return kFPNoErr;
}

static s32 do_read(AfpsServer *s, AfpsSess *se, Rd *r, AfpBuf *b, size_t rmax)
{
	AfpsFork *f;
	u32 off, cnt, len;
	unsigned mask, nl;
	long got = 0;
	r8(r);
	f = fork_of(s, se, r16(r));
	off = r32(r);
	cnt = r32(r);
	mask = r8(r);
	nl = r8(r);
	if (r->err)
		return kFPParamErr;
	if (!f)
		return kFPParamErr;
	if ((s32)off < 0 || (s32)cnt < 0)
		return kFPParamErr;
	if (cnt > rmax)
		cnt = (u32)rmax;                         /* the client's buffer: it asks again for the rest */
	if (f->rsrc) {
		u32 k = cnt;
		len = f->ad.rsrc_len;
		if (off >= len)
			return kFPEOFErr;
		if (k > len - off)
			k = len - off;
		if (f->f && k)
			got = s->ops->read(f->f, (u64)f->ad.rsrc_off + off, b->p + b->len, (long)k);
	} else if (cnt)
		got = s->ops->read(f->f, off, b->p + b->len, (long)cnt);
	if (got < 0)
		return fperr((int)got);
	if (mask) {                                  /* newline mode: up to the first match */
		long i;
		for (i = 0; i < got; i++)
			if ((b->p[b->len + (size_t)i] & mask) == nl) {
				got = i + 1;
				break;
			}
	}
	b->len += (size_t)got;
	if (got == 0 && cnt)
		return kFPEOFErr;
	if ((u32)got < cnt && !mask)
		return kFPEOFErr;                        /* part of what was asked for: the end */
	return kFPNoErr;
}

static s32 do_write(AfpsServer *s, AfpsSess *se, Rd *r, AfpBuf *b, const u8 *data, size_t dlen)
{
	unsigned flag = r8(r);
	AfpsFork *f = fork_of(s, se, r16(r));
	s32 off = (s32)r32(r);
	u32 cnt = r32(r);
	long w;
	if (r->err || !f)
		return kFPParamErr;
	if (!f->write)
		return kFPAccessDenied;
	if (flag & 0x80)
		off += (s32)fork_len(s, f);              /* the offset counts from the end */
	if (off < 0)
		return kFPParamErr;
	if (cnt > dlen)
		cnt = (u32)dlen;
	changed(s);
	if (f->rsrc) {
		w = s->ops->write(f->f, (u64)f->ad.rsrc_off + (u32)off, data, (long)cnt);
		if (w > 0 && (u32)off + (u32)w > f->ad.rsrc_len && afps_ad_set_rlen(s->ops, f->f, &f->ad, (u32)off + (u32)w) != LN_OK)
			return kFPMiscErr;
	} else
		w = s->ops->write(f->f, (u32)off, data, (long)cnt);
	if (w < 0)
		return fperr((int)w);
	afp_b_u32(b, (u32)off + (u32)w);
	return kFPNoErr;
}

static s32 do_getforkparms(AfpsServer *s, AfpsSess *se, Rd *r, AfpBuf *b)
{
	AfpsFork *f;
	unsigned bm;
	char path[AFPS_PATH_MAX];
	LnStat st;
	const AfpsNode *nd;
	r8(r);
	f = fork_of(s, se, r16(r));
	bm = r16(r);
	if (r->err || !f)
		return kFPParamErr;
	if (bm & ~AFPS_FBITS)
		return kFPBitmapErr;
	nd = afps_names_node(&s->names, f->node);
	if (!nd || fork_path(s, f, path, sizeof path) != LN_OK || vstat(s, path, &st) != LN_OK)
		return kFPObjectNotFound;
	if (!f->rsrc && f->f)
		s->ops->fstat(f->f, &st);                /* the open file's own length, writes included */
	afp_b_u16(b, bm);
	put_params(s, b, (u16)bm, 0, f->node, nd->parent, nd->name, path, &st);
	return kFPNoErr;
}

static s32 do_setforkparms(AfpsServer *s, AfpsSess *se, Rd *r)
{
	AfpsFork *f;
	unsigned bm;
	u32 len;
	int rc;
	r8(r);
	f = fork_of(s, se, r16(r));
	bm = r16(r);
	len = r32(r);
	if (r->err || !f)
		return kFPParamErr;
	if ((bm != FBIT_DFLEN && bm != FBIT_RFLEN) || (bm == FBIT_RFLEN) != (f->rsrc != 0))
		return kFPBitmapErr;
	if (!f->write)
		return kFPAccessDenied;
	changed(s);
	if (f->rsrc) {
		rc = s->ops->truncate(f->f, (u64)f->ad.rsrc_off + len);
		if (rc == LN_OK)
			rc = afps_ad_set_rlen(s->ops, f->f, &f->ad, len);
	} else
		rc = s->ops->truncate(f->f, len);
	return fperr(rc);
}

static s32 do_get_comment(AfpsServer *s, Rd *r, AfpBuf *b)
{
	u32 did, id;
	AfpsPath pa;
	char path[AFPS_PATH_MAX];
	LnStat st;
	u8 mac[200];
	int ml;
	s32 e;
	r16(r);
	did = r32(r);
	e = lookup(s, did, r, &pa, path, sizeof path, &st, &id);
	if (e != kFPNoErr)
		return e;
	if (!st.comment[0])
		return kFPItemNotFound;
	ml = afps_to_mac(st.comment, 0, mac, 199);
	if (ml <= 0 || afps_mangled_id(mac, (size_t)ml))
		return kFPItemNotFound;
	afp_b_u8(b, (unsigned)ml);
	afp_b_mem(b, mac, (size_t)ml);
	return kFPNoErr;
}

static s32 do_add_comment(AfpsServer *s, Rd *r)
{
	u32 did, id;
	AfpsPath pa;
	char path[AFPS_PATH_MAX];
	LnStat st, ns;
	s32 e;
	size_t n;
	const u8 *c;
	r16(r);
	did = r32(r);
	e = lookup(s, did, r, &pa, path, sizeof path, &st, &id);
	if (e != kFPNoErr)
		return e;
	ralign(r);
	c = rpstr(r, &n);
	memset(&ns, 0, sizeof ns);
	if (!r->err && afps_mac_to_utf8(c, n, ns.comment, sizeof ns.comment) >= 0 && id != AFPS_ROOT)
		s->ops->setattr(s->fs, path, &ns, LN_SET_COMMENT);   /* where the share keeps notes */
	return kFPNoErr;
}

size_t afps_write_size(const u8 *cmd, size_t n)
{
	if (n >= 12 && cmd[0] == FPWrite)
		return LN_MIN((size_t)ln_be32(cmd + 8), (size_t)AS_QUANTUM);
	if (n >= 18 && cmd[0] == FPAddIcon)
		return LN_MIN((size_t)ln_be16(cmd + 16), (size_t)AS_QUANTUM);
	return 0;
}

s32 afps_afp_call(AfpsServer *s, AfpsSess *se, const u8 *cmd, size_t n, const u8 *wdata, size_t wlen,
                  u8 *rep, size_t rmax, size_t *rlen)
{
	Rd r;
	AfpBuf b;
	s32 e;
	unsigned code;
	r.p = cmd; r.n = n; r.o = 1; r.err = 0;
	afp_b_init(&b, rep, rmax);
	*rlen = 0;
	if (!n)
		return kFPParamErr;
	code = cmd[0];
	if (code != FPLogin && code != FPGetSrvrInfo && !se->logged_in)
		return kFPUserNotAuth;
	switch (code) {
	case FPLogin:
		e = do_login(s, se, &r);
		break;
	case FPLoginCont:
		e = kFPBadUAM;
		break;
	case FPLogout:
		se->logged_in = 0;
		se->vol_open = 0;
		afps_afp_close_session(s, se);
		e = kFPNoErr;
		break;
	case FPGetSrvrInfo:
		b.len = afps_status(s, rep, rmax);
		e = kFPNoErr;
		break;
	case FPGetSrvrParms:
		afp_b_u32(&b, afp_date_from_unix(ln_time_unix()));
		afp_b_u8(&b, 1);
		afp_b_u8(&b, 0);                         /* no password, no Apple II configuration */
		afp_b_pstr(&b, s->cfg.volume);
		e = kFPNoErr;
		break;
	case FPOpenVol: {
		unsigned bm;
		size_t vl;
		const u8 *v;
		r8(&r);
		bm = r16(&r);
		v = rpstr(&r, &vl);
		if (r.err)
			e = kFPParamErr;
		else if (vl != strlen(s->cfg.volume) || ln_strncasecmp((const char *)v, s->cfg.volume, vl))
			e = kFPObjectNotFound;
		else {
			afp_b_u16(&b, bm);
			e = put_volparms(s, &b, (u16)bm);
			if (e == kFPNoErr)
				se->vol_open = 1;
		}
		break;
	}
	case FPCloseVol:
		se->vol_open = 0;
		e = kFPNoErr;
		break;
	case FPGetVolParms: {
		unsigned vol, bm;
		r8(&r);
		vol = r16(&r);
		bm = r16(&r);
		if (r.err || vol != AFPS_VOLID)
			e = kFPParamErr;
		else {
			afp_b_u16(&b, bm);
			e = put_volparms(s, &b, (u16)bm);
		}
		break;
	}
	case FPSetVolParms:
	case FPFlush:
	case FPCloseDir:
	case FPCloseDT:
	case FPAddAPPL:
	case FPRemoveAPPL:
	case FPRemoveComment:
	case FPAddIcon:
		e = kFPNoErr;                            /* nothing to keep, or nothing to do */
		break;
	case FPGetFileDirParms:
		r8(&r);
		e = do_getfiledirparms(s, &r, &b);
		break;
	case FPEnumerate:
		r8(&r);
		e = do_enumerate(s, &r, &b, rmax);
		break;
	case FPOpenDir: {
		AfpsPath pa;
		char path[AFPS_PATH_MAX];
		LnStat st;
		u32 did, id;
		r8(&r);
		r16(&r);
		did = r32(&r);
		e = lookup(s, did, &r, &pa, path, sizeof path, &st, &id);
		if (e == kFPNoErr && st.type != LN_T_DIR)
			e = kFPObjectTypeErr;
		if (e == kFPNoErr)
			afp_b_u32(&b, id);
		break;
	}
	case FPCreateDir:
		r8(&r);
		e = do_create(s, &r, &b, 1, 0);
		break;
	case FPCreateFile: {
		unsigned flag = r8(&r);
		e = do_create(s, &r, &b, 0, (flag & 0x80) != 0);
		break;
	}
	case FPDelete:
		r8(&r);
		e = do_delete(s, &r);
		break;
	case FPRename:
		r8(&r);
		e = do_rename(s, &r);
		break;
	case FPMoveAndRename:
		r8(&r);
		e = do_moveandrename(s, &r);
		break;
	case FPSetFileDirParms:
	case FPSetFileParms:
	case FPSetDirParms:
		r8(&r);
		e = do_setparms(s, &r, code == FPSetFileParms ? 1 : code == FPSetDirParms ? 2 : 0);
		break;
	case FPOpenFork: {
		unsigned flag = r8(&r);
		e = do_openfork(s, se, &r, &b, (flag & 0x80) != 0);
		break;
	}
	case FPCloseFork: {
		AfpsFork *f;
		r8(&r);
		f = fork_of(s, se, r16(&r));
		if (!f)
			e = kFPParamErr;
		else {
			fork_close(s, f);
			e = kFPNoErr;
		}
		break;
	}
	case FPRead:
		e = do_read(s, se, &r, &b, rmax);
		break;
	case FPWrite:
		e = do_write(s, se, &r, &b, wdata, wlen);
		break;
	case FPFlushFork: {
		AfpsFork *f;
		r8(&r);
		f = fork_of(s, se, r16(&r));
		e = !f ? kFPParamErr : f->f ? fperr(s->ops->flush(f->f)) : kFPNoErr;
		break;
	}
	case FPGetForkParms:
		e = do_getforkparms(s, se, &r, &b);
		break;
	case FPSetForkParms:
		e = do_setforkparms(s, se, &r);
		break;
	case FPByteRangeLock: {
		/* the Mac's own client is the only one: every range is granted */
		unsigned flags = r8(&r);
		AfpsFork *f = fork_of(s, se, r16(&r));
		s32 off = (s32)r32(&r);
		if (r.err || !f)
			e = kFPParamErr;
		else {
			if (flags & 0x80)
				off += (s32)fork_len(s, f);
			afp_b_u32(&b, (u32)off);
			e = kFPNoErr;
		}
		break;
	}
	case FPMapID:
		afp_b_u8(&b, 0);                         /* no user and group names to give */
		e = kFPNoErr;
		break;
	case FPMapName:
		e = kFPItemNotFound;
		break;
	case FPGetUserInfo: {
		unsigned bm;
		r8(&r);
		r32(&r);
		bm = r16(&r);
		afp_b_u16(&b, bm);
		if (bm & 1) afp_b_u32(&b, 0);
		if (bm & 2) afp_b_u32(&b, 0);
		e = r.err ? kFPParamErr : kFPNoErr;
		break;
	}
	case FPGetSrvrMsg: {
		unsigned type, bm;
		r8(&r);
		type = r16(&r);
		bm = r16(&r);
		afp_b_u16(&b, type);
		afp_b_u16(&b, bm);
		afp_b_u8(&b, 0);                         /* no message */
		e = r.err ? kFPParamErr : kFPNoErr;
		break;
	}
	case FPOpenDT:
		afp_b_u16(&b, AFPS_DTREF);
		e = kFPNoErr;
		break;
	case FPGetIcon:
	case FPGetIconInfo:
	case FPGetAPPL:
		e = kFPItemNotFound;                     /* the desktop database is empty */
		break;
	case FPGetComment:
		r8(&r);
		e = do_get_comment(s, &r, &b);
		break;
	case FPAddComment:
		r8(&r);
		e = s->cfg.readonly ? kFPVolLocked : do_add_comment(s, &r);
		break;
	default:
		LN_LOG(1, "afpsrv: call %u is not supported", code);
		e = kFPCallNotSupported;
		break;
	}
	*rlen = e == kFPNoErr || e == kFPEOFErr ? b.len : 0;
	if (b.err)
		e = kFPMiscErr;
	return e;
}
