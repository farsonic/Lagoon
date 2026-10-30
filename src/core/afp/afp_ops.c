/*
 * Lagoon - AFP 3.x backend (Mac OS X 10.x file sharing, AFP-only Time
 * Capsules / AirPort Disks, Netatalk 2/3) over DSI/TCP, port 548.
 *
 * Every object is addressed from the volume root (directory ID 2) with a
 * full UTF-8 pathname (path type 3, decomposed on the wire, components
 * separated by NUL bytes), so no directory-ID cache is needed. Only data
 * forks are used: resource forks are ignored. Logins: guest, DHX2,
 * DHCAST128, and clear text when the URL says cleartext=yes.
 *
 * URL options (afp://user:pw@host/volume?opt=value&...):
 *   uam=guest|cleartext|dhcast128|dhx2  force a login method
 *   cleartext=yes     allow "Cleartxt Passwrd" (sends the password unencrypted)
 *   volpass=secret    volume password (8 characters at most)
 *   showall=yes       also list .AppleDouble, .AppleDB, .AppleDesktop
 *   comments=no|yes|all  Finder comments: off / in stat (default) / in listings too
 *   timeout=seconds   reply timeout (default 30)
 *   maxio=bytes       largest read/write request (default 128 KB or the server quantum)
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "afp_int.h"
#include "../ln_sys.h"
#include "../ln_charset.h"

#define CMDMAX   4096            /* request buffer (paths are at most ~1.9 KB NFD each) */
#define RBUFMAX  65536           /* reply buffer for listings and parameters */
#define PATHMAX  1024            /* NFC path inside the volume */

struct LnFile {
	LnFile *next;
	LnFs   *fs;
	char   *path;                /* full path in the volume (NFC) */
	u16     fork;
	int     acc;                 /* AFP access mode */
	int     valid;               /* fork open in the current session */
};

struct LnDir {
	LnFs  *fs;
	char  *path;
	u8    *buf;                  /* current page of entries */
	size_t len, pos;
	u32    next_index;           /* 1-based index of the next page */
	int    left;                 /* entries left in buf */
	int    eof;
	u16    fbm, dbm;
};

struct LnFs {
	LnUrl     url;
	LnCreds   cr;
	AfpConn   c;
	AfpSrvInfo si;
	u16       volid, volattr;
	int       dtref, dt_state;   /* desktop database for comments: 0 untried, 1 open, -1 none */
	u16       fbm, dbm;          /* bitmaps we ask for */
	int       showall, comments, cleartext, timeout_ms;
	char      uam[16];
	char      volpass[16];
	char      base[PATHMAX];     /* url->path, NFC */
	long      maxio, maxio_opt;
	u8       *cmd, *rbuf;
	LnFile   *files;
	u32       last_login_ms;
};

/* ---------------------------------------------------------- calls ---- */

/* send the request in b; returns a transport error or LN_OK, AFP result in *code */
static int rawcall(LnFs *fs, const AfpBuf *b, void *reply, size_t rmax, size_t *rlen, s32 *code)
{
	size_t dummy;
	if (b->err)
		return LN_ENAMETOOLONG;
	return afp_transact(&fs->c, DSI_COMMAND, b->p, b->len, NULL, 0, reply, rmax, rlen ? rlen : &dummy, code);
}

/* the same, with the AFP result mapped to LN_E* */
static int call(LnFs *fs, const AfpBuf *b, void *reply, size_t rmax, size_t *rlen)
{
	s32 code = 0;
	int r = rawcall(fs, b, reply, rmax, rlen, &code);
	if (r)
		return r;
	if (code)
		LN_LOG(2, "afp: command %u -> %d", b->p[0], (int)code);
	return afp_err(code);
}

static void start(LnFs *fs, AfpBuf *b, int cmd)
{
	afp_b_init(b, fs->cmd, CMDMAX);
	afp_b_u8(b, (unsigned)cmd);
	afp_b_u8(b, 0);
}

/* full volume path: base + "/" + path */
static int full(LnFs *fs, const char *path, char *out)
{
	return ln_path_join(out, PATHMAX, fs->base, path);
}

/* --------------------------------------------------------- login ---- */

static const char *uam_name(int uam)
{
	switch (uam) {
	case UAM_GUEST: return "No User Authent";
	case UAM_CLEARTXT: return "Cleartxt Passwrd";
	case UAM_DHCAST128: return "DHCAST128";
	default: return "DHX2";
	}
}

static int choose_uam(LnFs *fs)
{
	u32 offered = fs->si.uams;
	if (fs->uam[0]) {
		int want = !ln_strcasecmp(fs->uam, "guest") ? UAM_GUEST :
		           !ln_strcasecmp(fs->uam, "cleartext") ? UAM_CLEARTXT :
		           !ln_strcasecmp(fs->uam, "dhcast128") ? UAM_DHCAST128 :
		           !ln_strcasecmp(fs->uam, "dhx2") ? UAM_DHX2 : 0;
		if (want == UAM_CLEARTXT && !fs->cleartext) {
			LN_LOG(0, "afp: uam=cleartext needs cleartext=yes (the password goes unencrypted)");
			return 0;
		}
		return want && (offered & (u32)want) ? want : 0;
	}
	if (!fs->cr.user[0])
		return offered & UAM_GUEST ? UAM_GUEST : 0;
	if (offered & UAM_DHX2) return UAM_DHX2;
	if (offered & UAM_DHCAST128) return UAM_DHCAST128;
	if ((offered & UAM_CLEARTXT) && fs->cleartext) return UAM_CLEARTXT;
	return 0;
}

/* FPLoginExt (or FPLogin for servers without it) with the first auth data */
static int login_first(LnFs *fs, int uam, const u8 *auth, size_t alen, size_t *rlen, s32 *code, int old)
{
	AfpBuf b;
	int r;
	afp_b_init(&b, fs->cmd, CMDMAX);
	if (!old) {
		afp_b_u8(&b, FPLoginExt);
		afp_b_u8(&b, 0);
		afp_b_u16(&b, 0);                              /* flags */
		afp_b_pstr(&b, fs->si.version_str);
		afp_b_pstr(&b, uam_name(uam));
		afp_b_name3(&b, uam == UAM_GUEST ? "" : fs->cr.user);
		afp_b_u8(&b, AFP_PATH_UTF8);                   /* (unused) directory name */
		afp_b_u16(&b, 0);
		afp_b_pad(&b);
	} else {
		afp_b_u8(&b, FPLogin);
		afp_b_pstr(&b, fs->si.version_str);
		afp_b_pstr(&b, uam_name(uam));
		if (uam != UAM_GUEST) {
			afp_b_pstr(&b, fs->cr.user);
			afp_b_pad(&b);
		}
	}
	afp_b_mem(&b, auth, alen);
	r = rawcall(fs, &b, fs->rbuf, RBUFMAX, rlen, code);
	ln_wipe(fs->cmd, b.len);
	return r;
}

static int login_cont(LnFs *fs, u16 id, const u8 *data, size_t dlen, size_t *rlen, s32 *code)
{
	AfpBuf b;
	int r;
	start(fs, &b, FPLoginCont);
	afp_b_u16(&b, id);
	afp_b_mem(&b, data, dlen);
	r = rawcall(fs, &b, fs->rbuf, RBUFMAX, rlen, code);
	ln_wipe(fs->cmd, b.len);
	return r;
}

static int login(LnFs *fs)
{
	int uam = choose_uam(fs), r, old = 0;
	u8 auth[16 + 256 + 16];
	u8 ra[32];
	AfpDhx *x = NULL;
	size_t n, alen = 0;
	s32 code;
	u32 t0 = ln_ms();
	if (!uam) {
		LN_LOG(0, "afp: no usable login method (server offers 0x%x%s)", (unsigned)fs->si.uams,
		       fs->cr.user[0] ? "" : ", no guest access");
		return LN_EAUTH;
	}
	memset(auth, 0, sizeof(auth));
	if (uam == UAM_CLEARTXT) {
		size_t pl = strlen(fs->cr.password);
		memcpy(auth, fs->cr.password, pl > 8 ? 8 : pl);
		alen = 8;
	} else if (uam == UAM_DHX2 || uam == UAM_DHCAST128) {
		x = ln_alloc(sizeof(*x));
		if (!x)
			return LN_ENOMEM;
		ln_random(ra, sizeof(ra));
		ra[0] |= 0x80;                                 /* full-size exponent */
		if (uam == UAM_DHCAST128) {
			afp_dhcast_ma(x, ra, 16);
			memcpy(auth, x->ma, 16);
			alen = 16;
		}
	}
again:
	r = login_first(fs, uam, auth, alen, &n, &code, old);
	if (!r && code == kFPCallNotSupported && !old) {
		old = 1;
		goto again;
	}
	if (r || (uam != UAM_GUEST && uam != UAM_CLEARTXT && code != kFPAuthContinue))
		goto done;
	if (uam == UAM_DHX2) {
		if ((r = afp_dhx2_reply1(x, fs->rbuf, n, ra, sizeof(ra))) != 0)
			goto done;
		ln_random(x->cnonce, 16);
		x->cnonce[0] = (u8)((x->cnonce[0] & 0x7f) | 0x01);
		alen = afp_dhx2_cont1(x, x->msg);
		if ((r = login_cont(fs, x->id, x->msg, alen, &n, &code)) != 0)
			goto done;
		if (code != kFPAuthContinue)
			goto done;
		if ((r = afp_dhx2_reply2(x, fs->rbuf, n)) != 0)
			goto done;
		alen = afp_dhx2_cont2(x, fs->cr.password, auth);
		r = login_cont(fs, x->id, auth, alen, &n, &code);
	} else if (uam == UAM_DHCAST128) {
		if ((r = afp_dhcast_reply(x, fs->rbuf, n, ra, 16)) != 0)
			goto done;
		alen = afp_dhcast_cont(x, fs->cr.password, auth);
		r = login_cont(fs, x->id, auth, alen, &n, &code);
	}
done:
	if (x) {
		ln_wipe(x, sizeof(*x));
		ln_free(x);
	}
	ln_wipe(auth, sizeof(auth));
	ln_wipe(ra, sizeof(ra));
	if (r)
		return r;
	if (code) {
		LN_LOG(0, "afp: %s login failed (%d)", uam_name(uam), (int)code);
		return code == kFPParamErr || code == kFPMiscErr || code == kFPAccessDenied || code == kFPAuthContinue
		       ? LN_EAUTH : afp_err(code);
	}
	fs->last_login_ms = ln_ms() - t0;
	LN_LOG(1, "afp: logged in to \"%s\" (%s) with %s, %s, in %u ms", fs->si.name, fs->si.machine,
	       uam_name(uam), fs->si.version_str, (unsigned)fs->last_login_ms);
	return LN_OK;
}

/* server info + DSI session + login */
static int session_open(LnFs *fs)
{
	u16 port = fs->url.port ? fs->url.port : 548;
	size_t n;
	int r;
	r = afp_getstatus(fs->url.host, port, fs->timeout_ms, fs->rbuf, RBUFMAX, &n);
	if (r)
		return r;
	if ((r = afp_parse_srvinfo(fs->rbuf, n, &fs->si)) != 0)
		return r;
	if (!fs->si.version) {
		LN_LOG(0, "afp: server \"%s\" does not speak AFP 3.x", fs->si.name);
		return LN_ENOTSUP;
	}
	if ((r = afp_conn_open(&fs->c, fs->url.host, port, fs->timeout_ms)) != 0)
		return r;
	fs->maxio = fs->maxio_opt > 0 ? fs->maxio_opt : 131072;
	if (fs->maxio > (long)fs->c.quantum - 64)
		fs->maxio = ((long)fs->c.quantum - 64) & ~4095L;
	if (fs->maxio < 4096)
		fs->maxio = 4096;
	r = login(fs);
	if (r)
		afp_conn_close(&fs->c, 1);
	return r;
}

static void session_close(LnFs *fs)
{
	AfpBuf b;
	if (fs->c.s) {
		start(fs, &b, FPLogout);
		call(fs, &b, fs->rbuf, 16, NULL);
	}
	afp_conn_close(&fs->c, 1);
}

/* -------------------------------------------------------- volumes ---- */

static int open_volume(LnFs *fs)
{
	AfpBuf b;
	char nfd[256];
	size_t n;
	int r;
	s32 code;
	if (ln_utf8_nfd(fs->url.share, nfd, sizeof(nfd)) < 0)
		return LN_ENAMETOOLONG;
	start(fs, &b, FPOpenVol);
	afp_b_u16(&b, VOLBIT_ATTR | VOLBIT_ID);
	afp_b_pstr(&b, nfd);
	if (fs->volpass[0]) {
		u8 pw[8];
		afp_b_pad(&b);
		memset(pw, 0, sizeof(pw));
		memcpy(pw, fs->volpass, LN_MIN(strlen(fs->volpass), sizeof(pw)));
		afp_b_mem(&b, pw, 8);
	}
	r = rawcall(fs, &b, fs->rbuf, RBUFMAX, &n, &code);
	if (r)
		return r;
	if (code == kFPObjectNotFound || code == kFPParamErr)
		return LN_ENOSHARE;
	if (code == kFPAccessDenied)
		return fs->volpass[0] ? LN_EAUTH : LN_EACCES;
	if (code)
		return afp_err(code);
	if (n < 6)
		return LN_EPROTO;
	fs->volattr = ln_be16(fs->rbuf + 2);
	fs->volid = ln_be16(fs->rbuf + 4);
	fs->dt_state = 0;
	fs->fbm = FDBIT_ATTR | FDBIT_CDATE | FDBIT_MDATE | FDBIT_NODEID | FBIT_XDFLEN | FDBIT_UTF8NAME;
	fs->dbm = FDBIT_ATTR | FDBIT_CDATE | FDBIT_MDATE | FDBIT_NODEID | FDBIT_UTF8NAME;
	if (fs->volattr & VOLATTR_UNIXPRIVS) {
		fs->fbm |= FDBIT_UNIXPR;
		fs->dbm |= FDBIT_UNIXPR;
	}
	LN_LOG(2, "afp: volume \"%s\" id %u attributes 0x%04x", fs->url.share, fs->volid, fs->volattr);
	return LN_OK;
}

/* the desktop database (Finder comments); opened on first use */
static int dt_open(LnFs *fs)
{
	AfpBuf b;
	size_t n;
	if (fs->dt_state)
		return fs->dt_state > 0;
	start(fs, &b, FPOpenDT);
	afp_b_u16(&b, fs->volid);
	if (call(fs, &b, fs->rbuf, 16, &n) == LN_OK && n >= 2) {
		fs->dtref = ln_be16(fs->rbuf);
		fs->dt_state = 1;
	} else if (fs->c.s)
		fs->dt_state = -1;
	return fs->dt_state > 0;
}

/* ---------------------------------------------------------- stats ---- */

static void to_stat(const AfpParams *pp, LnStat *st)
{
	memset(st, 0, sizeof(*st));
	st->type = pp->isdir ? LN_T_DIR : LN_T_FILE;
	st->size = pp->isdir ? 0 : pp->size;
	st->mtime = pp->mdate;
	st->ctime = pp->cdate ? pp->cdate : pp->mdate;
	st->fileid = pp->nodeid;
	st->prot = LN_P_READ | LN_P_WRITE | LN_P_EXEC | LN_P_DELETE;
	if (pp->has_unix) {
		unsigned ua = (pp->ua >> 24) & 0xff;     /* this user's access */
		st->mode = pp->perms & 0177777;
		st->uid = pp->uid;
		st->gid = pp->gid;
		if (!(ua & AR_UREAD))
			st->prot &= ~(u32)LN_P_READ;
		if (!(ua & AR_UWRITE))
			st->prot &= ~(u32)LN_P_WRITE;
		if (!pp->isdir && !(pp->perms & 0111))
			st->prot &= ~(u32)LN_P_EXEC;
	}
	if (pp->attr & ATTR_INVISIBLE)
		st->prot |= LN_P_HIDDEN;
	if (!pp->isdir && (pp->attr & ATTR_WRITEINHIBIT))
		st->prot &= ~(u32)LN_P_WRITE;
	if (pp->attr & (ATTR_DELETEINHIBIT | ATTR_RENAMEINHIBIT))
		st->prot &= ~(u32)LN_P_DELETE;
}

/* copy a comment, keeping it valid UTF-8 within the LnStat field */
static void set_comment_field(char *out, size_t max, const u8 *p, size_t n)
{
	char tmp[256];
	size_t l;
	if (n >= sizeof(tmp))
		n = sizeof(tmp) - 1;
	memcpy(tmp, p, n);
	tmp[n] = 0;
	if (ln_utf8_nfc(tmp, out, max) < 0) {
		ln_strlcpy(out, tmp, max);
	}
	l = strlen(out);
	/* do not end inside a multibyte sequence */
	if (l == max - 1) {
		size_t k = l;
		while (k > 0 && ((u8)out[k - 1] & 0xc0) == 0x80)
			k--;
		if (k > 0 && ((u8)out[k - 1] & 0x80)) {
			u8 lead = (u8)out[k - 1];
			size_t need = lead >= 0xf0 ? 4 : lead >= 0xe0 ? 3 : 2;
			if (l - (k - 1) < need)
				out[k - 1] = 0;
		}
	}
}

static int get_comment(LnFs *fs, const char *fpath, char *out, size_t max)
{
	AfpBuf b;
	size_t n;
	int r;
	out[0] = 0;
	if (!fs->comments || !dt_open(fs))
		return LN_OK;
	start(fs, &b, FPGetComment);
	afp_b_u16(&b, (unsigned)fs->dtref);
	afp_b_u32(&b, AFP_ROOT_DID);
	afp_b_path(&b, fpath);
	r = call(fs, &b, fs->rbuf, 256, &n);
	if (r == LN_ECONNRESET || r == LN_EBREAK)
		return r;
	if (r == LN_ENOTSUP)
		fs->dt_state = -1;
	if (r == LN_OK && n >= 1 && fs->rbuf[0] && (size_t)fs->rbuf[0] + 1 <= n)
		set_comment_field(out, max, fs->rbuf + 1, fs->rbuf[0]);
	return LN_OK;
}

/* FPGetFileDirParms on a full path */
static int getparms(LnFs *fs, const char *fpath, AfpParams *pp)
{
	AfpBuf b;
	size_t n;
	int r;
	u16 fbm, dbm;
	start(fs, &b, FPGetFileDirParms);
	afp_b_u16(&b, fs->volid);
	afp_b_u32(&b, AFP_ROOT_DID);
	afp_b_u16(&b, fs->fbm);
	afp_b_u16(&b, fs->dbm);
	afp_b_path(&b, fpath);
	r = call(fs, &b, fs->rbuf, RBUFMAX, &n);
	/* a file used as a directory: Netatalk says ParamErr, others ObjectTypeErr */
	if (r == LN_ENOTDIR || (r == LN_EINVAL && fpath[0]))
		return LN_ENOENT;
	if (r)
		return r;
	if (n < 6)
		return LN_EPROTO;
	fbm = ln_be16(fs->rbuf);
	dbm = ln_be16(fs->rbuf + 2);
	if (fs->rbuf[4] & 0x80)
		return afp_parse_params(fs->rbuf + 6, n - 6, dbm, 1, pp);
	return afp_parse_params(fs->rbuf + 6, n - 6, fbm, 0, pp);
}

static int afp_stat(LnFs *fs, const char *path, LnStat *st)
{
	char fp[PATHMAX];
	AfpParams pp;
	int r;
	if ((r = full(fs, path, fp)) != 0)
		return r;
	if ((r = getparms(fs, fp, &pp)) != 0)
		return r;
	to_stat(&pp, st);
	return get_comment(fs, fp, st->comment, sizeof(st->comment));
}

static int afp_statfs(LnFs *fs, LnStatFs *st)
{
	AfpBuf b;
	size_t n;
	int r;
	u16 bm;
	memset(st, 0, sizeof(*st));
	start(fs, &b, FPGetVolParms);
	afp_b_u16(&b, fs->volid);
	afp_b_u16(&b, VOLBIT_ATTR | VOLBIT_XBFREE | VOLBIT_XBTOTAL | VOLBIT_BSIZE);
	r = call(fs, &b, fs->rbuf, RBUFMAX, &n);
	if (r == LN_EINVAL) {                          /* no extended sizes / block size */
		start(fs, &b, FPGetVolParms);
		afp_b_u16(&b, fs->volid);
		afp_b_u16(&b, VOLBIT_ATTR | VOLBIT_BFREE | VOLBIT_BTOTAL);
		r = call(fs, &b, fs->rbuf, RBUFMAX, &n);
	}
	if (r)
		return r;
	if (n < 4)
		return LN_EPROTO;
	bm = ln_be16(fs->rbuf);
	{
		const u8 *p = fs->rbuf + 2, *e = fs->rbuf + n;
		if ((bm & VOLBIT_ATTR) && p + 2 <= e) { st->readonly = (ln_be16(p) & VOLATTR_READONLY) != 0; p += 2; }
		if ((bm & VOLBIT_BFREE) && p + 4 <= e) { st->free_bytes = ln_be32(p); p += 4; }
		if ((bm & VOLBIT_BTOTAL) && p + 4 <= e) { st->total_bytes = ln_be32(p); p += 4; }
		if ((bm & VOLBIT_XBFREE) && p + 8 <= e) { st->free_bytes = ln_be64(p); p += 8; }
		if ((bm & VOLBIT_XBTOTAL) && p + 8 <= e) { st->total_bytes = ln_be64(p); p += 8; }
		st->block_size = 4096;
		if ((bm & VOLBIT_BSIZE) && p + 4 <= e && ln_be32(p) >= 512)
			st->block_size = ln_be32(p);
	}
	if (fs->volattr & VOLATTR_READONLY)
		st->readonly = 1;
	ln_strlcpy(st->volume, fs->url.share, sizeof(st->volume));
	return LN_OK;
}

/* ------------------------------------------------------ directories ---- */

static int hidden_name(const char *n)
{
	return !strcmp(n, ".AppleDouble") || !strcmp(n, ".AppleDB") || !strcmp(n, ".AppleDesktop");
}

static int afp_opendir(LnFs *fs, const char *path, LnDir **out)
{
	char fp[PATHMAX];
	AfpParams pp;
	LnDir *d;
	int r;
	if ((r = full(fs, path, fp)) != 0)
		return r;
	if ((r = getparms(fs, fp, &pp)) != 0)
		return r;
	if (!pp.isdir)
		return LN_ENOTDIR;
	d = ln_alloc(sizeof(*d));
	if (!d || !(d->path = ln_strdup(fp))) {
		ln_free(d);
		return LN_ENOMEM;
	}
	d->fs = fs;
	d->next_index = 1;
	d->fbm = fs->fbm;
	d->dbm = fs->dbm;
	*out = d;
	return LN_OK;
}

/* fetch the next page into d->buf */
static int next_page(LnDir *d)
{
	LnFs *fs = d->fs;
	AfpBuf b;
	size_t n;
	int r, ext2 = fs->si.version >= 31;
	start(fs, &b, ext2 ? FPEnumerateExt2 : FPEnumerateExt);
	afp_b_u16(&b, fs->volid);
	afp_b_u32(&b, AFP_ROOT_DID);
	afp_b_u16(&b, d->fbm);
	afp_b_u16(&b, d->dbm);
	afp_b_u16(&b, 256);                            /* entries per page */
	if (ext2) {
		afp_b_u32(&b, d->next_index);
		afp_b_u32(&b, RBUFMAX);
	} else {
		if (d->next_index > 0xffff) { d->eof = 1; return LN_OK; }
		afp_b_u16(&b, d->next_index);
		afp_b_u16(&b, 32768);
	}
	afp_b_path(&b, d->path);
	r = call(fs, &b, fs->rbuf, RBUFMAX, &n);
	if (r == LN_ENOENT) {                          /* past the last entry */
		d->eof = 1;
		return LN_OK;
	}
	if (r)
		return r;
	if (n < 6)
		return LN_EPROTO;
	ln_free(d->buf);
	d->buf = ln_alloc(n);
	if (!d->buf)
		return LN_ENOMEM;
	memcpy(d->buf, fs->rbuf, n);
	d->len = n;
	d->pos = 6;
	d->left = ln_be16(d->buf + 4);
	if (!d->left)
		d->eof = 1;
	d->next_index += (u32)d->left;
	return LN_OK;
}

static int afp_readdir(LnDir *d, char *name, size_t namemax, LnStat *st)
{
	for (;;) {
		AfpParams pp;
		size_t el;
		int r;
		if (!d->left) {
			if (d->eof)
				return 0;
			if ((r = next_page(d)) != 0)
				return r;
			continue;
		}
		if (d->pos + 4 > d->len)
			return LN_EPROTO;
		el = ln_be16(d->buf + d->pos);
		if (el < 4 || d->pos + el > d->len)
			return LN_EPROTO;
		r = afp_parse_params(d->buf + d->pos + 4, el - 4, d->buf[d->pos + 2] & 0x80 ? d->dbm : d->fbm,
		                     (d->buf[d->pos + 2] & 0x80) != 0, &pp);
		d->pos += el;
		d->left--;
		if (r)
			return r;
		if (!pp.name[0] || (!d->fs->showall && hidden_name(pp.name)))
			continue;
		if (strlen(pp.name) >= namemax) {
			LN_LOG(1, "afp: skipping long name \"%s\"", pp.name);
			continue;
		}
		ln_strlcpy(name, pp.name, namemax);
		if (st) {
			to_stat(&pp, st);
			if (d->fs->comments > 1) {
				char fp[PATHMAX];
				if (ln_path_join(fp, sizeof(fp), d->path, pp.name) == LN_OK &&
				    (r = get_comment(d->fs, fp, st->comment, sizeof(st->comment))) != 0)
					return r;
			}
		}
		return 1;
	}
}

static void afp_closedir(LnDir *d)
{
	if (!d)
		return;
	ln_free(d->buf);
	ln_free(d->path);
	ln_free(d);
}

/* ----------------------------------------------------------- files ---- */

static int open_fork(LnFs *fs, const char *fpath, int acc, u16 *fork)
{
	AfpBuf b;
	size_t n;
	int r;
	afp_b_init(&b, fs->cmd, CMDMAX);
	afp_b_u8(&b, FPOpenFork);
	afp_b_u8(&b, 0);                               /* data fork */
	afp_b_u16(&b, fs->volid);
	afp_b_u32(&b, AFP_ROOT_DID);
	afp_b_u16(&b, 0);                              /* no parameters back */
	afp_b_u16(&b, (unsigned)acc);
	afp_b_path(&b, fpath);
	{
		s32 code;
		r = rawcall(fs, &b, fs->rbuf, RBUFMAX, &n, &code);
		if (r)
			return r;
		if (code == kFPObjectTypeErr)
			return LN_EISDIR;
		if (code == kFPObjectLocked)
			return LN_EACCES;                      /* write inhibited */
		if (code)
			return afp_err(code);
	}
	if (n < 4)
		return LN_EPROTO;
	*fork = ln_be16(fs->rbuf + 2);
	return LN_OK;
}

static int set_fork_len(LnFs *fs, u16 fork, u64 size)
{
	AfpBuf b;
	int r;
	start(fs, &b, FPSetForkParms);
	afp_b_u16(&b, fork);
	afp_b_u16(&b, FBIT_XDFLEN);
	afp_b_u64(&b, size);
	r = call(fs, &b, fs->rbuf, 16, NULL);
	if (r == LN_EINVAL && size < 0x80000000u) {   /* AFP 3.0 servers without ext lengths */
		start(fs, &b, FPSetForkParms);
		afp_b_u16(&b, fork);
		afp_b_u16(&b, FBIT_DFLEN);
		afp_b_u32(&b, (u32)size);
		r = call(fs, &b, fs->rbuf, 16, NULL);
	}
	return r;
}

static int close_fork(LnFs *fs, u16 fork)
{
	AfpBuf b;
	start(fs, &b, FPCloseFork);
	afp_b_u16(&b, fork);
	return call(fs, &b, fs->rbuf, 16, NULL);
}

static int create_file(LnFs *fs, const char *fpath)
{
	AfpBuf b;
	afp_b_init(&b, fs->cmd, CMDMAX);
	afp_b_u8(&b, FPCreateFile);
	afp_b_u8(&b, 0);                               /* soft create: fail if it exists */
	afp_b_u16(&b, fs->volid);
	afp_b_u32(&b, AFP_ROOT_DID);
	afp_b_path(&b, fpath);
	return call(fs, &b, fs->rbuf, 16, NULL);
}

static int afp_open(LnFs *fs, const char *path, int flags, LnFile **out)
{
	char fp[PATHMAX];
	LnFile *f;
	u16 fork;
	int r, acc;
	if ((r = full(fs, path, fp)) != 0)
		return r;
	if (flags & (LN_O_CREATE | LN_O_EXCL)) {
		r = create_file(fs, fp);
		if (r == LN_EEXIST && !(flags & LN_O_EXCL))
			r = LN_OK;
		if (r)
			return r;
	}
	acc = AFP_ACC_READ | ((flags & (LN_O_WRITE | LN_O_TRUNC)) ? AFP_ACC_WRITE : 0);
	/* no deny modes: after a network loss the old session may hold the
	 * fork until the server times it out, and a deny mode would then stop
	 * the reconnect from reopening it */
	r = open_fork(fs, fp, acc, &fork);
	if (r == LN_EACCES && (acc & AFP_ACC_WRITE) && !(flags & LN_O_READ)) {
		acc = AFP_ACC_WRITE;                       /* write-only file */
		r = open_fork(fs, fp, acc, &fork);
	}
	if (r)
		return r;
	if ((flags & LN_O_TRUNC) && (r = set_fork_len(fs, fork, 0)) != 0) {
		close_fork(fs, fork);
		return r;
	}
	f = ln_alloc(sizeof(*f));
	if (!f || !(f->path = ln_strdup(fp))) {
		ln_free(f);
		close_fork(fs, fork);
		return LN_ENOMEM;
	}
	f->fs = fs;
	f->fork = fork;
	f->acc = acc;
	f->valid = 1;
	f->next = fs->files;
	fs->files = f;
	*out = f;
	return LN_OK;
}

static long afp_read(LnFile *f, u64 off, void *buf, long n)
{
	LnFs *fs = f->fs;
	long done = 0;
	if (!f->valid)
		return LN_ESTALE;
	while (done < n) {
		AfpBuf b;
		long want = LN_MIN(n - done, fs->maxio);
		size_t got;
		s32 code;
		int r;
		start(fs, &b, FPReadExt);
		afp_b_u16(&b, f->fork);
		afp_b_u64(&b, off + (u64)done);
		afp_b_u64(&b, (u64)want);
		r = rawcall(fs, &b, (u8 *)buf + done, (size_t)want, &got, &code);
		if (r)
			return done ? done : r;
		if (code && code != kFPEOFErr)
			return done ? done : afp_err(code);
		done += (long)got;
		if (code == kFPEOFErr || got == 0)
			break;
	}
	return done;
}

static long afp_write(LnFile *f, u64 off, const void *buf, long n)
{
	LnFs *fs = f->fs;
	long done = 0, chunk = LN_MIN(fs->maxio, (long)fs->c.quantum - 32);
	if (!f->valid)
		return LN_ESTALE;
	while (done < n) {
		AfpBuf b;
		long want = LN_MIN(n - done, chunk);
		u8 rep[8];
		size_t got;
		s32 code;
		int r;
		u64 last;
		afp_b_init(&b, fs->cmd, CMDMAX);
		afp_b_u8(&b, FPWriteExt);
		afp_b_u8(&b, 0);                           /* offset from the start */
		afp_b_u16(&b, f->fork);
		afp_b_u64(&b, off + (u64)done);
		afp_b_u64(&b, (u64)want);
		r = afp_transact(&fs->c, DSI_WRITE, b.p, b.len, (const u8 *)buf + done, (size_t)want,
		                 rep, sizeof(rep), &got, &code);
		if (r)
			return done ? done : r;
		if (code)
			return done ? done : code == kFPObjectLocked ? LN_EACCES : afp_err(code);
		if (got < 8)
			return done ? done : LN_EPROTO;
		last = ln_be64(rep);
		if (last <= off + (u64)done)
			return done ? done : LN_EIO;
		done += (long)(last - (off + (u64)done));
	}
	return done;
}

static int afp_fstat(LnFile *f, LnStat *st)
{
	LnFs *fs = f->fs;
	AfpBuf b;
	AfpParams pp;
	size_t n;
	int r;
	u16 bm = (u16)(fs->fbm & ~FDBIT_UTF8NAME);
	if (!f->valid)
		return LN_ESTALE;
	start(fs, &b, FPGetForkParms);
	afp_b_u16(&b, f->fork);
	afp_b_u16(&b, bm);
	r = call(fs, &b, fs->rbuf, RBUFMAX, &n);
	if (r)
		return r;
	if (n < 2)
		return LN_EPROTO;
	if ((r = afp_parse_params(fs->rbuf + 2, n - 2, ln_be16(fs->rbuf), 0, &pp)) != 0)
		return r;
	to_stat(&pp, st);
	return get_comment(fs, f->path, st->comment, sizeof(st->comment));
}

static int afp_truncate(LnFile *f, u64 size)
{
	if (!f->valid)
		return LN_ESTALE;
	return set_fork_len(f->fs, f->fork, size);
}

static int afp_flush(LnFile *f)
{
	AfpBuf b;
	if (!f->valid)
		return LN_ESTALE;
	start(f->fs, &b, FPFlushFork);
	afp_b_u16(&b, f->fork);
	return call(f->fs, &b, f->fs->rbuf, 16, NULL);
}

static int afp_close(LnFile *f)
{
	LnFs *fs = f->fs;
	LnFile **pp;
	int r = LN_OK;
	if (f->valid)
		r = close_fork(fs, f->fork);
	for (pp = &fs->files; *pp; pp = &(*pp)->next)
		if (*pp == f) {
			*pp = f->next;
			break;
		}
	ln_free(f->path);
	ln_free(f);
	/* a lost connection loses nothing that a close could save */
	return r == LN_ECONNRESET ? LN_OK : r;
}

/* ---------------------------------------------------- namespace ops ---- */

static int afp_mkdir(LnFs *fs, const char *path)
{
	char fp[PATHMAX];
	AfpBuf b;
	size_t n;
	int r;
	if ((r = full(fs, path, fp)) != 0)
		return r;
	start(fs, &b, FPCreateDir);
	afp_b_u16(&b, fs->volid);
	afp_b_u32(&b, AFP_ROOT_DID);
	afp_b_path(&b, fp);
	return call(fs, &b, fs->rbuf, 16, &n);
}

static int afp_remove(LnFs *fs, const char *path)
{
	char fp[PATHMAX];
	AfpBuf b;
	s32 code;
	int r;
	if ((r = full(fs, path, fp)) != 0)
		return r;
	if (!fp[0])
		return LN_EACCES;
	start(fs, &b, FPDelete);
	afp_b_u16(&b, fs->volid);
	afp_b_u32(&b, AFP_ROOT_DID);
	afp_b_path(&b, fp);
	if ((r = rawcall(fs, &b, fs->rbuf, 16, NULL, &code)) != 0)
		return r;
	if (code == kFPObjectLocked)
		return LN_EACCES;                          /* delete inhibited */
	if (code == kFPFileBusy)
		return LN_EINUSE;
	return afp_err(code);
}

static int afp_rename(LnFs *fs, const char *from, const char *to)
{
	char fp[PATHMAX], tp[PATHMAX], tdir[PATHMAX], nfd[512];
	AfpParams a, t;
	AfpBuf b;
	s32 code;
	int r;
	if ((r = full(fs, from, fp)) != 0 || (r = full(fs, to, tp)) != 0)
		return r;
	if (!fp[0] || !tp[0])
		return LN_EINVAL;
	if ((r = getparms(fs, fp, &a)) != 0)
		return r;
	/* never overwrite; a case-only rename finds the same object */
	r = getparms(fs, tp, &t);
	if (r == LN_OK && !(t.nodeid && t.nodeid == a.nodeid))
		return LN_EEXIST;
	if (r && r != LN_ENOENT)
		return r;
	ln_path_parent(tdir, sizeof(tdir), tp);
	if (ln_utf8_nfd(ln_path_base(tp), nfd, sizeof(nfd)) < 0)
		return LN_ENAMETOOLONG;
	start(fs, &b, FPMoveAndRename);
	afp_b_u16(&b, fs->volid);
	afp_b_u32(&b, AFP_ROOT_DID);
	afp_b_u32(&b, AFP_ROOT_DID);
	afp_b_path(&b, fp);
	afp_b_path(&b, tdir);
	afp_b_u8(&b, AFP_PATH_UTF8);
	afp_b_u32(&b, 0);
	afp_b_u16(&b, (unsigned)strlen(nfd));
	afp_b_mem(&b, nfd, strlen(nfd));
	if ((r = rawcall(fs, &b, fs->rbuf, 16, NULL, &code)) != 0)
		return r;
	if (code == kFPObjectLocked)
		return LN_EACCES;                          /* rename inhibited */
	if (code == kFPCantMove)
		return LN_EINVAL;                          /* into itself */
	return afp_err(code);
}

static int set_fdparms(LnFs *fs, const char *fp, u16 bitmap, const u8 *data, size_t dlen)
{
	AfpBuf b;
	s32 code;
	int r;
	start(fs, &b, FPSetFileDirParms);
	afp_b_u16(&b, fs->volid);
	afp_b_u32(&b, AFP_ROOT_DID);
	afp_b_u16(&b, bitmap);
	afp_b_path(&b, fp);
	afp_b_pad(&b);
	afp_b_mem(&b, data, dlen);
	if ((r = rawcall(fs, &b, fs->rbuf, 16, NULL, &code)) != 0)
		return r;
	if (code == kFPObjectLocked)
		return LN_EACCES;
	return afp_err(code);
}

static int set_comment(LnFs *fs, const char *fp, const char *comment)
{
	AfpBuf b;
	size_t l = strlen(comment);
	int r;
	if (!dt_open(fs))
		return fs->c.s ? LN_ENOTSUP : LN_ECONNRESET;
	if (!l) {
		start(fs, &b, FPRemoveComment);
		afp_b_u16(&b, (unsigned)fs->dtref);
		afp_b_u32(&b, AFP_ROOT_DID);
		afp_b_path(&b, fp);
		r = call(fs, &b, fs->rbuf, 16, NULL);
		return r == LN_ENOENT ? LN_OK : r;
	}
	if (l > 199)
		l = 199;
	start(fs, &b, FPAddComment);
	afp_b_u16(&b, (unsigned)fs->dtref);
	afp_b_u32(&b, AFP_ROOT_DID);
	afp_b_path(&b, fp);
	afp_b_pad(&b);
	afp_b_u8(&b, (unsigned)l);
	afp_b_mem(&b, comment, l);
	return call(fs, &b, fs->rbuf, 16, NULL);
}

static int afp_setattr(LnFs *fs, const char *path, const LnStat *st, u32 mask)
{
	char fp[PATHMAX];
	AfpParams cur;
	u8 d[16];
	int r, first = LN_OK;
	if ((r = full(fs, path, fp)) != 0)
		return r;
	if ((r = getparms(fs, fp, &cur)) != 0)
		return r;
	if (mask & LN_SET_SIZE) {
		LnFile *f;
		if (cur.isdir)
			return LN_EISDIR;
		r = afp_open(fs, path, LN_O_WRITE, &f);
		if (!r) {
			r = afp_truncate(f, st->size);
			afp_close(f);
		}
		if (r && !first) first = r;
	}
	if (mask & LN_SET_PROT) {
		u16 known = ATTR_INVISIBLE | ATTR_RENAMEINHIBIT | ATTR_DELETEINHIBIT | (cur.isdir ? 0 : ATTR_WRITEINHIBIT);
		u16 want = 0, clr, set;
		if (st->prot & LN_P_HIDDEN) want |= ATTR_INVISIBLE;
		if (!(st->prot & LN_P_DELETE)) want |= ATTR_RENAMEINHIBIT | ATTR_DELETEINHIBIT;
		if (!cur.isdir && !(st->prot & LN_P_WRITE)) want |= ATTR_WRITEINHIBIT;
		clr = (u16)(cur.attr & known & ~want);
		set = (u16)(want & ~cur.attr);
		r = LN_OK;
		if (clr) {
			ln_put_be16(d, clr);
			r = set_fdparms(fs, fp, FDBIT_ATTR, d, 2);
		}
		if (!r && set) {
			ln_put_be16(d, (u16)(ATTR_SETCLEAR | set));
			r = set_fdparms(fs, fp, FDBIT_ATTR, d, 2);
		}
		if (r && !first) first = r;
	}
	if (mask & LN_SET_MODE) {
		if (!cur.has_unix)
			r = LN_ENOTSUP;
		else {
			ln_put_be32(d, cur.uid);
			ln_put_be32(d + 4, cur.gid);
			ln_put_be32(d + 8, (cur.perms & ~07777u) | (st->mode & 07777));
			ln_put_be32(d + 12, cur.ua);
			r = set_fdparms(fs, fp, FDBIT_UNIXPR, d, 16);
		}
		if (r && !first) first = r;
	}
	if (mask & LN_SET_MTIME) {
		ln_put_be32(d, afp_date_from_unix(st->mtime));
		r = set_fdparms(fs, fp, FDBIT_MDATE, d, 4);
		if (r && !first) first = r;
	}
	if (mask & LN_SET_COMMENT) {
		r = set_comment(fs, fp, st->comment);
		if (r && !first) first = r;
	}
	return first;
}

/* ------------------------------------------------- mount and friends ---- */

static void read_opts(LnFs *fs, const LnUrl *url)
{
	char v[32];
	fs->cleartext = !ln_strcasecmp(ln_url_opt(url, "cleartext", "no", v, sizeof(v)), "yes");
	fs->showall = !ln_strcasecmp(ln_url_opt(url, "showall", "no", v, sizeof(v)), "yes");
	ln_url_opt(url, "comments", "yes", v, sizeof(v));
	fs->comments = !ln_strcasecmp(v, "no") ? 0 : !ln_strcasecmp(v, "all") ? 2 : 1;
	ln_url_opt(url, "uam", "", fs->uam, sizeof(fs->uam));
	ln_url_opt(url, "volpass", "", fs->volpass, sizeof(fs->volpass));
	fs->timeout_ms = ln_url_opt_int(url, "timeout", 30) * 1000;
	if (fs->timeout_ms < 2000)
		fs->timeout_ms = 2000;
	fs->maxio_opt = ln_url_opt_int(url, "maxio", 0);
}

static LnFs *fs_new(const LnUrl *url, const LnCreds *cr)
{
	LnFs *fs = ln_alloc(sizeof(*fs));
	if (!fs)
		return NULL;
	fs->cmd = ln_alloc(CMDMAX);
	fs->rbuf = ln_alloc(RBUFMAX);
	if (!fs->cmd || !fs->rbuf) {
		ln_free(fs->cmd);
		ln_free(fs->rbuf);
		ln_free(fs);
		return NULL;
	}
	fs->url = *url;
	if (cr)
		fs->cr = *cr;
	read_opts(fs, url);
	return fs;
}

static void fs_free(LnFs *fs)
{
	while (fs->files) {
		LnFile *f = fs->files;
		fs->files = f->next;
		ln_free(f->path);
		ln_free(f);
	}
	ln_wipe(&fs->cr, sizeof(fs->cr));
	ln_wipe(fs->volpass, sizeof(fs->volpass));
	ln_wipe(&fs->url, sizeof(fs->url));
	ln_free(fs->cmd);
	ln_free(fs->rbuf);
	ln_free(fs);
}

static int afp_mount(const LnUrl *url, const LnCreds *cr, LnFs **out)
{
	LnFs *fs;
	int r;
	if (!url->share[0])
		return LN_ENOSHARE;
	fs = fs_new(url, cr);
	if (!fs)
		return LN_ENOMEM;
	if (ln_utf8_nfc(url->path, fs->base, sizeof(fs->base)) < 0) {
		fs_free(fs);
		return LN_ENAMETOOLONG;
	}
	while (fs->base[0] && fs->base[strlen(fs->base) - 1] == '/')
		fs->base[strlen(fs->base) - 1] = 0;
	r = session_open(fs);
	if (!r) {
		r = open_volume(fs);
		if (!r && fs->base[0]) {
			AfpParams pp;
			r = getparms(fs, fs->base, &pp);
			if (!r && !pp.isdir)
				r = LN_ENOTDIR;
		}
		if (r)
			session_close(fs);
	}
	if (r) {
		fs_free(fs);
		return r == LN_ECONNRESET ? LN_EPROTO : r;
	}
	*out = fs;
	return LN_OK;
}

static void afp_unmount(LnFs *fs)
{
	AfpBuf b;
	LnFile *f;
	if (!fs)
		return;
	for (f = fs->files; f && fs->c.s; f = f->next)
		if (f->valid)
			close_fork(fs, f->fork);
	if (fs->c.s && fs->dt_state > 0) {
		start(fs, &b, FPCloseDT);
		afp_b_u16(&b, (unsigned)fs->dtref);
		call(fs, &b, fs->rbuf, 16, NULL);
	}
	if (fs->c.s) {
		start(fs, &b, FPCloseVol);
		afp_b_u16(&b, fs->volid);
		call(fs, &b, fs->rbuf, 16, NULL);
	}
	session_close(fs);
	fs_free(fs);
}

static int afp_reconnect(LnFs *fs)
{
	LnFile *f;
	int r;
	afp_conn_close(&fs->c, 0);
	fs->dt_state = 0;
	for (f = fs->files; f; f = f->next)
		f->valid = 0;
	if ((r = session_open(fs)) != 0)
		return r == LN_ECONNRESET ? LN_ECONNREFUSED : r;
	if ((r = open_volume(fs)) != 0) {
		afp_conn_close(&fs->c, 0);
		return r == LN_ECONNRESET ? LN_ECONNREFUSED : r;
	}
	/* reopen forks by path; files that vanished stay invalid (LN_ESTALE) */
	for (f = fs->files; f; f = f->next) {
		r = open_fork(fs, f->path, f->acc, &f->fork);
		if (r == LN_ECONNRESET)
			return r;
		f->valid = r == LN_OK;
		if (r)
			LN_LOG(1, "afp: could not reopen \"%s\": %s", f->path, ln_strerror(r));
	}
	LN_LOG(1, "afp: reconnected to %s", fs->url.host);
	return LN_OK;
}

static int afp_ping(LnFs *fs)
{
	AfpBuf b;
	int r;
	if (!fs->c.s)
		return LN_ECONNRESET;
	/* a tickle keeps the session alive; a cheap round trip proves the
	 * server is still there (and processes pending attentions) */
	if ((r = afp_conn_tickle(&fs->c)) != 0)
		return r;
	start(fs, &b, FPGetVolParms);
	afp_b_u16(&b, fs->volid);
	afp_b_u16(&b, VOLBIT_ATTR);
	r = call(fs, &b, fs->rbuf, 64, NULL);
	if (fs->c.attention & DSIATTN_SHUTDOWN)
		LN_LOG(0, "afp: server %s shuts down in %d minutes", fs->url.host, fs->c.attention & DSIATTN_MINUTES);
	return r;
}

static int afp_list_shares(const LnUrl *url, const LnCreds *cr, ln_share_cb cb, void *ud)
{
	LnFs *fs = fs_new(url, cr);
	AfpBuf b;
	size_t n, off;
	int r, i, cnt;
	if (!fs)
		return LN_ENOMEM;
	r = session_open(fs);
	if (r) {
		fs_free(fs);
		return r == LN_ECONNRESET ? LN_EPROTO : r;
	}
	start(fs, &b, FPGetSrvrParms);
	r = call(fs, &b, fs->rbuf, RBUFMAX, &n);
	if (!r && n < 5)
		r = LN_EPROTO;
	if (!r) {
		cnt = fs->rbuf[4];
		off = 5;
		for (i = 0; i < cnt && off + 2 <= n; i++) {
			int flags = fs->rbuf[off];
			size_t l = fs->rbuf[off + 1];
			char raw[256], name[256];
			if (off + 2 + l > n)
				break;
			memcpy(raw, fs->rbuf + off + 2, l);
			raw[l] = 0;
			off += 2 + l;
			if (ln_utf8_nfc(raw, name, sizeof(name)) < 0)
				ln_strlcpy(name, raw, sizeof(name));
			cb(ud, name, flags & 0x80 ? "volume password" : "");
		}
	}
	session_close(fs);
	fs_free(fs);
	return r;
}

static long afp_max_io(LnFs *fs)
{
	return fs->maxio;
}

const LnOps ln_afp_ops = {
	"afp", "AFP 3.x (older Macs, Time Capsule, Netatalk)", 548,
	afp_mount, afp_unmount, afp_reconnect, afp_ping,
	afp_statfs, afp_stat,
	afp_opendir, afp_readdir, afp_closedir,
	afp_open, afp_read, afp_write, afp_fstat, afp_truncate, afp_flush, afp_close,
	afp_mkdir, afp_remove, afp_rename, afp_setattr,
	afp_list_shares, afp_max_io
};
