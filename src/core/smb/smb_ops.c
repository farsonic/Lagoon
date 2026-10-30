/*
 * Lagoon - SMB 2/3 backend (Windows, macOS, Samba, NAS): the LnOps calls
 * on top of smb_conn.c / smb_auth.c. One TCP connection, one session and
 * one tree per mount; requests are synchronous (the handler is single
 * threaded); open files remember their path and flags so reconnect() can
 * reopen them transparently. MS-SMB2 sections 2.2 and 3.2.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "smb_int.h"
#include "../ln_charset.h"

/* access masks, attributes, create options */
#define A_READ_DATA        0x00000001u
#define A_WRITE_DATA       0x00000002u
#define A_APPEND_DATA      0x00000004u
#define A_READ_ATTR        0x00000080u
#define A_WRITE_ATTR       0x00000100u
#define A_DELETE           0x00010000u
#define A_SYNCHRONIZE      0x00100000u
#define A_FILE_READ        0x00120089u   /* read data, EA, attributes, READ_CONTROL, SYNCHRONIZE */
#define A_FILE_WRITE       0x00000116u   /* write data, append, write EA, write attributes */
#define A_DIR_LIST         (A_READ_DATA | A_READ_ATTR | A_SYNCHRONIZE)

#define FA_READONLY  0x01u
#define FA_HIDDEN    0x02u
#define FA_SYSTEM    0x04u
#define FA_DIRECTORY 0x10u
#define FA_ARCHIVE   0x20u
#define FA_NORMAL    0x80u

#define SH_ALL 7u                         /* FILE_SHARE_READ | WRITE | DELETE */
enum { D_SUPERSEDE, D_OPEN, D_CREATE, D_OPEN_IF, D_OVERWRITE, D_OVERWRITE_IF };
#define O_DIRECTORY      0x00000001u
#define O_NON_DIRECTORY  0x00000040u
#define O_OPEN_REPARSE   0x00200000u

#define IO_CAP_HOST   (1024u * 1024)
#define IO_CAP_AMIGA  65536u              /* 64 KB: one credit, fits the handler's buffers */

struct LnFile {
	LnFs   *fs;
	LnFile *next;
	u8      fid[16];
	int     flags;
	int     valid;
	char   *path;
};

struct LnDir {
	LnFs   *fs;
	LnDir  *next;
	u8      fid[16];
	int     valid;
	char   *path;
	u8     *buf;
	u32     len, pos, cap;
	int     restart, done;
	u32     returned, skip;
};

struct LnFs {
	SmbConn c;
	char    host[128];
	u16     port;
	char    share[128];
	char    root[LN_URL_MAX];         /* subdirectory of the share from the URL */
	LnCreds cr;
	u16     max_dialect;
	int     sign_opt;                 /* 1 required, 0 auto */
	int     enc_opt;                  /* 1 yes, 0 auto, -1 no */
	int     gmac;
	u16     cipher_only;
	int     timeout_ms;
	u32     io_cap;
	u32     share_flags, maxacc;
	int     readonly;
	int     aapl_pending;             /* send the AAPL context with the next CREATE */
	int     apple;
	LnFile *files;
	LnDir  *dirs;
	u8      p16[2048], q16[2048];     /* UTF-16 path scratch */
};

/* ------------------------------------------------------------ helpers */

static int fail(SmbConn *c, const char *what)
{
	int e = smb_err(c->status);
	LN_LOG(2, "smb: %s: %s", what, smb_status_name(c->status));
	return e ? e : LN_EIO;
}

static void fill_stat(LnStat *st, u32 attrs, u64 ct, u64 mt, u64 eof, u64 fileid)
{
	memset(st, 0, sizeof(*st));
	st->type = (attrs & FA_DIRECTORY) ? LN_T_DIR : LN_T_FILE;
	st->size = st->type == LN_T_DIR ? 0 : eof;
	st->mtime = smb_ft2unix(mt);
	st->ctime = ct ? smb_ft2unix(ct) : st->mtime;
	st->prot = LN_P_READ | LN_P_WRITE | LN_P_EXEC | LN_P_DELETE;
	if ((attrs & FA_READONLY) && st->type != LN_T_DIR)
		st->prot &= ~(u32)(LN_P_WRITE | LN_P_DELETE);
	if (attrs & FA_HIDDEN)
		st->prot |= LN_P_HIDDEN;
	if (!(attrs & FA_ARCHIVE))
		st->prot |= LN_P_ARCHIVE;   /* Amiga "archived" = not modified since backup */
	st->fileid = fileid;
}

static int path16(LnFs *fs, const char *path, u8 *out)
{
	return smb_path16(fs->root, path, out, 2048);
}

int smb_tree_connect(SmbConn *c, const char *host, const char *share, u32 *flags, u32 *maxacc)
{
	char unc[300];
	u8 *b;
	int n, r;
	ln_snprintf(unc, sizeof(unc), "\\\\%s\\%s", host, share);
	b = smb_body(c, 8 + 2 * strlen(unc) + 2);
	if (!b)
		return LN_ENOMEM;
	n = ln_utf8_to_utf16le(unc, strlen(unc), b + 8, 2 * strlen(unc) + 2);
	if (n < 0)
		return LN_ENAMETOOLONG;
	ln_put_le16(b, 9);
	ln_put_le16(b + 4, SMB2_HDR + 8);
	ln_put_le16(b + 6, (u16)n);
	c->tid = 0;
	r = smb_call(c, SMB2_TREE_CONNECT, 8 + (size_t)n, 0);
	if (r)
		return r;
	if (c->status != ST_OK) {
		LN_LOG(0, "smb: TREE_CONNECT %s: %s", unc, smb_status_name(c->status));
		r = smb_err(c->status);
		return r == LN_ENOENT ? LN_ENOSHARE : r ? r : LN_EIO;
	}
	if (c->blen < 16)
		return LN_EPROTO;
	c->tid = ln_le32(c->msg + 36);
	*flags = ln_le32(c->body + 4);
	*maxacc = ln_le32(c->body + 12);
	return LN_OK;
}

/* CREATE with optional QFid and AAPL create contexts */
int smb_create(SmbConn *c, const u8 *name, int nlen, SmbCreate *cr, int aapl)
{
	u8 *b, *ctx;
	size_t off, clen = 0, blen;
	int r;
	off = (56 + (size_t)(nlen ? nlen : 1) + 7) & ~(size_t)7;
	blen = off + 24 + (aapl ? 48 : 0);
	b = smb_body(c, blen);
	if (!b)
		return LN_ENOMEM;
	ln_put_le16(b, 57);
	ln_put_le32(b + 4, 2);                   /* impersonation */
	ln_put_le32(b + 24, cr->access);
	ln_put_le32(b + 28, cr->attrs);
	ln_put_le32(b + 32, cr->share);
	ln_put_le32(b + 36, cr->disposition);
	ln_put_le32(b + 40, cr->options);
	ln_put_le16(b + 44, SMB2_HDR + 56);
	ln_put_le16(b + 46, (u16)nlen);
	memcpy(b + 56, name, (size_t)nlen);
	/* contexts: QFid (no data); AAPL server query */
	ctx = b + off;
	ln_put_le32(ctx, aapl ? 24 : 0);         /* next */
	ln_put_le16(ctx + 4, 16);
	ln_put_le16(ctx + 6, 4);
	memcpy(ctx + 16, "QFid", 4);
	clen = 24;
	if (aapl) {
		u8 *a = ctx + 24;
		ln_put_le16(a + 4, 16);
		ln_put_le16(a + 6, 4);
		ln_put_le16(a + 10, 24);             /* data offset */
		ln_put_le32(a + 12, 24);             /* data length */
		memcpy(a + 16, "AAPL", 4);
		ln_put_le32(a + 24, 1);              /* kAAPL_SERVER_QUERY */
		ln_put_le64(a + 32, 7);              /* server caps | volume caps | model info */
		ln_put_le64(a + 40, 0);              /* client caps: plain client */
		clen += 48;
	}
	ln_put_le32(b + 48, (u32)(SMB2_HDR + off));
	ln_put_le32(b + 52, (u32)clen);
	r = smb_call(c, SMB2_CREATE, off + clen, 0);
	if (r)
		return r;
	if (c->status != ST_OK)
		return 1;                            /* caller looks at c->status */
	if (c->blen < 88)
		return LN_EPROTO;
	b = c->body;
	cr->action = ln_le32(b + 4);
	cr->ctime = ln_le64(b + 8);
	cr->atime = ln_le64(b + 16);
	cr->mtime = ln_le64(b + 24);
	cr->chtime = ln_le64(b + 32);
	cr->alloc = ln_le64(b + 40);
	cr->eof = ln_le64(b + 48);
	cr->fattrs = ln_le32(b + 56);
	memcpy(cr->fid, b + 64, 16);
	cr->diskid = 0;
	cr->apple = 0;
	{
		/* walk the reply's create contexts */
		u32 co = ln_le32(b + 80), cl = ln_le32(b + 84), p = co;
		while (cl && p + 16 <= c->msglen && p + 16 <= co + cl) {
			const u8 *e = c->msg + p;
			u32 next = ln_le32(e);
			u16 no = ln_le16(e + 4), nl = ln_le16(e + 6), dof = ln_le16(e + 10);
			u32 dl = ln_le32(e + 12);
			if (p + no + nl > c->msglen || p + dof + dl > c->msglen)
				break;
			if (nl == 4 && !memcmp(e + no, "QFid", 4) && dl >= 8)
				cr->diskid = ln_le64(e + dof);
			if (nl == 4 && !memcmp(e + no, "AAPL", 4) && dl >= 16) {
				const u8 *d = e + dof;
				u64 bits = ln_le64(d + 8);
				u32 k = 16;
				cr->apple = 1;
				if ((bits & 1) && k + 8 <= dl) {
					LN_LOG(2, "smb: AAPL server caps 0x%llx", (unsigned long long)ln_le64(d + k));
					k += 8;
				}
				if ((bits & 2) && k + 8 <= dl) {
					LN_LOG(2, "smb: AAPL volume caps 0x%llx", (unsigned long long)ln_le64(d + k));
					k += 8;
				}
				if ((bits & 4) && k + 8 <= dl) {
					u32 ml = ln_le32(d + k + 4);
					char model[64];
					model[0] = 0;
					if (k + 8 + ml <= dl)
						ln_utf16le_to_utf8(d + k + 8, LN_MIN(ml, 120u), model, sizeof(model));
					LN_LOG(1, "smb: Apple SMB server (model \"%s\")", model);
				}
			}
			if (!next)
				break;
			p += next;
		}
	}
	return LN_OK;
}

int smb_close(SmbConn *c, const u8 fid[16])
{
	u8 *b = smb_body(c, 24);
	int r;
	if (!b)
		return LN_ENOMEM;
	ln_put_le16(b, 24);
	memcpy(b + 8, fid, 16);
	r = smb_call(c, SMB2_CLOSE, 24, 0);
	if (r)
		return r;
	return c->status == ST_OK ? LN_OK : fail(c, "CLOSE");
}

static int do_create(LnFs *fs, const char *path, SmbCreate *cr)
{
	int n = path16(fs, path, fs->p16), r;
	if (n < 0)
		return n;
	r = smb_create(&fs->c, fs->p16, n, cr, fs->aapl_pending);
	if (fs->aapl_pending && r >= 0) {
		fs->aapl_pending = 0;
		if (r == 0 && cr->apple)
			fs->apple = 1;
	}
	if (r == 1)
		return fail(&fs->c, "CREATE");
	return r;
}

static int query_info(SmbConn *c, const u8 fid[16], u8 type, u8 cls, u32 outlen, const u8 **out, u32 *olen)
{
	u8 *b = smb_body(c, 41);
	int r;
	u32 o, l;
	if (!b)
		return LN_ENOMEM;
	ln_put_le16(b, 41);
	b[2] = type;
	b[3] = cls;
	ln_put_le32(b + 4, outlen);
	memcpy(b + 24, fid, 16);
	r = smb_call(c, SMB2_QUERY_INFO, 41, outlen);
	if (r)
		return r;
	if (c->status != ST_OK && c->status != ST_BUFFER_OVERFLOW)
		return fail(c, "QUERY_INFO");
	if (c->blen < 8)
		return LN_EPROTO;
	o = ln_le16(c->body + 2);
	l = ln_le32(c->body + 4);
	if (o + l > c->msglen)
		return LN_EPROTO;
	*out = c->msg + o;
	*olen = l;
	return LN_OK;
}

static int set_info(SmbConn *c, const u8 fid[16], u8 type, u8 cls, const u8 *data, u32 len)
{
	u8 *b = smb_body(c, 32 + len);
	int r;
	if (!b)
		return LN_ENOMEM;
	ln_put_le16(b, 33);
	b[2] = type;
	b[3] = cls;
	ln_put_le32(b + 4, len);
	ln_put_le16(b + 8, SMB2_HDR + 32);
	memcpy(b + 16, fid, 16);
	memcpy(b + 32, data, len);
	r = smb_call(c, SMB2_SET_INFO, 32 + len, 0);
	if (r)
		return r;
	return c->status == ST_OK ? LN_OK : fail(c, "SET_INFO");
}

/* --------------------------------------------------- connect / mount */

static int validate_negotiate(LnFs *fs)
{
	SmbConn *c = &fs->c;
	u8 *b = smb_body(c, 56 + 24 + 8);
	int r, nd = 0, i;
	static const u16 ds[] = { SMB_D202, SMB_D210, SMB_D300, SMB_D302 };
	if (!b)
		return LN_ENOMEM;
	ln_put_le16(b, 57);
	ln_put_le32(b + 4, 0x00140204);          /* FSCTL_VALIDATE_NEGOTIATE_INFO */
	memset(b + 8, 0xff, 16);
	ln_put_le32(b + 24, SMB2_HDR + 56);
	ln_put_le32(b + 36, 24);                 /* max output */
	ln_put_le32(b + 44, 1);                  /* FSCTL */
	ln_put_le32(b + 56, 0x04 | (c->offer_encrypt ? 0x40 : 0));
	memcpy(b + 60, c->cli_guid, 16);
	ln_put_le16(b + 76, (u16)(c->sign ? 3 : 1));
	for (i = 0; i < 4; i++)
		if (ds[i] <= c->max_dialect)
			ln_put_le16(b + 80 + 2 * nd++, ds[i]);
	ln_put_le16(b + 78, (u16)nd);
	ln_put_le32(b + 28, (u32)(24 + 2 * nd));
	c->force_sign = 1;
	r = smb_call(c, SMB2_IOCTL, 56 + 24 + 2 * (size_t)nd, 24);
	c->force_sign = 0;
	if (r)
		return r;
	if (c->status != ST_OK) {
		/* older servers / NAS boxes that do not implement it */
		LN_LOG(2, "smb: VALIDATE_NEGOTIATE: %s (ignored)", smb_status_name(c->status));
		return LN_OK;
	}
	{
		u32 oo = ln_le32(c->body + 32), ol = ln_le32(c->body + 36);
		const u8 *o = c->msg + oo;
		if (c->blen < 48 || ol < 24 || oo + 24 > c->msglen)
			return LN_EPROTO;
		if (ln_le32(o) != c->srv_caps || memcmp(o + 4, c->srv_guid, 16) ||
		    ln_le16(o + 20) != c->srv_secmode || ln_le16(o + 22) != c->dialect) {
			LN_LOG(0, "smb: VALIDATE_NEGOTIATE mismatch: possible downgrade attack");
			return LN_ECRYPTO;
		}
	}
	return LN_OK;
}

static int connect_all(LnFs *fs)
{
	SmbConn *c = &fs->c;
	int r;
	memset(c, 0, sizeof(*c));
	c->timeout_ms = fs->timeout_ms;
	c->max_dialect = fs->max_dialect;
	c->want_gmac = fs->gmac;
	c->cipher_only = fs->cipher_only;
	c->offer_encrypt = fs->enc_opt >= 0;
	c->sign = fs->sign_opt > 0;
	r = smb_connect(c, fs->host, fs->port);
	if (!r)
		r = smb_negotiate(c);
	if (r)
		goto bad;
	if (c->srv_secmode & 2)
		c->sign = 1;
	if (fs->enc_opt > 0) {
		if (c->cipher == SMB_C_NONE) {
			LN_LOG(0, "smb: encryption requested but the server/dialect does not support it");
			r = LN_ENOTSUP;
			goto bad;
		}
	}
	r = smb_session_setup(c, &fs->cr, fs->host, fs->sign_opt > 0);
	if (r)
		goto bad;
	if (fs->enc_opt > 0) {
		if (!c->keys) {
			LN_LOG(0, "smb: encryption requested but guest/anonymous sessions have no keys");
			r = LN_EAUTH;
			goto bad;
		}
		c->encrypt = 1;
	}
	r = smb_tree_connect(c, fs->host, fs->share, &fs->share_flags, &fs->maxacc);
	if (r)
		goto bad;
	if ((fs->share_flags & 0x8000) && !c->encrypt) {
		if (!c->keys || c->cipher == SMB_C_NONE) {
			LN_LOG(0, "smb: share \"%s\" requires encryption, which this session cannot do", fs->share);
			r = LN_EACCES;
			goto bad;
		}
		c->encrypt = 1;
	}
	if ((c->dialect == SMB_D300 || c->dialect == SMB_D302) && c->keys && !c->encrypt) {
		r = validate_negotiate(fs);
		if (r)
			goto bad;
	}
	fs->readonly = !(fs->maxacc & (A_WRITE_DATA | A_APPEND_DATA));
	fs->aapl_pending = 1;
	LN_LOG(1, "smb: connected to \\\\%s\\%s%s%s%s", fs->host, fs->share, c->sign ? ", signed" : "",
	       c->encrypt ? ", encrypted" : "", fs->readonly ? ", read-only" : "");
	return LN_OK;
bad:
	smb_disconnect(c);
	return r;
}

static void parse_opts(LnFs *fs, const LnUrl *u)
{
	char b[32];
	const char *v;
	v = ln_url_opt(u, "sign", "auto", b, sizeof(b));
	fs->sign_opt = (!ln_strcasecmp(v, "required") || !ln_strcasecmp(v, "yes")) ? 1 : 0;
	v = ln_url_opt(u, "encrypt", "auto", b, sizeof(b));
	fs->enc_opt = (!ln_strcasecmp(v, "yes") || !ln_strcasecmp(v, "required")) ? 1 :
	              !ln_strcasecmp(v, "no") ? -1 : 0;
	v = ln_url_opt(u, "dialect", "3.1.1", b, sizeof(b));
	fs->max_dialect = !strcmp(v, "2.0.2") || !strcmp(v, "2.0") || !strcmp(v, "2") ? SMB_D202 :
	                  !strcmp(v, "2.1") ? SMB_D210 : !strcmp(v, "3.0") || !strcmp(v, "3") ? SMB_D300 :
	                  !strcmp(v, "3.0.2") ? SMB_D302 : SMB_D311;
	v = ln_url_opt(u, "gmac", "yes", b, sizeof(b));
	fs->gmac = ln_strcasecmp(v, "no") != 0;
	v = ln_url_opt(u, "cipher", "", b, sizeof(b));
	fs->cipher_only = !ln_strcasecmp(v, "ccm") || !ln_strcasecmp(v, "ccm128") ? SMB_C_CCM128 :
	                  !ln_strcasecmp(v, "gcm") || !ln_strcasecmp(v, "gcm128") ? SMB_C_GCM128 :
	                  !ln_strcasecmp(v, "ccm256") ? SMB_C_CCM256 : !ln_strcasecmp(v, "gcm256") ? SMB_C_GCM256 : 0;
	fs->timeout_ms = ln_url_opt_int(u, "timeout", 30) * 1000;
	if (fs->timeout_ms <= 0)
		fs->timeout_ms = 30000;
#ifdef __VBCC__
	fs->io_cap = (u32)ln_url_opt_int(u, "io", (int)IO_CAP_AMIGA);
#else
	fs->io_cap = (u32)ln_url_opt_int(u, "io", (int)IO_CAP_HOST);
#endif
	if (fs->io_cap < 4096)
		fs->io_cap = 4096;
	if (fs->io_cap > 8u * 1024 * 1024)
		fs->io_cap = 8u * 1024 * 1024;
}

static int smb_mount(const LnUrl *u, const LnCreds *cr, LnFs **out)
{
	LnFs *fs;
	int r;
	*out = NULL;
	if (!u->share[0])
		return LN_ENOSHARE;
	fs = ln_alloc(sizeof(*fs));
	if (!fs)
		return LN_ENOMEM;
	ln_strlcpy(fs->host, u->host, sizeof(fs->host));
	fs->port = u->port ? u->port : 445;
	ln_strlcpy(fs->share, u->share, sizeof(fs->share));
	ln_strlcpy(fs->root, u->path, sizeof(fs->root));
	if (cr)
		fs->cr = *cr;
	parse_opts(fs, u);
	r = connect_all(fs);
	if (r) {
		ln_wipe(&fs->cr, sizeof(fs->cr));
		ln_free(fs);
		return r;
	}
	*out = fs;
	return LN_OK;
}

static void smb_unmount(LnFs *fs)
{
	SmbConn *c = &fs->c;
	while (fs->files) {
		LnFile *f = fs->files;
		fs->files = f->next;
		if (f->valid && !c->dead)
			smb_close(c, f->fid);
		ln_free(f->path);
		ln_free(f);
	}
	while (fs->dirs) {
		LnDir *d = fs->dirs;
		fs->dirs = d->next;
		if (d->valid && !c->dead)
			smb_close(c, d->fid);
		ln_free(d->path);
		ln_free(d->buf);
		ln_free(d);
	}
	if (!c->dead && c->sock) {
		u8 *b = smb_body(c, 4);
		if (b) {
			ln_put_le16(b, 4);
			smb_call(c, SMB2_TREE_DISCONNECT, 4, 0);
		}
		b = smb_body(c, 4);
		if (b && !c->dead) {
			ln_put_le16(b, 4);
			smb_call(c, SMB2_LOGOFF, 4, 0);
		}
	}
	smb_disconnect(c);
	ln_wipe(&fs->cr, sizeof(fs->cr));
	ln_free(fs);
}

static int open_file(LnFs *fs, const char *path, int flags, int reopen, u8 fid[16]);
static int open_dir(LnFs *fs, const char *path, u8 fid[16]);

static int smb_reconnect(LnFs *fs)
{
	LnFile *f;
	LnDir *d;
	int r;
	smb_disconnect(&fs->c);
	r = connect_all(fs);
	if (r)
		return r;
	/* reopen files by path (without create/truncate) and directories */
	for (f = fs->files; f; f = f->next) {
		f->valid = open_file(fs, f->path, f->flags, 1, f->fid) == LN_OK;
		if (!f->valid)
			LN_LOG(1, "smb: could not reopen %s after reconnect", f->path);
		if (fs->c.dead)
			return LN_ECONNRESET;
	}
	for (d = fs->dirs; d; d = d->next) {
		d->valid = open_dir(fs, d->path, d->fid) == LN_OK;
		d->restart = 1;
		d->done = 0;
		d->len = d->pos = 0;
		d->skip = d->returned;
		d->returned = 0;
		if (fs->c.dead)
			return LN_ECONNRESET;
	}
	return LN_OK;
}

static int smb_ping(LnFs *fs)
{
	SmbConn *c = &fs->c;
	u8 *b = smb_body(c, 4);
	int r;
	if (!b)
		return LN_ENOMEM;
	ln_put_le16(b, 4);
	r = smb_call(c, SMB2_ECHO, 4, 0);
	if (r)
		return r;
	return c->status == ST_OK ? LN_OK : fail(c, "ECHO");
}

/* --------------------------------------------------------------- stat */

static int smb_statfs(LnFs *fs, LnStatFs *st)
{
	SmbConn *c = &fs->c;
	SmbCreate cr;
	const u8 *o;
	u32 ol;
	int r, r2;
	memset(st, 0, sizeof(*st));
	memset(&cr, 0, sizeof(cr));
	cr.access = A_READ_ATTR | A_SYNCHRONIZE;
	cr.share = SH_ALL;
	cr.disposition = D_OPEN;
	cr.options = O_DIRECTORY;
	r = do_create(fs, "", &cr);
	if (r)
		return r;
	r = query_info(c, cr.fid, 2, 7, 32, &o, &ol);   /* FileFsFullSizeInformation */
	if (!r && ol >= 32) {
		u64 unit = (u64)ln_le32(o + 24) * ln_le32(o + 28);
		st->total_bytes = ln_le64(o) * unit;
		st->free_bytes = ln_le64(o + 8) * unit;
		st->block_size = unit > 0 && unit <= 0x100000 ? (u32)unit : 4096;
	} else if (!r)
		r = LN_EPROTO;
	if (!r && query_info(c, cr.fid, 2, 1, 256, &o, &ol) == LN_OK && ol >= 18) {
		u32 ll = ln_le32(o + 12);
		if (18 + ll <= ol)
			ln_utf16le_to_utf8(o + 18, ll, st->volume, sizeof(st->volume));
	}
	if (!st->volume[0])
		ln_strlcpy(st->volume, fs->share, sizeof(st->volume));
	st->readonly = fs->readonly;
	r2 = smb_close(c, cr.fid);
	return r ? r : r2;
}

static int smb_stat(LnFs *fs, const char *path, LnStat *st)
{
	SmbCreate cr;
	int r;
	memset(&cr, 0, sizeof(cr));
	cr.access = A_READ_ATTR | A_SYNCHRONIZE;
	cr.share = SH_ALL;
	cr.disposition = D_OPEN;
	r = do_create(fs, path, &cr);
	if (r)
		return r;
	fill_stat(st, cr.fattrs, cr.ctime, cr.mtime, cr.eof, cr.diskid);
	return smb_close(&fs->c, cr.fid);
}

/* --------------------------------------------------------- directories */

static int open_dir(LnFs *fs, const char *path, u8 fid[16])
{
	SmbCreate cr;
	int r;
	memset(&cr, 0, sizeof(cr));
	cr.access = A_DIR_LIST;
	cr.share = SH_ALL;
	cr.disposition = D_OPEN;
	cr.options = O_DIRECTORY;
	r = do_create(fs, path, &cr);
	if (r == LN_OK)
		memcpy(fid, cr.fid, 16);
	return r;
}

static int smb_opendir(LnFs *fs, const char *path, LnDir **out)
{
	LnDir *d = ln_alloc(sizeof(*d));
	int r;
	*out = NULL;
	if (!d)
		return LN_ENOMEM;
	d->fs = fs;
	d->path = ln_strdup(path);
	d->cap = LN_MIN(fs->c.max_trans, 65536u);
	d->buf = ln_alloc(d->cap);
	if (!d->path || !d->buf) {
		r = LN_ENOMEM;
		goto bad;
	}
	r = open_dir(fs, path, d->fid);
	if (r)
		goto bad;
	d->valid = 1;
	d->restart = 1;
	d->next = fs->dirs;
	fs->dirs = d;
	*out = d;
	return LN_OK;
bad:
	ln_free(d->path);
	ln_free(d->buf);
	ln_free(d);
	return r;
}

static int fetch_dir(LnDir *d)
{
	SmbConn *c = &d->fs->c;
	u8 *b = smb_body(c, 32 + 2);
	int r;
	u32 o, l;
	if (!b)
		return LN_ENOMEM;
	ln_put_le16(b, 33);
	b[2] = 0x25;                             /* FileIdBothDirectoryInformation */
	b[3] = d->restart ? 1 : 0;               /* SMB2_RESTART_SCANS */
	memcpy(b + 8, d->fid, 16);
	ln_put_le16(b + 24, SMB2_HDR + 32);
	ln_put_le16(b + 26, 2);
	ln_put_le32(b + 28, d->cap);
	b[32] = '*';
	r = smb_call(c, SMB2_QUERY_DIRECTORY, 34, d->cap);
	if (r)
		return r;
	d->restart = 0;
	if (c->status == ST_NO_MORE_FILES) {
		d->done = 1;
		return LN_OK;
	}
	if (c->status != ST_OK)
		return fail(c, "QUERY_DIRECTORY");
	if (c->blen < 8)
		return LN_EPROTO;
	o = ln_le16(c->body + 2);
	l = ln_le32(c->body + 4);
	if (o + l > c->msglen || l > d->cap)
		return LN_EPROTO;
	memcpy(d->buf, c->msg + o, l);
	d->len = l;
	d->pos = 0;
	if (!l)
		d->done = 1;
	return LN_OK;
}

static int smb_readdir(LnDir *d, char *name, size_t namemax, LnStat *st)
{
	char *tmp = (char *)d->fs->q16;          /* scratch (2 KB), keeps the handler stack small */
	for (;;) {
		const u8 *e;
		u32 next, nl;
		int n;
		if (!d->valid)
			return LN_ESTALE;
		if (d->pos >= d->len) {
			int r;
			if (d->done)
				return 0;
			r = fetch_dir(d);
			if (r)
				return r;
			if (d->done)
				return 0;
		}
		e = d->buf + d->pos;
		if (d->pos + 104 > d->len)
			return LN_EPROTO;
		next = ln_le32(e);
		nl = ln_le32(e + 60);
		if (d->pos + 104 + nl > d->len)
			return LN_EPROTO;
		d->pos = next ? d->pos + next : d->len;
		if ((nl == 2 && e[104] == '.' && e[105] == 0) ||
		    (nl == 4 && e[104] == '.' && e[105] == 0 && e[106] == '.' && e[107] == 0))
			continue;
		if (d->skip) {
			d->skip--;
			d->returned++;
			continue;
		}
		n = ln_utf16le_to_utf8(e + 104, nl, tmp, sizeof(d->fs->q16));
		if (n < 0 || ln_utf8_nfc(tmp, name, namemax) < 0) {
			LN_LOG(1, "smb: skipping a name that is too long");
			continue;
		}
		fill_stat(st, ln_le32(e + 56), ln_le64(e + 8), ln_le64(e + 24), ln_le64(e + 40), ln_le64(e + 96));
		d->returned++;
		return 1;
	}
}

static void smb_closedir(LnDir *d)
{
	LnFs *fs = d->fs;
	LnDir **pp;
	for (pp = &fs->dirs; *pp; pp = &(*pp)->next)
		if (*pp == d) {
			*pp = d->next;
			break;
		}
	if (d->valid && !fs->c.dead)
		smb_close(&fs->c, d->fid);
	ln_free(d->path);
	ln_free(d->buf);
	ln_free(d);
}

/* --------------------------------------------------------------- files */

static int open_file(LnFs *fs, const char *path, int flags, int reopen, u8 fid[16])
{
	SmbCreate cr;
	int r, w = flags & (LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC);
	memset(&cr, 0, sizeof(cr));
	cr.access = A_FILE_READ | (w ? A_FILE_WRITE : 0);
	cr.share = SH_ALL;
	cr.options = O_NON_DIRECTORY;
	if (reopen)
		cr.disposition = D_OPEN;
	else if ((flags & LN_O_CREATE) && (flags & LN_O_EXCL))
		cr.disposition = D_CREATE;
	else if ((flags & LN_O_CREATE) && (flags & LN_O_TRUNC))
		cr.disposition = D_OVERWRITE_IF;
	else if (flags & LN_O_CREATE)
		cr.disposition = D_OPEN_IF;
	else if (flags & LN_O_TRUNC)
		cr.disposition = D_OVERWRITE;
	else
		cr.disposition = D_OPEN;
	r = do_create(fs, path, &cr);
	if (r == LN_OK)
		memcpy(fid, cr.fid, 16);
	return r;
}

static int smb_open(LnFs *fs, const char *path, int flags, LnFile **out)
{
	LnFile *f;
	int r;
	*out = NULL;
	if (!path[0])
		return LN_EISDIR;
	if (fs->readonly && (flags & (LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC)))
		return LN_EROFS;
	f = ln_alloc(sizeof(*f));
	if (!f)
		return LN_ENOMEM;
	f->path = ln_strdup(path);
	if (!f->path) {
		ln_free(f);
		return LN_ENOMEM;
	}
	r = open_file(fs, path, flags, 0, f->fid);
	if (r) {
		ln_free(f->path);
		ln_free(f);
		return r;
	}
	f->fs = fs;
	f->flags = flags;
	f->valid = 1;
	f->next = fs->files;
	fs->files = f;
	*out = f;
	return LN_OK;
}

static long smb_read(LnFile *f, u64 off, void *buf, long n)
{
	SmbConn *c = &f->fs->c;
	u8 *dst = buf;
	long done = 0;
	if (!f->valid)
		return LN_ESTALE;
	while (done < n) {
		u32 want = smb_io_limit(c, c->max_read, f->fs->io_cap), got, doff;
		u8 *b;
		int r;
		if ((long)want > n - done)
			want = (u32)(n - done);
		b = smb_body(c, 49);
		if (!b)
			return LN_ENOMEM;
		ln_put_le16(b, 49);
		b[2] = 0x50;
		ln_put_le32(b + 4, want);
		ln_put_le64(b + 8, off + (u64)done);
		memcpy(b + 16, f->fid, 16);
		r = smb_call(c, SMB2_READ, 49, want);
		if (r)
			return r;
		if (c->status == ST_END_OF_FILE)
			break;
		if (c->status != ST_OK)
			return fail(c, "READ");
		if (c->blen < 16)
			return LN_EPROTO;
		doff = c->body[2];
		got = ln_le32(c->body + 4);
		if (doff + got > c->msglen || got > want)
			return LN_EPROTO;
		memcpy(dst + done, c->msg + doff, got);
		done += (long)got;
		if (got < want)
			break;
	}
	return done;
}

static long smb_write(LnFile *f, u64 off, const void *buf, long n)
{
	SmbConn *c = &f->fs->c;
	const u8 *src = buf;
	long done = 0;
	if (!f->valid)
		return LN_ESTALE;
	while (done < n) {
		u32 want = smb_io_limit(c, c->max_write, f->fs->io_cap), got;
		u8 *b;
		int r;
		if ((long)want > n - done)
			want = (u32)(n - done);
		b = smb_body(c, 48 + want);
		if (!b)
			return LN_ENOMEM;
		ln_put_le16(b, 49);
		ln_put_le16(b + 2, SMB2_HDR + 48);
		ln_put_le32(b + 4, want);
		ln_put_le64(b + 8, off + (u64)done);
		memcpy(b + 16, f->fid, 16);
		memcpy(b + 48, src + done, want);
		r = smb_call(c, SMB2_WRITE, 48 + want, 0);
		if (r)
			return r;
		if (c->status != ST_OK)
			return fail(c, "WRITE");
		if (c->blen < 16)
			return LN_EPROTO;
		got = ln_le32(c->body + 4);
		if (got > want)
			return LN_EPROTO;
		done += (long)got;
		if (got < want)
			break;
	}
	return done;
}

static int smb_fstat(LnFile *f, LnStat *st)
{
	const u8 *o;
	u32 ol;
	int r;
	if (!f->valid)
		return LN_ESTALE;
	r = query_info(&f->fs->c, f->fid, 1, 34, 56, &o, &ol);   /* FileNetworkOpenInformation */
	if (r)
		return r;
	if (ol < 56)
		return LN_EPROTO;
	fill_stat(st, ln_le32(o + 48), ln_le64(o), ln_le64(o + 16), ln_le64(o + 40), 0);
	return LN_OK;
}

static int smb_truncate(LnFile *f, u64 size)
{
	u8 d[8];
	if (!f->valid)
		return LN_ESTALE;
	ln_put_le64(d, size);
	return set_info(&f->fs->c, f->fid, 1, 20, d, 8);         /* FileEndOfFileInformation */
}

static int smb_flush(LnFile *f)
{
	SmbConn *c = &f->fs->c;
	u8 *b;
	int r;
	if (!f->valid)
		return LN_ESTALE;
	b = smb_body(c, 24);
	if (!b)
		return LN_ENOMEM;
	ln_put_le16(b, 24);
	memcpy(b + 8, f->fid, 16);
	r = smb_call(c, SMB2_FLUSH, 24, 0);
	if (r)
		return r;
	return c->status == ST_OK ? LN_OK : fail(c, "FLUSH");
}

static int smb_fclose(LnFile *f)
{
	LnFs *fs = f->fs;
	LnFile **pp;
	int r = LN_OK;
	for (pp = &fs->files; *pp; pp = &(*pp)->next)
		if (*pp == f) {
			*pp = f->next;
			break;
		}
	if (f->valid)
		r = smb_close(&fs->c, f->fid);
	ln_free(f->path);
	ln_free(f);
	return r;
}

/* ------------------------------------------------------ name operations */

static int smb_mkdir(LnFs *fs, const char *path)
{
	SmbCreate cr;
	int r;
	if (fs->readonly)
		return LN_EROFS;
	memset(&cr, 0, sizeof(cr));
	cr.access = A_READ_ATTR | A_SYNCHRONIZE;
	cr.share = SH_ALL;
	cr.disposition = D_CREATE;
	cr.options = O_DIRECTORY;
	r = do_create(fs, path, &cr);
	if (r)
		return r;
	return smb_close(&fs->c, cr.fid);
}

static int smb_remove(LnFs *fs, const char *path)
{
	SmbCreate cr;
	u8 one = 1;
	int r, r2;
	if (!path[0])
		return LN_EACCES;
	if (fs->readonly)
		return LN_EROFS;
	memset(&cr, 0, sizeof(cr));
	cr.access = A_DELETE | A_READ_ATTR | A_SYNCHRONIZE;
	cr.share = SH_ALL;
	cr.disposition = D_OPEN;
	cr.options = O_OPEN_REPARSE;
	r = do_create(fs, path, &cr);
	if (r)
		return r;
	r = set_info(&fs->c, cr.fid, 1, 13, &one, 1);              /* FileDispositionInformation */
	r2 = smb_close(&fs->c, cr.fid);
	return r ? r : r2;
}

static int smb_rename(LnFs *fs, const char *from, const char *to)
{
	SmbCreate cr;
	u8 *d;
	int n, r, r2;
	if (!from[0] || !to[0])
		return LN_EINVAL;
	if (fs->readonly)
		return LN_EROFS;
	n = path16(fs, to, fs->q16);
	if (n < 0)
		return n;
	memset(&cr, 0, sizeof(cr));
	cr.access = A_DELETE | A_READ_ATTR | A_SYNCHRONIZE;
	cr.share = SH_ALL;
	cr.disposition = D_OPEN;
	cr.options = O_OPEN_REPARSE;
	r = do_create(fs, from, &cr);
	if (r)
		return r;
	/* FILE_RENAME_INFORMATION_TYPE_2: ReplaceIfExists=0, RootDirectory=0 */
	d = ln_alloc(20 + (size_t)n);
	if (!d) {
		smb_close(&fs->c, cr.fid);
		return LN_ENOMEM;
	}
	ln_put_le32(d + 16, (u32)n);
	memcpy(d + 20, fs->q16, (size_t)n);
	r = set_info(&fs->c, cr.fid, 1, 10, d, 20 + (u32)n);
	ln_free(d);
	r2 = smb_close(&fs->c, cr.fid);
	return r ? r : r2;
}

static int smb_setattr(LnFs *fs, const char *path, const LnStat *st, u32 mask)
{
	SmbCreate cr;
	u8 bi[40];
	int r = LN_OK, r2;
	if (!(mask & (LN_SET_MTIME | LN_SET_PROT | LN_SET_SIZE)))
		return (mask & (LN_SET_COMMENT | LN_SET_MODE)) ? LN_ENOTSUP : LN_OK;
	if (fs->readonly)
		return LN_EROFS;
	memset(&cr, 0, sizeof(cr));
	cr.access = A_READ_ATTR | A_WRITE_ATTR | A_SYNCHRONIZE | ((mask & LN_SET_SIZE) ? A_WRITE_DATA : 0);
	cr.share = SH_ALL;
	cr.disposition = D_OPEN;
	r = do_create(fs, path, &cr);
	if (r)
		return r;
	if (mask & (LN_SET_MTIME | LN_SET_PROT)) {
		memset(bi, 0, sizeof(bi));
		if (mask & LN_SET_MTIME)
			ln_put_le64(bi + 16, smb_unix2ft(st->mtime));
		if (mask & LN_SET_PROT) {
			u32 a = cr.fattrs & ~(FA_READONLY | FA_HIDDEN | FA_ARCHIVE | FA_NORMAL);
			if (!(cr.fattrs & FA_DIRECTORY) &&
			    (!(st->prot & LN_P_WRITE) || !(st->prot & LN_P_DELETE)))
				a |= FA_READONLY;
			if (st->prot & LN_P_HIDDEN)
				a |= FA_HIDDEN;
			if (!(st->prot & LN_P_ARCHIVE))
				a |= FA_ARCHIVE;
			if (!a)
				a = FA_NORMAL;
			ln_put_le32(bi + 32, a);
		}
		r = set_info(&fs->c, cr.fid, 1, 4, bi, 40);              /* FileBasicInformation */
	}
	if (!r && (mask & LN_SET_SIZE)) {
		u8 d[8];
		ln_put_le64(d, st->size);
		r = set_info(&fs->c, cr.fid, 1, 20, d, 8);
	}
	r2 = smb_close(&fs->c, cr.fid);
	return r ? r : r2;
}

/* ------------------------------------------------------------- shares */

static int smb_list_shares(const LnUrl *u, const LnCreds *cr, ln_share_cb cb, void *ud)
{
	LnFs *fs = ln_alloc(sizeof(*fs));
	char b[8];
	int r, all;
	if (!fs)
		return LN_ENOMEM;
	ln_strlcpy(fs->host, u->host, sizeof(fs->host));
	fs->port = u->port ? u->port : 445;
	ln_strlcpy(fs->share, "IPC$", sizeof(fs->share));
	if (cr)
		fs->cr = *cr;
	parse_opts(fs, u);
	all = ln_strcasecmp(ln_url_opt(u, "hidden", "no", b, sizeof(b)), "no") != 0;
	r = connect_all(fs);
	if (!r) {
		r = smb_enum_shares(&fs->c, fs->host, all, cb, ud);
		smb_unmount(fs);
		return r;
	}
	ln_wipe(&fs->cr, sizeof(fs->cr));
	ln_free(fs);
	return r;
}

static long smb_max_io(LnFs *fs)
{
	u32 m = LN_MIN(fs->c.max_read, fs->c.max_write);
	m = LN_MIN(m, fs->io_cap);
	if (!fs->c.large_mtu)
		m = LN_MIN(m, 65536u);
	return (long)(m ? m : 65536u);
}

const LnOps ln_smb_ops = {
	"smb", "SMB 2/3 (Windows, macOS, Samba, NAS)", 445,
	smb_mount, smb_unmount, smb_reconnect, smb_ping,
	smb_statfs, smb_stat,
	smb_opendir, smb_readdir, smb_closedir,
	smb_open, smb_read, smb_write, smb_fstat, smb_truncate, smb_flush, smb_fclose,
	smb_mkdir, smb_remove, smb_rename, smb_setattr,
	smb_list_shares, smb_max_io
};
