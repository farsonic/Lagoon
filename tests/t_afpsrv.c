/*
 * Lagoon - tests for the AFP 2.1 server over AppleTalk (src/core/afpsrv): a scripted AppleShare
 * client talks ASP to the server through an in-memory ATP, and the server serves an in-memory
 * share (the mem backend). What System 7's client does when it logs in and the Finder works on
 * the volume: GetStatus, OpenSess, FPLogin, FPGetSrvrParms, FPOpenVol, FPGetFileDirParms,
 * FPEnumerate, files created, written (SPWrite and its WriteContinue), read back, Finder info
 * kept in AppleDouble files, resource forks, renames, moves, deletes, CloseSess; and the
 * transport's side: duplicate requests dropped, tickles started and cancelled, replies never
 * larger than the requester's room.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "testutil.h"
#include "ln_vfs.h"
#include "ln_sys.h"
#include "afpsrv/afps_int.h"

/* ---- the in-memory ATP ---- */
#define SSS 0x80
static const AsAddr ws = { 0xFF00, 0x42, 0xFD };     /* the workstation's own socket */
static struct {
	int    n;                    /* responses so far */
	u16    tid;
	u8     user[4];
	u8     data[AS_QUANTUM];
	size_t len;
	int    too_big;              /* a response larger than the request's bitmap allowed */
} rsp;
static struct treq { u32 id; AsAddr dst; u8 user[4]; u8 data[8]; size_t len; int xo, nresp, retries, cancelled; } treq[64];
static int ntreq;

static int t_respond(void *ud, const AsReq *q, const u8 user[4], const u8 *data, size_t len)
{
	unsigned b = q->bitmap, n = 0;
	for (; b; b >>= 1)
		n += b & 1;
	if (len > (size_t)n * AS_ATP_DATA)
		rsp.too_big = 1;
	rsp.n++;
	rsp.tid = q->tid;
	memcpy(rsp.user, user, 4);
	rsp.len = LN_MIN(len, sizeof rsp.data);
	if (len)
		memcpy(rsp.data, data, rsp.len);
	return LN_OK;
}
static int t_request(void *ud, AsAddr dst, const u8 user[4], const u8 *data, size_t len, int xo, int nresp,
                     int timeout_s, int retries, u32 *id)
{
	struct treq *t = &treq[ntreq % 64];
	memset(t, 0, sizeof *t);
	t->id = (u32)++ntreq;
	t->dst = dst;
	memcpy(t->user, user, 4);
	t->len = LN_MIN(len, sizeof t->data);
	if (len)
		memcpy(t->data, data, t->len);
	t->xo = xo; t->nresp = nresp; t->retries = retries;
	*id = t->id;
	return LN_OK;
}
static void t_cancel(void *ud, u32 id)
{
	int i;
	for (i = 0; i < ntreq && i < 64; i++)
		if (treq[i].id == id)
			treq[i].cancelled = 1;
}
static struct treq *last_req(void) { return ntreq ? &treq[(ntreq - 1) % 64] : NULL; }

/* ---- the scripted client ---- */
static AfpsServer *srv;
static u16 tid = 100;
static u8 sid;
static u16 seq;

static void send_req(int xo, unsigned bitmap, const u8 user[4], const u8 *data, size_t len, u16 use_tid)
{
	AsReq q;
	memset(&q, 0, sizeof q);
	q.src = ws;
	q.tid = use_tid;
	q.xo = (u8)xo;
	q.bitmap = (u8)bitmap;
	memcpy(q.user, user, 4);
	q.data = data;
	q.len = len;
	afps_input(srv, &q);
}

/* an AFP call over SPCommand; the reply's data in rsp.data, the result returned */
static s32 call(const AfpBuf *b)
{
	u8 u[4] = { SP_COMMAND, 0, 0, 0 };
	int before = rsp.n;
	u[1] = sid;
	seq++;
	ln_put_be16(u + 2, seq);
	send_req(1, 0xFF, u, b->p, b->len, ++tid);
	if (rsp.n != before + 1)
		return 1;                                /* no answer at all */
	return (s32)ln_be32(rsp.user);
}

/* an AFP call over SPWrite: the server's WriteContinue is answered with data */
static s32 call_write(const AfpBuf *b, const u8 *data, size_t len, int *asked)
{
	u8 u[4] = { SP_WRITE, 0, 0, 0 };
	int before = rsp.n, nreq = ntreq;
	struct treq *wc;
	u[1] = sid;
	seq++;
	ln_put_be16(u + 2, seq);
	send_req(1, 0xFF, u, b->p, b->len, ++tid);
	*asked = -1;
	if (ntreq == nreq + 1 && (wc = last_req())->user[0] == SP_WRITECONT) {
		*asked = ln_be16(wc->data);
		CHECK(wc->xo);
		CHECK_INT(wc->user[1], sid);
		CHECK_INT(ln_be16(wc->user + 2), seq);
		CHECK_INT(wc->dst.socket, ws.socket);
		afps_reply(srv, wc->id, 0, data, LN_MIN(len, (size_t)*asked));
	}
	if (rsp.n != before + 1)
		return 1;
	return (s32)ln_be32(rsp.user);
}

/* AFP 2 long-name pathname: type 2, then the elements separated by NUL */
static void path2(AfpBuf *b, const char *p)
{
	size_t n = strlen(p), i;
	afp_b_u8(b, AFPS_PATH_LONG);
	afp_b_u8(b, (unsigned)n);
	for (i = 0; i < n; i++)
		afp_b_u8(b, p[i] == ':' ? 0 : (u8)p[i]);
}

static u8 rq[700];
static AfpBuf B;
static AfpBuf *start(int cmd, int flag)
{
	afp_b_init(&B, rq, sizeof rq);
	afp_b_u8(&B, (unsigned)cmd);
	afp_b_u8(&B, (unsigned)flag);
	return &B;
}

/* FPGetFileDirParms: is-dir flag, and the parameters' start in rsp.data */
static s32 getparms(u32 did, const char *path, u16 fbm, u16 dbm, int *isdir)
{
	AfpBuf *b = start(FPGetFileDirParms, 0);
	s32 e;
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, did);
	afp_b_u16(b, fbm);
	afp_b_u16(b, dbm);
	path2(b, path);
	e = call(b);
	*isdir = e == 0 && rsp.len > 4 ? (rsp.data[4] & 0x80) != 0 : -1;
	return e;
}

/* the pstr at offset 'at' (a name offset field) of a parameter block */
static void pname(const u8 *params, unsigned off_field, char *out)
{
	unsigned o = ln_be16(params + off_field);
	memcpy(out, params + o + 1, params[o]);
	out[params[o]] = 0;
}

static s32 openfork(u32 did, const char *path, int rsrc, int acc, u16 *ref)
{
	AfpBuf *b = start(FPOpenFork, rsrc ? 0x80 : 0);
	s32 e;
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, did);
	afp_b_u16(b, FBIT_DFLEN | FBIT_RFLEN);
	afp_b_u16(b, (unsigned)acc);
	path2(b, path);
	e = call(b);
	*ref = e == 0 ? ln_be16(rsp.data + 2) : 0;
	return e;
}
static s32 closefork(u16 ref)
{
	AfpBuf *b = start(FPCloseFork, 0);
	afp_b_u16(b, ref);
	return call(b);
}
static s32 rd(u16 ref, u32 off, u32 n)
{
	AfpBuf *b = start(FPRead, 0);
	afp_b_u16(b, ref);
	afp_b_u32(b, off);
	afp_b_u32(b, n);
	afp_b_u8(b, 0);
	afp_b_u8(b, 0);
	return call(b);
}
static s32 wr(u16 ref, u32 off, const void *data, size_t n, int *asked)
{
	AfpBuf *b = start(FPWrite, 0);
	afp_b_u16(b, ref);
	afp_b_u32(b, off);
	afp_b_u32(b, (u32)n);
	return call_write(b, data, n, asked);
}

int main(void)
{
	const LnOps *ops;
	LnFs *fs;
	AsTransport t;
	AfpsConfig cfg;
	AfpSrvInfo si;
	AfpBuf *b;
	u8 u[4], status[1024];
	size_t n;
	int isdir, asked, i;
	s32 e;
	u32 dir1, newdir;
	u16 ref;
	char name[64];
	static u8 big[9000];

	CHECK_INT(ln_vfs_mount_url("mem://t/afps?seed=1", NULL, &ops, &fs), LN_OK);
	memset(&t, 0, sizeof t);
	t.socket = SSS;
	t.respond = t_respond;
	t.request = t_request;
	t.cancel = t_cancel;
	memset(&cfg, 0, sizeof cfg);
	ln_strlcpy(cfg.server, "Lagoon Test", sizeof cfg.server);
	ln_strlcpy(cfg.volume, "Share", sizeof cfg.volume);
	ln_strlcpy(cfg.user, "lagoon", sizeof cfg.user);
	ln_strlcpy(cfg.password, "secret", sizeof cfg.password);
	srv = afps_new(&cfg, ops, fs, &t);
	CHECK(srv != NULL);

	/* names: Mac Roman both ways, mangling, ':' and '/' */
	{
		u8 mac[40];
		char back[64];
		int l = afps_to_mac("\xc3\x9cn\xc3\xaf-x.txt", 77, mac, 31);   /* "Üni-x.txt" */
		CHECK_INT(l, 9);
		CHECK_INT(mac[0], 0x86);
		CHECK_INT(mac[2], 0x95);
		CHECK_INT(afps_mac_to_utf8(mac, (size_t)l, back, sizeof back), 11);
		CHECK_STR(back, "\xc3\x9cn\xc3\xaf-x.txt");
		l = afps_to_mac("a:b", 5, mac, 31);
		CHECK_INT(l, 3);
		CHECK_INT(mac[1], '/');
		afps_mac_to_utf8(mac, 3, back, sizeof back);
		CHECK_STR(back, "a:b");
		l = afps_to_mac("\xc5\xbf.txt", 0x1A2B, mac, 31);              /* U+017F: no Mac Roman */
		mac[l] = 0;
		CHECK_STR((char *)mac, "_.txt#1A2B");
		CHECK_INT(afps_mangled_id(mac, (size_t)l), 0x1A2B);
		CHECK_INT(afps_mangled_id((const u8 *)"plain", 5), 0);
		memset(back, 'x', 40);
		back[40] = 0;
		l = afps_to_mac(back, 0x10, mac, 31);
		CHECK_INT(l, 31);
		CHECK(!memcmp(mac + 28, "#10", 3));
	}

	/* GetStatus: the AFP client's own parser reads the status block */
	memset(u, 0, 4);
	u[0] = SP_GETSTATUS;
	send_req(0, 0xFF, u, NULL, 0, ++tid);
	CHECK_INT(rsp.n, 1);
	n = afps_status(srv, status, sizeof status);
	CHECK_INT(rsp.len, n);
	CHECK_INT(afp_parse_srvinfo(rsp.data, rsp.len, &si), LN_OK);
	CHECK_STR(si.name, "Lagoon Test");
	CHECK_STR(si.machine, "Lagoon");
	CHECK_INT(si.uams, UAM_GUEST | UAM_CLEARTXT);

	/* OpenSess: a bad version, then a good one, and the server starts tickling */
	u[0] = SP_OPENSESS; u[1] = ws.socket; u[2] = 0x02; u[3] = 0x00;
	send_req(1, 1, u, NULL, 0, ++tid);
	CHECK_INT((s16)ln_be16(rsp.user + 2), ASPERR_BADVERS);
	u[2] = 0x01;
	send_req(1, 1, u, NULL, 0, ++tid);
	CHECK_INT(rsp.user[0], SSS);
	sid = rsp.user[1];
	CHECK(sid != 0);
	CHECK_INT(ln_be16(rsp.user + 2), 0);
	CHECK_INT(afps_sessions(srv), 1);
	CHECK_INT(last_req()->user[0], SP_TICKLE);
	CHECK_INT(last_req()->user[1], sid);
	CHECK_INT(last_req()->retries, -1);
	CHECK(!last_req()->xo);

	/* before FPLogin: nothing */
	b = start(FPGetSrvrParms, 0);
	CHECK_INT(call(b), kFPUserNotAuth);
	/* FPLogin: an unknown version, a wrong password, then a guest */
	b = start(FPLogin, 0);
	b->len = 1;
	afp_b_pstr(b, "AFPVersion 1.1");
	afp_b_pstr(b, "No User Authent");
	CHECK_INT(call(b), kFPBadVersNum);
	b = start(FPLogin, 0);
	b->len = 1;
	afp_b_pstr(b, "AFPVersion 2.1");
	afp_b_pstr(b, "Cleartxt Passwrd");
	afp_b_pstr(b, "lagoon");
	afp_b_pad(b);
	afp_b_mem(b, "wrong\0\0\0", 8);
	CHECK_INT(call(b), kFPUserNotAuth);
	b = start(FPLogin, 0);
	b->len = 1;
	afp_b_pstr(b, "AFPVersion 2.1");
	afp_b_pstr(b, "Cleartxt Passwrd");
	afp_b_pstr(b, "Lagoon");
	afp_b_pad(b);
	afp_b_mem(b, "secret\0\0", 8);
	CHECK_INT(call(b), kFPNoErr);
	b = start(FPLogin, 0);
	b->len = 1;
	afp_b_pstr(b, "AFPVersion 2.1");
	afp_b_pstr(b, "No User Authent");
	CHECK_INT(call(b), kFPNoErr);

	/* a repeated exactly-once request is not served twice */
	{
		int before = rsp.n;
		b = start(FPGetSrvrParms, 0);
		u[0] = SP_COMMAND; u[1] = sid; ln_put_be16(u + 2, ++seq);
		send_req(1, 0xFF, u, b->p, b->len, ++tid);
		send_req(1, 0xFF, u, b->p, b->len, tid);
		CHECK_INT(rsp.n, before + 1);
	}

	/* FPGetSrvrParms: one volume */
	b = start(FPGetSrvrParms, 0);
	CHECK_INT(call(b), kFPNoErr);
	CHECK_INT(rsp.data[4], 1);
	CHECK_INT(rsp.data[6], 5);
	CHECK(!memcmp(rsp.data + 7, "Share", 5));

	/* FPOpenVol: wrong name, then ours (any case) */
	b = start(FPOpenVol, 0);
	afp_b_u16(b, AFPS_VBITS);
	afp_b_pstr(b, "Nope");
	CHECK_INT(call(b), kFPObjectNotFound);
	b = start(FPOpenVol, 0);
	afp_b_u16(b, AFPS_VBITS);
	afp_b_pstr(b, "share");
	CHECK_INT(call(b), kFPNoErr);
	CHECK_INT(ln_be16(rsp.data), AFPS_VBITS);
	CHECK_INT(ln_be16(rsp.data + 2), 0);                 /* attributes: not read-only */
	CHECK_INT(ln_be16(rsp.data + 4), 2);                 /* fixed directory IDs */
	CHECK_INT(ln_be16(rsp.data + 18), AFPS_VOLID);
	CHECK(ln_be32(rsp.data + 24) > 1000000);           /* bytes total: the mem share's 64 MB */
	pname(rsp.data + 2, 26, name);
	CHECK_STR(name, "Share");

	/* the root folder, by ID 2 and by the volume's name in ID 1 */
	CHECK_INT(getparms(AFPS_ROOT, "", 0, FDBIT_NODEID | FDBIT_PDID | FDBIT_LNAME | DBIT_OFFCNT | DBIT_ACCESS, &isdir), kFPNoErr);
	CHECK_INT(isdir, 1);
	CHECK_INT(ln_be32(rsp.data + 6), AFPS_PARENT_OF_ROOT);
	CHECK_INT(ln_be32(rsp.data + 12), AFPS_ROOT);
	CHECK_INT(ln_be16(rsp.data + 16), 7);                /* the seven seeded entries */
	CHECK_INT(ln_be32(rsp.data + 18), 0x87070707u);
	pname(rsp.data + 6, 4, name);
	CHECK_STR(name, "Share");
	CHECK_INT(getparms(AFPS_PARENT_OF_ROOT, "Share", 0, FDBIT_NODEID, &isdir), kFPNoErr);
	CHECK_INT(ln_be32(rsp.data + 6), AFPS_ROOT);

	/* a file: type and creator from its extension, its length, its name */
	CHECK_INT(getparms(AFPS_ROOT, "ReadMe.txt", FDBIT_FINFO | FDBIT_LNAME | FBIT_DFLEN | FBIT_RFLEN | FDBIT_PDID, 0, &isdir), kFPNoErr);
	CHECK_INT(isdir, 0);
	CHECK_INT(ln_be32(rsp.data + 6), AFPS_ROOT);
	CHECK(!memcmp(rsp.data + 10, "TEXTttxt", 8));
	CHECK_INT(ln_be32(rsp.data + 44), 35);
	CHECK_INT(ln_be32(rsp.data + 48), 0);
	pname(rsp.data + 6, 36, name);
	CHECK_STR(name, "ReadMe.txt");
	CHECK_INT(getparms(AFPS_ROOT, "NoSuchFile", FDBIT_ATTR, 0, &isdir), kFPObjectNotFound);
	CHECK_INT(getparms(AFPS_ROOT, "a/b.txt", FBIT_DFLEN, 0, &isdir), kFPNoErr);   /* "a:b.txt" */
	CHECK_INT(ln_be32(rsp.data + 6), 6);

	/* folders: Dir1's ID, then a path through it, and NUL NUL going back up */
	CHECK_INT(getparms(AFPS_ROOT, "Dir1", 0, FDBIT_NODEID | DBIT_OFFCNT, &isdir), kFPNoErr);
	dir1 = ln_be32(rsp.data + 6);
	CHECK(dir1 >= AFPS_FIRST_ID);
	CHECK_INT(ln_be16(rsp.data + 10), 1);
	CHECK_INT(getparms(AFPS_ROOT, "Dir1:sub:deep.txt", FBIT_DFLEN, 0, &isdir), kFPNoErr);
	CHECK_INT(ln_be32(rsp.data + 6), 5);
	CHECK_INT(getparms(dir1, "sub::sub:deep.txt", FBIT_DFLEN, 0, &isdir), kFPNoErr);
	CHECK_INT(getparms(dir1, "::ReadMe.txt", FBIT_DFLEN, 0, &isdir), kFPNoErr);
	CHECK_INT(ln_be32(rsp.data + 6), 35);
	CHECK_INT(getparms(AFPS_ROOT, "::x", FBIT_DFLEN, 0, &isdir), kFPObjectNotFound);

	/* FPEnumerate: everything, in pages of three, files only, folders only */
	{
		int total = 0, first = 1, got, dirs = 0;
		char seen_names[16][40];
		for (;;) {
			const u8 *p;
			b = start(FPEnumerate, 0);
			afp_b_u16(b, AFPS_VOLID);
			afp_b_u32(b, AFPS_ROOT);
			afp_b_u16(b, FDBIT_LNAME | FBIT_DFLEN);
			afp_b_u16(b, FDBIT_LNAME | FDBIT_NODEID);
			afp_b_u16(b, 3);
			afp_b_u16(b, (unsigned)first);
			afp_b_u16(b, 4096);
			path2(b, "");
			e = call(b);
			if (e == kFPObjectNotFound)
				break;
			CHECK_INT(e, kFPNoErr);
			if (e)
				break;
			got = ln_be16(rsp.data + 4);
			CHECK(got >= 1 && got <= 3);
			p = rsp.data + 6;
			for (i = 0; i < got; i++) {
				CHECK(p[0] % 2 == 0);
				if (total < 16)
					pname(p + 2, 0, seen_names[total]);
				dirs += (p[1] & 0x80) != 0;
				total++;
				p += p[0];
			}
			first += got;
		}
		CHECK_INT(total, 7);
		CHECK_INT(dirs, 1);
		CHECK_STR(seen_names[0], "Dir1");                /* sorted by name */
		/* the 134-byte name is shown mangled, and found again by that name */
		for (i = 0; i < total && i < 16; i++)
			if (strchr(seen_names[i], '#') && strlen(seen_names[i]) == 31)
				break;
		CHECK(i < total);
		if (i < total) {
			CHECK_INT(getparms(AFPS_ROOT, seen_names[i], FBIT_DFLEN, 0, &isdir), kFPNoErr);
			CHECK_INT(ln_be32(rsp.data + 6), 10);
		}
		/* folders only: StartIndex counts folders */
		b = start(FPEnumerate, 0);
		afp_b_u16(b, AFPS_VOLID);
		afp_b_u32(b, AFPS_ROOT);
		afp_b_u16(b, 0);
		afp_b_u16(b, FDBIT_NODEID);
		afp_b_u16(b, 20);
		afp_b_u16(b, 1);
		afp_b_u16(b, 4096);
		path2(b, "");
		CHECK_INT(call(b), kFPNoErr);
		CHECK_INT(ln_be16(rsp.data + 4), 1);
		CHECK_INT(ln_be32(rsp.data + 8), dir1);
	}

	/* create a folder and a file in it; soft create twice fails */
	b = start(FPCreateDir, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, AFPS_ROOT);
	path2(b, "From the Mac");
	CHECK_INT(call(b), kFPNoErr);
	newdir = ln_be32(rsp.data);
	CHECK(newdir >= AFPS_FIRST_ID);
	b = start(FPCreateFile, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, newdir);
	path2(b, "Notes");
	CHECK_INT(call(b), kFPNoErr);
	b = start(FPCreateFile, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, newdir);
	path2(b, "Notes");
	CHECK_INT(call(b), kFPObjectExists);

	/* Finder info: set type/creator and flags; kept in "._Notes" */
	b = start(FPSetFileDirParms, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, newdir);
	afp_b_u16(b, FDBIT_FINFO | FDBIT_MDATE);
	path2(b, "Notes");
	afp_b_pad(b);
	afp_b_u32(b, afp_date_from_unix(1000000000u));
	afp_b_mem(b, "ttroMACS\x01\x00\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 32);
	CHECK_INT(call(b), kFPNoErr);
	CHECK_INT(getparms(newdir, "Notes", FDBIT_FINFO | FDBIT_MDATE, 0, &isdir), kFPNoErr);
	CHECK(!memcmp(rsp.data + 10, "ttroMACS\x01\x00", 10));
	CHECK_INT(afp_date_to_unix(ln_be32(rsp.data + 6)), 1000000000u);
	{
		LnStat st;
		CHECK_INT(ops->stat(fs, "From the Mac/._Notes", &st), LN_OK);
		CHECK_INT(st.size, AFPS_AD_HDR);
	}
	/* ... and the "._" file is not shown */
	b = start(FPEnumerate, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, newdir);
	afp_b_u16(b, FDBIT_LNAME);
	afp_b_u16(b, FDBIT_LNAME);
	afp_b_u16(b, 20);
	afp_b_u16(b, 1);
	afp_b_u16(b, 4096);
	path2(b, "");
	CHECK_INT(call(b), kFPNoErr);
	CHECK_INT(ln_be16(rsp.data + 4), 1);
	CHECK_INT(getparms(newdir, "._Notes", FDBIT_ATTR, 0, &isdir), kFPObjectNotFound);

	/* the data fork: write 9000 bytes in two SPWrites, read them back in reads the client's
	 * buffer limits */
	for (i = 0; i < (int)sizeof big; i++)
		big[i] = (u8)(i * 7 + (i >> 8));
	CHECK_INT(openfork(newdir, "Notes", 0, AFP_ACC_READ | AFP_ACC_WRITE, &ref), kFPNoErr);
	CHECK(ref != 0);
	CHECK_INT(wr(ref, 0, big, sizeof big, &asked), kFPNoErr);
	CHECK_INT(asked, AS_QUANTUM);                         /* one transaction's worth */
	CHECK_INT(ln_be32(rsp.data), AS_QUANTUM);
	CHECK_INT(wr(ref, AS_QUANTUM, big + AS_QUANTUM, sizeof big - AS_QUANTUM, &asked), kFPNoErr);
	CHECK_INT(asked, sizeof big - AS_QUANTUM);
	CHECK_INT(ln_be32(rsp.data), sizeof big);
	{
		u32 off = 0;
		int ok = 1;
		while (off < sizeof big) {
			e = rd(ref, off, 4000);
			if (e != kFPNoErr && e != kFPEOFErr)
				break;
			ok &= !memcmp(rsp.data, big + off, rsp.len);
			off += (u32)rsp.len;
			if (e == kFPEOFErr || !rsp.len)
				break;
		}
		CHECK_INT(off, sizeof big);
		CHECK(ok);
		CHECK_INT(rd(ref, sizeof big, 100), kFPEOFErr);
		CHECK_INT(rsp.len, 0);
	}
	/* a read never answers more than the request's bitmap has room for */
	{
		AsReq q;
		b = start(FPRead, 0);
		afp_b_u16(b, ref);
		afp_b_u32(b, 0);
		afp_b_u32(b, 4000);
		afp_b_u8(b, 0);
		afp_b_u8(b, 0);
		memset(&q, 0, sizeof q);
		q.src = ws; q.tid = ++tid; q.xo = 1; q.bitmap = 0x03;
		q.user[0] = SP_COMMAND; q.user[1] = sid; ln_put_be16(q.user + 2, ++seq);
		q.data = b->p; q.len = b->len;
		afps_input(srv, &q);
		CHECK_INT(rsp.len, 2 * AS_ATP_DATA);
		CHECK(!rsp.too_big);
	}
	/* FPGetForkParms sees the length; FPSetForkParms truncates */
	b = start(FPGetForkParms, 0);
	afp_b_u16(b, ref);
	afp_b_u16(b, FBIT_DFLEN);
	CHECK_INT(call(b), kFPNoErr);
	CHECK_INT(ln_be32(rsp.data + 2), sizeof big);
	b = start(FPSetForkParms, 0);
	afp_b_u16(b, ref);
	afp_b_u16(b, FBIT_DFLEN);
	afp_b_u32(b, 5000);
	CHECK_INT(call(b), kFPNoErr);
	b = start(FPByteRangeLock, 0);
	afp_b_u16(b, ref);
	afp_b_u32(b, 10);
	afp_b_u32(b, 20);
	CHECK_INT(call(b), kFPNoErr);
	CHECK_INT(ln_be32(rsp.data), 10);
	/* deleting an open file is refused */
	b = start(FPDelete, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, newdir);
	path2(b, "Notes");
	CHECK_INT(call(b), kFPFileBusy);
	CHECK_INT(closefork(ref), kFPNoErr);
	CHECK_INT(closefork(ref), kFPParamErr);
	{
		LnStat st;
		CHECK_INT(ops->stat(fs, "From the Mac/Notes", &st), LN_OK);
		CHECK_INT(st.size, 5000);
	}

	/* the resource fork: none yet; write one, read it, and the Finder info is still there */
	CHECK_INT(openfork(newdir, "ReadMe.txt", 1, AFP_ACC_READ, &ref), kFPObjectNotFound);
	CHECK_INT(openfork(AFPS_ROOT, "ReadMe.txt", 1, AFP_ACC_READ, &ref), kFPNoErr);
	CHECK_INT(ln_be32(rsp.data + 8), 0);
	CHECK_INT(rd(ref, 0, 100), kFPEOFErr);
	CHECK_INT(closefork(ref), kFPNoErr);
	CHECK_INT(openfork(newdir, "Notes", 1, AFP_ACC_READ | AFP_ACC_WRITE, &ref), kFPNoErr);
	CHECK_INT(wr(ref, 0, "resource fork data", 18, &asked), kFPNoErr);
	CHECK_INT(wr(ref, 18, "!", 1, &asked), kFPNoErr);
	CHECK_INT(rd(ref, 0, 100), kFPEOFErr);
	CHECK_INT(rsp.len, 19);
	CHECK(!memcmp(rsp.data, "resource fork data!", 19));
	CHECK_INT(closefork(ref), kFPNoErr);
	CHECK_INT(getparms(newdir, "Notes", FDBIT_FINFO | FBIT_RFLEN | FBIT_DFLEN, 0, &isdir), kFPNoErr);
	CHECK(!memcmp(rsp.data + 6, "ttroMACS", 8));
	CHECK_INT(ln_be32(rsp.data + 38), 5000);
	CHECK_INT(ln_be32(rsp.data + 42), 19);
	{
		LnStat st;
		CHECK_INT(ops->stat(fs, "From the Mac/._Notes", &st), LN_OK);
		CHECK_INT(st.size, AFPS_AD_HDR + 19);
	}

	/* rename (the "._" file goes along), move into Dir1, refuse moving a folder into itself */
	b = start(FPRename, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, newdir);
	path2(b, "Notes");
	path2(b, "Notes \xa5 2");                            /* Mac Roman bullet */
	CHECK_INT(call(b), kFPNoErr);
	{
		LnStat st;
		CHECK_INT(ops->stat(fs, "From the Mac/Notes \xe2\x80\xa2 2", &st), LN_OK);
		CHECK_INT(ops->stat(fs, "From the Mac/._Notes \xe2\x80\xa2 2", &st), LN_OK);
	}
	b = start(FPMoveAndRename, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, newdir);
	afp_b_u32(b, dir1);
	path2(b, "Notes \xa5 2");
	path2(b, "");
	path2(b, "");
	CHECK_INT(call(b), kFPNoErr);
	CHECK_INT(getparms(dir1, "Notes \xa5 2", FBIT_RFLEN, 0, &isdir), kFPNoErr);
	CHECK_INT(ln_be32(rsp.data + 6), 19);
	b = start(FPMoveAndRename, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, AFPS_ROOT);
	afp_b_u32(b, dir1);
	path2(b, "Dir1");
	path2(b, "sub");
	path2(b, "");
	CHECK_INT(call(b), kFPCantMove);
	/* move the folder itself: IDs below it keep working */
	b = start(FPMoveAndRename, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, AFPS_ROOT);
	afp_b_u32(b, newdir);
	path2(b, "Dir1");
	path2(b, "");
	path2(b, "Moved");
	CHECK_INT(call(b), kFPNoErr);
	CHECK_INT(getparms(dir1, "sub:deep.txt", FBIT_DFLEN, 0, &isdir), kFPNoErr);
	{
		LnStat st;
		CHECK_INT(ops->stat(fs, "From the Mac/Moved/sub/deep.txt", &st), LN_OK);
	}

	/* delete: a full folder is refused, files and then the folder go (and their "._" files) */
	b = start(FPDelete, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, AFPS_ROOT);
	path2(b, "From the Mac");
	CHECK_INT(call(b), kFPDirNotEmpty);
	b = start(FPDelete, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, dir1);
	path2(b, "Notes \xa5 2");
	CHECK_INT(call(b), kFPNoErr);
	{
		LnStat st;
		CHECK_INT(ops->stat(fs, "From the Mac/Moved/._Notes \xe2\x80\xa2 2", &st), LN_ENOENT);
	}
	/* a folder with only AppleDouble leftovers can be deleted */
	{
		LnFile *f;
		CHECK_INT(ops->open(fs, "From the Mac/Moved/sub/._ghost", LN_O_WRITE | LN_O_CREATE, &f), LN_OK);
		ops->close(f);
	}
	b = start(FPDelete, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, dir1);
	path2(b, "sub:deep.txt");
	CHECK_INT(call(b), kFPNoErr);
	b = start(FPDelete, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, dir1);
	path2(b, "sub");
	CHECK_INT(call(b), kFPNoErr);

	/* desktop database: empty but answering; comments through the share's notes */
	b = start(FPOpenDT, 0);
	afp_b_u16(b, AFPS_VOLID);
	CHECK_INT(call(b), kFPNoErr);
	CHECK_INT(ln_be16(rsp.data), AFPS_DTREF);
	b = start(FPGetIcon, 0);
	afp_b_u16(b, AFPS_DTREF);
	afp_b_mem(b, "ttxtTEXT", 8);
	afp_b_u8(b, 1);
	afp_b_u8(b, 0);
	afp_b_u16(b, 256);
	CHECK_INT(call(b), kFPItemNotFound);
	b = start(FPAddComment, 0);
	afp_b_u16(b, AFPS_DTREF);
	afp_b_u32(b, AFPS_ROOT);
	path2(b, "ReadMe.txt");
	afp_b_pad(b);
	afp_b_pstr(b, "a note");
	CHECK_INT(call(b), kFPNoErr);
	b = start(FPGetComment, 0);
	afp_b_u16(b, AFPS_DTREF);
	afp_b_u32(b, AFPS_ROOT);
	path2(b, "ReadMe.txt");
	CHECK_INT(call(b), kFPNoErr);
	CHECK_INT(rsp.data[0], 6);
	b = start(FPCopyFile, 0);
	CHECK_INT(call(b), kFPCallNotSupported);

	/* the workstation's tickles keep the session; CloseSess ends it and its tickle */
	u[0] = SP_TICKLE; u[1] = sid; u[2] = u[3] = 0;
	{
		int before = rsp.n;
		send_req(0, 1, u, NULL, 0, ++tid);
		CHECK_INT(rsp.n, before);                        /* never answered */
	}
	afps_tick(srv);
	CHECK_INT(afps_sessions(srv), 1);
	{
		u32 tickle = 0;
		for (i = 0; i < ntreq && i < 64; i++)
			if (treq[i].user[0] == SP_TICKLE)
				tickle = treq[i].id;
		u[0] = SP_CLOSESESS; u[1] = sid;
		send_req(0, 1, u, NULL, 0, ++tid);
		CHECK_INT(afps_sessions(srv), 0);
		CHECK(treq[tickle - 1].cancelled);
	}
	/* a command on the closed session */
	b = start(FPGetSrvrParms, 0);
	CHECK_INT(call(b), ASPERR_SESSCLOSED);

	/* a second session, then the server goes: Attention and CloseSess to the workstation */
	u[0] = SP_OPENSESS; u[1] = ws.socket; u[2] = 0x01; u[3] = 0;
	send_req(1, 1, u, NULL, 0, ++tid);
	sid = rsp.user[1];
	CHECK_INT(afps_sessions(srv), 1);
	i = ntreq;
	afps_free(srv);
	CHECK_INT(ntreq, i + 2);
	CHECK_INT(treq[i].user[0], SP_ATTENTION);
	CHECK_INT(ln_be16(treq[i].user + 2), 0x8000);
	CHECK_INT(treq[i + 1].user[0], SP_CLOSESESS);
	CHECK(!rsp.too_big);

	/* a read-only share: writes refused with VolLocked */
	cfg.readonly = 1;
	cfg.user[0] = 0;
	srv = afps_new(&cfg, ops, fs, &t);
	u[0] = SP_OPENSESS; u[1] = ws.socket; u[2] = 0x01; u[3] = 0;
	send_req(1, 1, u, NULL, 0, ++tid);
	sid = rsp.user[1];
	b = start(FPLogin, 0);
	b->len = 1;
	afp_b_pstr(b, "AFPVersion 2.0");
	afp_b_pstr(b, "Cleartxt Passwrd");
	afp_b_pstr(b, "lagoon");
	afp_b_pad(b);
	afp_b_mem(b, "secret\0\0", 8);
	CHECK_INT(call(b), kFPBadUAM);                       /* no user configured */
	b = start(FPLogin, 0);
	b->len = 1;
	afp_b_pstr(b, "AFPVersion 2.0");
	afp_b_pstr(b, "No User Authent");
	CHECK_INT(call(b), kFPNoErr);
	b = start(FPCreateDir, 0);
	afp_b_u16(b, AFPS_VOLID);
	afp_b_u32(b, AFPS_ROOT);
	path2(b, "x");
	CHECK_INT(call(b), kFPVolLocked);
	CHECK_INT(openfork(AFPS_ROOT, "ReadMe.txt", 0, AFP_ACC_WRITE, &ref), kFPVolLocked);
	CHECK_INT(getparms(AFPS_ROOT, "", 0, DBIT_ACCESS, &isdir), kFPNoErr);
	CHECK_INT(ln_be32(rsp.data + 6), 0x83030303u);
	afps_free(srv);

	ops->unmount(fs);
	T_DONE("t_afpsrv");
}
