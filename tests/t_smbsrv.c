/* Lagoon - the SMB2 server core (src/core/srv): NTLMv2 checking with the
 * MS-NLMP 4.2.4 vectors, the server/export/user lines of lagoon.conf,
 * Latin-1 names, NetBIOS and mDNS answers (read back with Lagoon's own
 * discovery code), raw protocol units (SMB1 upgrade, anonymous logon,
 * compound CREATE+QUERY_INFO+CLOSE, bad frames), then Lagoon's SMB client
 * against the server over loopback: every dialect, signing, guest and
 * password shares, wrong passwords, read-only refusals, share lists and
 * the file operations, on a host directory and on the mem backend.
 * SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "testutil.h"
#include "ln_srv.h"
#include "ln_conf.h"
#include "ln_vfs.h"
#include "ln_sys.h"
#include "ln_net.h"
#include "ln_hash.h"
#include "ln_charset.h"
#include "ln_netbios.h"
#include "ln_mdns.h"
#include "../src/core/srv/srv_int.h"
#include "../src/host/fs_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/stat.h>

extern const LnOps ln_mem_ops;

static void unhex(const char *h, u8 *o)
{
	while (h[0] && h[1]) {
		unsigned v;
		sscanf(h, "%2x", &v);
		*o++ = (u8)v;
		h += 2;
	}
}

/* ------------------------------------------------------- NTLM vectors */
static void t_ntlm(void)
{
	u8 nt[16], key[16], base[16], resp[16 + 28 + 36 + 4];
	u8 srvchal[8], temp[28 + 36 + 4];
	size_t tl = 0;
	ln_nthash("Password", nt);
	CHECK_HEX(nt, 16, "a4f49c406510bdcab6824ee7c30fd852");
	srv_ntowfv2(nt, "User", "Domain", key);
	CHECK_HEX(key, 16, "0c868a403bfd7a93a3001ef22ef02e3f");
	/* MS-NLMP 4.2.4.1.3: temp = 0101 0000 0000 0000, time 0, client challenge aa.., 0, AV pairs, 0 */
	memset(temp, 0, sizeof(temp));
	temp[0] = 1; temp[1] = 1;
	memset(temp + 16, 0xaa, 8);
	tl = 28;
	unhex("02000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000", temp + tl);
	tl += 36 + 4;
	unhex("0123456789abcdef", srvchal);
	{
		LnHmacMd5 h;
		ln_hmac_md5_init(&h, key, 16);
		ln_hmac_md5_update(&h, srvchal, 8);
		ln_hmac_md5_update(&h, temp, tl);
		ln_hmac_md5_final(&h, resp);
	}
	CHECK_HEX(resp, 16, "68cd0ab851e51c96aabc927bebef6a1c");
	memcpy(resp + 16, temp, tl);
	CHECK(srv_ntlmv2_check(nt, "User", "Domain", srvchal, resp, 16 + tl, base) == 1);
	CHECK_HEX(base, 16, "8de40ccadbc14a82f15cb0ad0de95ca3");
	/* user names are case-insensitive, domains are taken as sent */
	CHECK(srv_ntlmv2_check(nt, "user", "Domain", srvchal, resp, 16 + tl, base) == 1);
	CHECK(srv_ntlmv2_check(nt, "User", "DOMAIN", srvchal, resp, 16 + tl, base) == 0);
	resp[3] ^= 1;
	CHECK(srv_ntlmv2_check(nt, "User", "Domain", srvchal, resp, 16 + tl, base) == 0);
	resp[3] ^= 1;
	ln_nthash("password", nt);
	CHECK(srv_ntlmv2_check(nt, "User", "Domain", srvchal, resp, 16 + tl, base) == 0);
	/* NTLMv1-sized responses are refused */
	CHECK(srv_ntlmv2_check(nt, "User", "Domain", srvchal, resp, 24, base) == 0);
}

/* ------------------------------------------------------------- conf */
static void t_conf(void)
{
	static const char text[] =
		"share name=\"NAS\" url=\"smb://nas/Public\" automount=no readonly=no\n"
		"server name=\"AMIGA\" workgroup=\"HOME\" signing=required mdns=no future=1\n"
		"export name=\"Work\" path=\"Work:\" readonly=no guest=yes\n"
		"export name=\"Projects\" path=\"DH0:Projects\" readonly=yes users=\"bob, alice\" comment=\"Code\"\n"
		"user name=\"bob\" nthash=\"a4f49c406510bdcab6824ee7c30fd852\"\n";
	LnConf *c = calloc(1, sizeof(LnConf)), *d = calloc(1, sizeof(LnConf));
	char *buf = malloc(65536);
	int line = 0;
	CHECK_INT(ln_conf_parse(c, text, &line), LN_OK);
	CHECK_INT(c->nshares, 1);
	CHECK_STR(c->server.name, "AMIGA");
	CHECK_STR(c->server.workgroup, "HOME");
	CHECK_INT(c->server.signing, 1);
	CHECK_INT(c->server.mdns, 0);
	CHECK_INT(c->server.netbios, 1);
	CHECK_INT(c->nexports, 2);
	CHECK_STR(c->export_[1].path, "DH0:Projects");
	CHECK_INT(c->export_[0].guest, 1);
	CHECK_INT(c->export_[1].readonly, 1);
	CHECK(ln_conf_user_listed(c->export_[1].users, "ALICE"));
	CHECK(!ln_conf_user_listed(c->export_[1].users, "carol"));
	CHECK_INT(c->nusers, 1);
	CHECK_HEX(c->user[0].nthash, 16, "a4f49c406510bdcab6824ee7c30fd852");
	CHECK_INT(ln_conf_put_user(c, "Alice", "s3cret"), LN_OK);
	CHECK_INT(ln_conf_put_user(c, "BOB", "Password"), LN_OK);
	CHECK_INT(c->nusers, 2);
	CHECK(ln_conf_format(c, buf, 65536) > 0);
	CHECK(strstr(buf, "s3cret") == NULL);                 /* never the plain password */
	CHECK(strstr(buf, "future=\"1\"") != NULL);           /* unknown keys kept */
	CHECK_INT(ln_conf_parse(d, buf, &line), LN_OK);
	CHECK_INT(d->nexports, 2);
	CHECK_INT(d->nusers, 2);
	CHECK_STR(d->export_[1].comment, "Code");
	CHECK(!memcmp(d->user[1].nthash, c->user[1].nthash, 16));
	CHECK_INT(ln_conf_remove_export(d, "work"), LN_OK);
	CHECK_INT(ln_conf_remove_user(d, "alice"), LN_OK);
	CHECK_INT(d->nexports, 1);
	CHECK_INT(d->nusers, 1);
	CHECK_INT(ln_conf_parse(d, "user name=\"x\" nthash=\"12\"\n", &line), LN_EINVAL);
	CHECK_INT(ln_conf_parse(d, "export name=\"x\"\n", &line), LN_EINVAL);
	/* a file without server lines formats without them */
	ln_conf_init(d);
	CHECK(ln_conf_format(d, buf, 65536) >= 0);
	CHECK(strstr(buf, "server") == NULL);
	free(c); free(d); free(buf);
}

static void t_latin1(void)
{
	char u[64], l[64];
	CHECK_INT(ln_latin1_to_utf8("Gr\xfc\xdf" "e", u, sizeof(u)), 7);
	CHECK_STR(u, "Gr\xc3\xbc\xc3\x9f" "e");
	CHECK_INT(ln_utf8_to_latin1(u, l, sizeof(l)), 5);
	CHECK_STR(l, "Gr\xfc\xdf" "e");
	CHECK_INT(ln_utf8_to_latin1("\xe2\x82\xac", l, sizeof(l)), -1);       /* the euro sign is not Latin-1 */
	CHECK_INT(ln_latin1_to_utf8("abc", u, 3), -1);
}

/* ------------------------------------------------------ name services */
static LnSrv *mksrv(void)
{
	LnSrvCfg cfg;
	memset(&cfg, 0, sizeof(cfg));
	ln_strlcpy(cfg.name, "Amiga1200", sizeof(cfg.name));
	return ln_srv_new(&cfg);
}

static void t_names(void)
{
	LnSrv *s = mksrv();
	LnAddr me, got[2];
	u8 q[600], a[1500];
	int n, uni;
	LnNbHost h;
	memset(&me, 0, sizeof(me));
	me.family = 4; me.a[0] = 192; me.a[1] = 168; me.a[2] = 1; me.a[3] = 77;
	n = ln_nb_build_query(q, sizeof(q), 0x1234, "amiga1200", 0x20, 1);
	n = ln_srv_nbns_answer(s, &me, q, (size_t)n, a, sizeof(a));
	CHECK(n > 0);
	CHECK_INT(ln_nb_parse_query(a, (size_t)n, 0x1234, got, 2), 1);
	CHECK(!memcmp(got[0].a, me.a, 4));
	n = ln_nb_build_query(q, sizeof(q), 1, "OTHER", 0x20, 1);
	CHECK_INT(ln_srv_nbns_answer(s, &me, q, (size_t)n, a, sizeof(a)), 0);
	n = ln_nb_build_status(q, sizeof(q), 7);
	n = ln_srv_nbns_answer(s, &me, q, (size_t)n, a, sizeof(a));
	CHECK(n > 0);
	memset(&h, 0, sizeof(h));
	CHECK_INT(ln_nb_parse_status(a, (size_t)n, &h), LN_OK);
	CHECK_STR(h.name, "AMIGA1200");
	CHECK_STR(h.group, "WORKGROUP");
	CHECK(h.server);

	{
		const char *names[1] = { "_smb._tcp.local" };
		u16 types[1] = { LN_DNS_PTR };
		LnMdns *m = ln_mdns_new();
		LnService sv[4];
		n = ln_mdns_query(q, sizeof(q), 99, names, types, 1, 0);
		n = ln_srv_mdns_answer(s, &me, 445, q, (size_t)n, 0, a, sizeof(a), &uni);
		CHECK(n > 0);
		CHECK(uni);
		CHECK_INT(ln_be16(a), 99);                       /* legacy unicast keeps the id */
		CHECK(ln_mdns_feed(m, a, (size_t)n) >= 4);
		CHECK_INT(ln_mdns_services(m, NULL, sv, 4), 1);
		CHECK_STR(sv[0].instance, "AMIGA1200");
		CHECK_STR(sv[0].host, "amiga1200.local");
		CHECK_INT(sv[0].port, 445);
		CHECK(!memcmp(sv[0].addr.a, me.a, 4));
		ln_mdns_free(m);
		/* a multicast query from 5353 is answered to the group */
		names[0] = "amiga1200.local";
		types[0] = LN_DNS_A;
		n = ln_mdns_query(q, sizeof(q), 0, names, types, 1, 0);
		n = ln_srv_mdns_answer(s, &me, 445, q, (size_t)n, 1, a, sizeof(a), &uni);
		CHECK(n > 0);
		CHECK(!uni);
		m = ln_mdns_new();
		ln_mdns_feed(m, a, (size_t)n);
		CHECK_INT(ln_mdns_addrs(m, "amiga1200.local", got, 2), 1);
		ln_mdns_free(m);
		names[0] = "other.local";
		n = ln_mdns_query(q, sizeof(q), 0, names, types, 1, 0);
		CHECK_INT(ln_srv_mdns_answer(s, &me, 445, q, (size_t)n, 1, a, sizeof(a), &uni), 0);
		n = ln_srv_mdns_announce(s, &me, 445, a, sizeof(a));
		CHECK(n > 0);
	}
	ln_srv_free(s);
}

/* ------------------------------------------------- raw protocol units */
static u8 msg[4096];
static u64 mid;

static size_t hdr(u16 cmd, u64 sid, u32 tid, u32 flags)
{
	memset(msg, 0, SMB2_HDR);
	memcpy(msg, "\xfeSMB", 4);
	ln_put_le16(msg + 4, 64);
	ln_put_le16(msg + 12, cmd);
	ln_put_le16(msg + 18, 8);
	ln_put_le32(msg + 16, flags);
	ln_put_le64(msg + 24, mid++);
	ln_put_le32(msg + 36, tid);
	ln_put_le64(msg + 40, sid);
	return SMB2_HDR;
}

static const u8 *rep;
static size_t replen;

static int send_msg(LnSrvConn *c, size_t n)
{
	return ln_srv_conn_input(c, msg, n, &rep, &replen);
}

static u32 rstatus(void) { return replen >= 68 ? ln_le32(rep + 4 + 8) : 0xffffffffu; }

static void t_units(void)
{
	LnSrv *s = mksrv();
	LnSrvConn *c;
	LnSrvShare sh;
	LnUrl u;
	size_t n;
	u64 sid;
	u32 tid;
	static const u8 smb1[] = {
		0xff, 'S', 'M', 'B', 0x72, 0, 0, 0, 0, 0x18, 0x53, 0xc8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0xff, 0xfe, 0, 0, 0, 0, 0, 0x22, 0,
		2, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0,
		2, 'S', 'M', 'B', ' ', '2', '.', '0', '0', '2', 0,
		2, 'S', 'M', 'B', ' ', '2', '.', '?', '?', '?', 0 };

	memset(&sh, 0, sizeof(sh));
	ln_strlcpy(sh.name, "Public", sizeof(sh.name));
	sh.guest = 1;
	sh.ops = &ln_mem_ops;
	ln_url_parse("mem://unit/pub?seed=1", &u);
	CHECK_INT(ln_mem_ops.mount(&u, NULL, &sh.fs), LN_OK);
	CHECK_INT(ln_srv_add_share(s, &sh), LN_OK);
	CHECK_INT(ln_srv_add_share(s, &sh), LN_EEXIST);

	/* SMB1 multi-protocol negotiate -> SMB2 response with dialect 0x02ff */
	c = ln_srv_conn_new(s, "unit");
	memcpy(msg, smb1, sizeof(smb1));
	CHECK_INT(send_msg(c, sizeof(smb1)), LN_OK);
	CHECK(replen > 4 + 64 + 64);
	CHECK(!memcmp(rep + 4, "\xfeSMB", 4));
	CHECK_INT(ln_le16(rep + 4 + 64 + 4), 0x02ff);
	CHECK_INT(((size_t)rep[1] << 16) | ((size_t)rep[2] << 8) | rep[3], replen - 4);
	/* then SMB2 NEGOTIATE 2.1 */
	n = hdr(SMB2_NEGOTIATE, 0, 0, 0);
	ln_put_le16(msg + n, 36); ln_put_le16(msg + n + 2, 2); ln_put_le16(msg + n + 4, 1);
	ln_put_le16(msg + n + 36, 0x0202); ln_put_le16(msg + n + 38, 0x0210);
	CHECK_INT(send_msg(c, n + 40), LN_OK);
	CHECK_INT(rstatus(), 0);
	CHECK_INT(ln_le16(rep + 4 + 64 + 4), 0x0210);
	/* a second NEGOTIATE is refused */
	CHECK_INT(send_msg(c, n + 40), LN_OK);
	CHECK(rstatus() != 0);
	/* requests without a session */
	n = hdr(SMB2_TREE_CONNECT, 0x1234, 0, 0);
	ln_put_le16(msg + n, 9);
	CHECK_INT(send_msg(c, n + 8), LN_OK);
	CHECK_INT(rstatus(), ST_USER_SESSION_DELETED);
	/* ECHO works without one */
	n = hdr(SMB2_ECHO, 0, 0, 0);
	ln_put_le16(msg + n, 4);
	CHECK_INT(send_msg(c, n + 4), LN_OK);
	CHECK_INT(rstatus(), 0);

	/* anonymous logon: raw NTLMSSP NEGOTIATE, then an empty AUTHENTICATE */
	n = hdr(SMB2_SESSION_SETUP, 0, 0, 0);
	ln_put_le16(msg + n, 25);
	ln_put_le16(msg + n + 12, 64 + 24);
	ln_put_le16(msg + n + 14, 32);
	memcpy(msg + n + 24, "NTLMSSP", 8);
	ln_put_le32(msg + n + 32, 1);
	ln_put_le32(msg + n + 36, 0x00000207);
	CHECK_INT(send_msg(c, n + 24 + 32), LN_OK);
	CHECK_INT(rstatus(), ST_MORE_PROCESSING);
	sid = ln_le64(rep + 4 + 40);
	CHECK(sid != 0);
	CHECK(!memcmp(rep + 4 + 64 + 8, "NTLMSSP", 8));       /* a raw CHALLENGE back */
	n = hdr(SMB2_SESSION_SETUP, sid, 0, 0);
	ln_put_le16(msg + n, 25);
	ln_put_le16(msg + n + 12, 64 + 24);
	ln_put_le16(msg + n + 14, 72);
	memset(msg + n + 24, 0, 72);
	memcpy(msg + n + 24, "NTLMSSP", 8);
	ln_put_le32(msg + n + 24 + 8, 3);
	{
		int f;
		for (f = 12; f <= 52; f += 8)
			ln_put_le32(msg + n + 24 + f + 4, 72);
	}
	ln_put_le32(msg + n + 24 + 60, 0x00000a05);
	CHECK_INT(send_msg(c, n + 24 + 72), LN_OK);
	CHECK_INT(rstatus(), 0);
	CHECK_INT(ln_le16(rep + 4 + 64 + 2), 2);              /* SMB2_SESSION_FLAG_IS_NULL */

	/* TREE_CONNECT \\x\Public */
	n = hdr(SMB2_TREE_CONNECT, sid, 0, 0);
	{
		int l = ln_utf8_to_utf16le("\\\\x\\public", 10, msg + n + 8, 100);
		ln_put_le16(msg + n, 9);
		ln_put_le16(msg + n + 4, 64 + 8);
		ln_put_le16(msg + n + 6, (u16)l);
		CHECK_INT(send_msg(c, n + 8 + (size_t)l), LN_OK);
	}
	CHECK_INT(rstatus(), 0);
	tid = ln_le32(rep + 4 + 36);
	CHECK(tid != 0);
	n = hdr(SMB2_TREE_CONNECT, sid, 0, 0);
	{
		int l = ln_utf8_to_utf16le("\\\\x\\nope", 8, msg + n + 8, 100);
		ln_put_le16(msg + n, 9);
		ln_put_le16(msg + n + 4, 64 + 8);
		ln_put_le16(msg + n + 6, (u16)l);
		CHECK_INT(send_msg(c, n + 8 + (size_t)l), LN_OK);
	}
	CHECK_INT(rstatus(), ST_BAD_NETWORK_NAME);

	/* compound: CREATE "Dir1/sub/deep.txt" + QUERY_INFO standard (related) + CLOSE (related) */
	{
		size_t o1, o2, o3;
		int l;
		const u8 *r1, *r2, *r3;
		o1 = hdr(SMB2_CREATE, sid, tid, 0);
		ln_put_le16(msg + o1, 57);
		ln_put_le32(msg + o1 + 24, 0x00120089);
		ln_put_le32(msg + o1 + 32, 7);
		ln_put_le32(msg + o1 + 36, 1);
		l = ln_utf8_to_utf16le("Dir1\\sub\\deep.txt", 17, msg + o1 + 56, 200);
		ln_put_le16(msg + o1 + 44, 64 + 56);
		ln_put_le16(msg + o1 + 46, (u16)l);
		o2 = (o1 + 56 + (size_t)l + 7) & ~(size_t)7;
		ln_put_le32(msg + 20, (u32)o2);
		memset(msg + o2, 0, 64 + 40);
		memcpy(msg + o2, "\xfeSMB", 4);
		ln_put_le16(msg + o2 + 4, 64);
		ln_put_le16(msg + o2 + 12, SMB2_QUERY_INFO);
		ln_put_le32(msg + o2 + 16, SMB2_FLAGS_RELATED);
		ln_put_le64(msg + o2 + 24, mid++);
		ln_put_le32(msg + o2 + 36, 0xffffffffu);
		ln_put_le64(msg + o2 + 40, 0xffffffffffffffffULL);
		ln_put_le16(msg + o2 + 64, 41);
		msg[o2 + 64 + 2] = 1;
		msg[o2 + 64 + 3] = 5;
		ln_put_le32(msg + o2 + 64 + 4, 1024);
		memset(msg + o2 + 64 + 24, 0xff, 16);
		o3 = o2 + 64 + 40;
		ln_put_le32(msg + o2 + 20, (u32)(o3 - o2));
		memset(msg + o3, 0, 64 + 24);
		memcpy(msg + o3, "\xfeSMB", 4);
		ln_put_le16(msg + o3 + 4, 64);
		ln_put_le16(msg + o3 + 12, SMB2_CLOSE);
		ln_put_le32(msg + o3 + 16, SMB2_FLAGS_RELATED);
		ln_put_le64(msg + o3 + 24, mid++);
		ln_put_le32(msg + o3 + 36, 0xffffffffu);
		ln_put_le64(msg + o3 + 40, 0xffffffffffffffffULL);
		ln_put_le16(msg + o3 + 64, 24);
		memset(msg + o3 + 64 + 8, 0xff, 16);
		CHECK_INT(send_msg(c, o3 + 64 + 24), LN_OK);
		r1 = rep + 4;
		CHECK_INT(ln_le32(r1 + 8), 0);
		CHECK(ln_le32(r1 + 20) != 0 && (ln_le32(r1 + 20) & 7) == 0);
		r2 = r1 + ln_le32(r1 + 20);
		CHECK_INT(ln_le16(r2 + 12), SMB2_QUERY_INFO);
		CHECK_INT(ln_le32(r2 + 8), 0);
		CHECK(ln_le32(r2 + 16) & SMB2_FLAGS_RELATED);
		CHECK_INT(ln_le64(r2 + 64 + 8 + 8), ln_le64(r1 + 64 + 48));   /* end of file = CREATE's */
		r3 = r2 + ln_le32(r2 + 20);
		CHECK_INT(ln_le16(r3 + 12), SMB2_CLOSE);
		CHECK_INT(ln_le32(r3 + 8), 0);
		CHECK_INT(ln_le32(r3 + 20), 0);
		CHECK_INT((size_t)(r3 - rep) + 64 + 60, replen);
		/* the same chain on a missing file: every reply carries the CREATE's error */
		l = ln_utf8_to_utf16le("missing.txt", 11, msg + o1 + 56, 200);
		ln_put_le16(msg + o1 + 46, (u16)l);
		CHECK_INT(send_msg(c, o3 + 64 + 24), LN_OK);
		r1 = rep + 4;
		CHECK_INT(ln_le32(r1 + 8), ST_OBJECT_NAME_NOT_FOUND);
		r2 = r1 + ln_le32(r1 + 20);
		CHECK_INT(ln_le32(r2 + 8), ST_OBJECT_NAME_NOT_FOUND);
		r3 = r2 + ln_le32(r2 + 20);
		CHECK_INT(ln_le32(r3 + 8), ST_OBJECT_NAME_NOT_FOUND);
	}
	/* paths that escape the share are refused */
	{
		int l;
		n = hdr(SMB2_CREATE, sid, tid, 0);
		ln_put_le16(msg + n, 57);
		ln_put_le32(msg + n + 24, 0x00120089);
		ln_put_le32(msg + n + 36, 1);
		l = ln_utf8_to_utf16le("Dir1\\..\\..\\etc", 14, msg + n + 56, 200);
		ln_put_le16(msg + n + 44, 64 + 56);
		ln_put_le16(msg + n + 46, (u16)l);
		CHECK_INT(send_msg(c, n + 56 + (size_t)l), LN_OK);
		CHECK_INT(rstatus(), ST_OBJECT_PATH_SYNTAX_BAD);
		l = ln_utf8_to_utf16le("a:stream", 8, msg + n + 56, 200);
		ln_put_le16(msg + n + 46, (u16)l);
		CHECK_INT(send_msg(c, n + 56 + (size_t)l), LN_OK);
		CHECK_INT(rstatus(), ST_OBJECT_NAME_INVALID);
	}
	/* a short or broken frame drops the connection; an encrypted one too */
	CHECK(ln_srv_conn_input(c, msg, 10, &rep, &replen) < 0);
	memcpy(msg, "\xfdSMB", 4);
	CHECK(ln_srv_conn_input(c, msg, 100, &rep, &replen) < 0);
	n = hdr(SMB2_ECHO, 0, 0, 0);
	ln_put_le32(msg + 20, 12);                             /* NextCommand not 8-aligned */
	CHECK(send_msg(c, n + 4) < 0);
	ln_srv_conn_free(c);
	ln_mem_ops.unmount(sh.fs);
	ln_srv_free(s);
}

/* --------------------------------------- client <-> server over loopback */
static int port;
static char tmp[128];
static volatile sig_atomic_t stop_flag;
static void on_term(int x) { (void)x; stop_flag = 1; }
static int poll_stop(void *ud) { (void)ud; return stop_flag || getppid() == 1 ? 1 : 0; }

static pid_t start_server(int sign_required)
{
	pid_t p = fork();
	if (p == 0) {
		LnSrvCfg cfg;
		LnSrvShare sh;
		LnSrvNet net;
		LnSrv *s;
		u8 h[16];
		char d[200];
		LnUrl u;
		signal(SIGTERM, on_term);
		memset(&cfg, 0, sizeof(cfg));
		ln_strlcpy(cfg.name, "LOOPAMIGA", sizeof(cfg.name));
		cfg.sign_required = sign_required;
		s = ln_srv_new(&cfg);
		ln_nthash("Secr3t!", h);
		ln_srv_add_user(s, "bob", h);
		ln_nthash("other", h);
		ln_srv_add_user(s, "carol", h);
		memset(&sh, 0, sizeof(sh));
		ln_strlcpy(sh.name, "Public", sizeof(sh.name));
		ln_strlcpy(sh.comment, "for everyone", sizeof(sh.comment));
		sh.guest = 1;
		sh.ops = &ln_posixfs_ops;
		snprintf(d, sizeof(d), "%s/pub", tmp);
		ln_posixfs_open(d, 0, &sh.fs);
		ln_srv_add_share(s, &sh);
		ln_strlcpy(sh.name, "Private", sizeof(sh.name));
		sh.comment[0] = 0;
		sh.guest = 0;
		ln_strlcpy(sh.users, "bob", sizeof(sh.users));
		snprintf(d, sizeof(d), "%s/priv", tmp);
		ln_posixfs_open(d, 0, &sh.fs);
		ln_srv_add_share(s, &sh);
		ln_strlcpy(sh.name, "Archive", sizeof(sh.name));
		sh.readonly = 1;
		sh.users[0] = 0;
		snprintf(d, sizeof(d), "%s/pub", tmp);
		ln_posixfs_open(d, 1, &sh.fs);
		ln_srv_add_share(s, &sh);
		ln_strlcpy(sh.name, "Mem", sizeof(sh.name));
		sh.readonly = 0;
		sh.ops = &ln_mem_ops;
		ln_url_parse("mem://loop/m?seed=1", &u);
		ln_mem_ops.mount(&u, NULL, &sh.fs);
		ln_srv_add_share(s, &sh);
		memset(&net, 0, sizeof(net));
		net.port = (u16)port;
		ln_srv_serve(s, &net, poll_stop, NULL);
		ln_srv_free_all(s);
		_exit(0);
	}
	{
		/* wait until it listens */
		int i;
		for (i = 0; i < 50; i++) {
			LnSock *k;
			struct timespec ts = { 0, 50000000 };
			if (ln_tcp_connect("127.0.0.1", (u16)port, 1000, &k) == LN_OK) {
				ln_sock_close(k);
				break;
			}
			nanosleep(&ts, NULL);
		}
	}
	return p;
}

static void stop_server(pid_t p)
{
	int st;
	kill(p, SIGTERM);
	waitpid(p, &st, 0);
}

static int mount(const char *user, const char *pass, const char *share, const char *opts, const LnOps **ops, LnFs **fs)
{
	char url[300];
	LnCreds cr;
	memset(&cr, 0, sizeof(cr));
	ln_strlcpy(cr.user, user, sizeof(cr.user));
	ln_strlcpy(cr.password, pass, sizeof(cr.password));
	snprintf(url, sizeof(url), "smb://127.0.0.1:%d/%s%s%s", port, share, opts[0] ? "?" : "", opts);
	return ln_vfs_mount_url(url, &cr, ops, fs);
}

static int found;
static void share_cb(void *ud, const char *name, const char *comment)
{
	(void)ud;
	if (!strcmp(name, "Public") && !strcmp(comment, "for everyone")) found |= 1;
	if (!strcmp(name, "Private")) found |= 2;
	if (!strcmp(name, "IPC$")) found |= 4;
}

/* the file operations on a mounted share */
static void exercise(const LnOps *ops, LnFs *fs, const char *what)
{
	LnFile *f;
	LnStat st;
	LnDir *d;
	LnStatFs sf;
	char name[256], *big = malloc(200000), *back = malloc(200000);
	int i, n, seen = 0;
	long k;
	for (i = 0; i < 200000; i++)
		big[i] = (char)(i * 7 + (i >> 9));
	CHECK_INT(ops->statfs(fs, &sf), LN_OK);
	CHECK(sf.total_bytes > 0);
	ops->remove(fs, "dir/sub/big.bin");
	ops->remove(fs, "dir/sub");
	ops->remove(fs, "dir/renamed.txt");
	ops->remove(fs, "dir");
	CHECK_INT(ops->mkdir(fs, "dir"), LN_OK);
	CHECK_INT(ops->mkdir(fs, "dir"), LN_EEXIST);
	CHECK_INT(ops->mkdir(fs, "dir/sub"), LN_OK);
	CHECK_INT(ops->open(fs, "dir/sub/big.bin", LN_O_READ | LN_O_WRITE | LN_O_CREATE | LN_O_EXCL, &f), LN_OK);
	for (i = 0; i < 200000; i += (int)k) {
		k = ops->write(f, (u64)i, big + i, LN_MIN(200000 - i, 50000));
		CHECK(k > 0);
		if (k <= 0) break;
	}
	CHECK_INT(ops->close(f), LN_OK);
	CHECK_INT(ops->stat(fs, "dir/sub/big.bin", &st), LN_OK);
	CHECK_INT(st.size, 200000);
	CHECK_INT(st.type, LN_T_FILE);
	CHECK_INT(ops->open(fs, "dir/sub/big.bin", LN_O_READ, &f), LN_OK);
	for (i = 0; i < 200000; i += (int)k) {
		k = ops->read(f, (u64)i, back + i, 65536);
		if (k <= 0) break;
	}
	CHECK_INT(i, 200000);
	CHECK(!memcmp(big, back, 200000));
	CHECK_INT(ops->read(f, 200000, back, 100), 0);
	CHECK_INT(ops->close(f), LN_OK);
	CHECK_INT(ops->open(fs, "dir/sub/big.bin", LN_O_READ | LN_O_WRITE | LN_O_CREATE | LN_O_EXCL, &f), LN_EEXIST);
	/* truncate, set the time */
	CHECK_INT(ops->open(fs, "dir/sub/big.bin", LN_O_READ | LN_O_WRITE, &f), LN_OK);
	CHECK_INT(ops->truncate(f, 1000), LN_OK);
	CHECK_INT(ops->close(f), LN_OK);
	memset(&st, 0, sizeof(st));
	st.mtime = 1000000000;
	CHECK_INT(ops->setattr(fs, "dir/sub/big.bin", &st, LN_SET_MTIME), LN_OK);
	CHECK_INT(ops->stat(fs, "dir/sub/big.bin", &st), LN_OK);
	CHECK_INT(st.size, 1000);
	CHECK_INT(st.mtime, 1000000000);
	/* rename, no overwrite */
	CHECK_INT(ops->open(fs, "dir/a.txt", LN_O_READ | LN_O_WRITE | LN_O_CREATE, &f), LN_OK);
	CHECK_INT(ops->write(f, 0, "abc", 3), 3);
	CHECK_INT(ops->close(f), LN_OK);
	CHECK_INT(ops->rename(fs, "dir/a.txt", "dir/renamed.txt"), LN_OK);
	CHECK_INT(ops->stat(fs, "dir/a.txt", &st), LN_ENOENT);
	CHECK_INT(ops->stat(fs, "dir/renamed.txt", &st), LN_OK);
	CHECK_INT(st.size, 3);
	/* listing */
	CHECK_INT(ops->opendir(fs, "dir", &d), LN_OK);
	while ((n = ops->readdir(d, name, sizeof(name), &st)) > 0) {
		if (!strcmp(name, "sub") && st.type == LN_T_DIR) seen |= 1;
		if (!strcmp(name, "renamed.txt") && st.size == 3) seen |= 2;
		if (!strcmp(name, ".") || !strcmp(name, "..")) seen |= 4;
	}
	ops->closedir(d);
	CHECK_INT(seen, 3);
	/* Latin-1 and other Unicode names */
	CHECK_INT(ops->open(fs, "dir/Gr\xc3\xbc\xc3\x9f" "e \xe2\x82\xac.txt", LN_O_READ | LN_O_WRITE | LN_O_CREATE, &f), LN_OK);
	ops->close(f);
	CHECK_INT(ops->stat(fs, "dir/Gr\xc3\xbc\xc3\x9f" "e \xe2\x82\xac.txt", &st), LN_OK);
	CHECK_INT(ops->remove(fs, "dir/Gr\xc3\xbc\xc3\x9f" "e \xe2\x82\xac.txt"), LN_OK);
	/* delete: a full directory refuses */
	CHECK_INT(ops->remove(fs, "dir/sub"), LN_ENOTEMPTY);
	CHECK_INT(ops->remove(fs, "dir/sub/big.bin"), LN_OK);
	CHECK_INT(ops->remove(fs, "dir/sub"), LN_OK);
	CHECK_INT(ops->remove(fs, "dir/renamed.txt"), LN_OK);
	CHECK_INT(ops->remove(fs, "dir"), LN_OK);
	CHECK_INT(ops->stat(fs, "dir", &st), LN_ENOENT);
	CHECK_INT(ops->remove(fs, "nothing"), LN_ENOENT);
	if (t_fail)
		fprintf(stderr, "t_smbsrv: %d failures after %s\n", t_fail, what);
	free(big);
	free(back);
}

static void t_loopback(void)
{
	static const char *const variants[] = { "dialect=2.0.2", "dialect=2.1", "dialect=3.0", "dialect=3.0.2", "",
	                                        "gmac=no", "dialect=2.1&sign=required", "dialect=3.0&sign=required",
	                                        "sign=required" };
	const LnOps *ops;
	LnFs *fs;
	LnStat st;
	LnFile *f;
	pid_t p;
	int i, r;
	char d[200];

	snprintf(tmp, sizeof(tmp), "/tmp/lagoon-srv-%d", (int)getpid());
	mkdir(tmp, 0755);
	snprintf(d, sizeof(d), "%s/pub", tmp); mkdir(d, 0755);
	snprintf(d, sizeof(d), "%s/priv", tmp); mkdir(d, 0755);
	snprintf(d, sizeof(d), "%s/pub/hello.txt", tmp);
	{
		FILE *fp = fopen(d, "w");
		fputs("hello", fp);
		fclose(fp);
	}
	port = 20000 + (int)(getpid() % 20000);
	p = start_server(0);

	for (i = 0; i < (int)LN_ARRAY_SIZE(variants); i++) {
		r = mount("bob", "Secr3t!", "Private", variants[i], &ops, &fs);
		CHECK_INT(r, LN_OK);
		if (r) {
			fprintf(stderr, "t_smbsrv: mount with \"%s\" failed: %s\n", variants[i], ln_strerror(r));
			continue;
		}
		exercise(ops, fs, variants[i]);
		ops->unmount(fs);
		printf("t_smbsrv: variant \"%s\" ok\n", variants[i]);
	}
	/* the mem backend behind the server */
	CHECK_INT(mount("bob", "Secr3t!", "Mem", "", &ops, &fs), LN_OK);
	if (fs) {
		exercise(ops, fs, "mem");
		ops->unmount(fs);
	}
	/* wrong password, unknown user on a server with a guest share = guest */
	CHECK_INT(mount("bob", "wrong", "Private", "", &ops, &fs), LN_EAUTH);
	CHECK_INT(mount("carol", "other", "Private", "", &ops, &fs), LN_EACCES);    /* not in users= */
	CHECK_INT(mount("nobody", "x", "Private", "", &ops, &fs), LN_EACCES);       /* a guest */
	CHECK_INT(mount("", "", "Private", "", &ops, &fs), LN_EACCES);
	CHECK_INT(mount("", "", "Nope", "", &ops, &fs), LN_ENOSHARE);
	/* guest on the guest share */
	r = mount("", "", "Public", "dialect=2.1", &ops, &fs);
	CHECK_INT(r, LN_OK);
	if (!r) {
		CHECK_INT(ops->stat(fs, "hello.txt", &st), LN_OK);
		CHECK_INT(st.size, 5);
		CHECK_INT(ops->stat(fs, "HELLO.TXT", &st), LN_OK);     /* names are case-insensitive */
		exercise(ops, fs, "guest");
		ops->unmount(fs);
	}
	r = mount("nobody", "x", "Public", "", &ops, &fs);
	CHECK_INT(r, LN_OK);
	if (!r) ops->unmount(fs);
	/* the read-only share refuses changes */
	r = mount("bob", "Secr3t!", "Archive", "", &ops, &fs);
	CHECK_INT(r, LN_OK);
	if (!r) {
		CHECK_INT(ops->stat(fs, "hello.txt", &st), LN_OK);
		CHECK_INT(ops->open(fs, "hello.txt", LN_O_READ, &f), LN_OK);
		if (f) ops->close(f);
		r = ops->open(fs, "new.txt", LN_O_READ | LN_O_WRITE | LN_O_CREATE, &f);
		CHECK(r == LN_EACCES || r == LN_EROFS);
		r = ops->open(fs, "hello.txt", LN_O_READ | LN_O_WRITE, &f);
		CHECK(r == LN_EACCES || r == LN_EROFS);
		r = ops->remove(fs, "hello.txt");
		CHECK(r == LN_EACCES || r == LN_EROFS);
		r = ops->mkdir(fs, "x");
		CHECK(r == LN_EACCES || r == LN_EROFS);
		CHECK_INT(ops->stat(fs, "hello.txt", &st), LN_OK);
		ops->unmount(fs);
	}
	/* share list (srvsvc over IPC$) */
	{
		LnUrl u;
		LnCreds cr;
		char url[100];
		memset(&cr, 0, sizeof(cr));
		snprintf(url, sizeof(url), "smb://127.0.0.1:%d/", port);
		ln_url_parse(url, &u);
		found = 0;
		CHECK_INT(ln_vfs_find("smb")->list_shares(&u, &cr, share_cb, NULL), LN_OK);
		CHECK_INT(found & 3, 3);
		snprintf(url, sizeof(url), "smb://127.0.0.1:%d/?hidden=yes", port);
		ln_url_parse(url, &u);
		ln_strlcpy(cr.user, "bob", sizeof(cr.user));
		ln_strlcpy(cr.password, "Secr3t!", sizeof(cr.password));
		found = 0;
		CHECK_INT(ln_vfs_find("smb")->list_shares(&u, &cr, share_cb, NULL), LN_OK);
		CHECK_INT(found, 7);
	}
	/* several clients at once */
	{
		const LnOps *o1, *o2;
		LnFs *f1 = NULL, *f2 = NULL;
		CHECK_INT(mount("bob", "Secr3t!", "Private", "", &o1, &f1), LN_OK);
		CHECK_INT(mount("", "", "Public", "", &o2, &f2), LN_OK);
		if (f1 && f2) {
			CHECK_INT(o1->stat(f1, "", &st), LN_OK);
			CHECK_INT(o2->stat(f2, "hello.txt", &st), LN_OK);
			CHECK_INT(o1->ping(f1), LN_OK);
		}
		if (f1) o1->unmount(f1);
		if (f2) o2->unmount(f2);
	}
	stop_server(p);

	/* signing required: no guests, unsigned clients refused */
	p = start_server(1);
	CHECK_INT(mount("", "", "Public", "", &ops, &fs), LN_EAUTH);
	r = mount("bob", "Secr3t!", "Private", "dialect=2.1", &ops, &fs);
	CHECK_INT(r, LN_OK);
	if (!r) {
		CHECK_INT(ops->stat(fs, "", &st), LN_OK);
		ops->unmount(fs);
	}
	stop_server(p);
	snprintf(d, sizeof(d), "%s/pub/hello.txt", tmp); unlink(d);
	snprintf(d, sizeof(d), "%s/pub", tmp); rmdir(d);
	snprintf(d, sizeof(d), "%s/priv", tmp); rmdir(d);
	rmdir(tmp);
}

int main(void)
{
	ln_log_level = getenv("LN_LOG") ? atoi(getenv("LN_LOG")) : 0;
	ln_net_init();
	t_ntlm();
	t_conf();
	t_latin1();
	t_names();
	t_units();
	t_loopback();
	T_DONE("t_smbsrv");
}
