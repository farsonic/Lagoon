/* Lagoon - mDNS/DNS-SD tests: query encoding, canned responses (compression,
 * goodbye records, malformed packets) and a live browse/resolve against
 * tests/servers/mdns/responder.py (skipped without python3).
 * SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "testutil.h"
#include "ln_mdns.h"
#include "ln_net.h"
#include "ln_sys.h"
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

static void queries(void)
{
	u8 b[512];
	const char *names[2] = { "_smb._tcp.local", "nas.local" };
	u16 types[2] = { LN_DNS_PTR, LN_DNS_A };
	int l = ln_mdns_query(b, sizeof(b), 0x1234, names, types, 2, 1);
	CHECK_INT(l, 12 + 17 + 4 + 11 + 4);
	CHECK_HEX(b, 12, "123400000002000000000000");
	CHECK_HEX(b + 12, 21, "045f736d62045f746370056c6f63616c00000c8001");
	CHECK_HEX(b + 33, 15, "036e6173056c6f63616c0000018001");
	CHECK_INT(ln_mdns_query(b, 20, 1, names, types, 2, 0), LN_ENOSPC);
	CHECK_INT(ln_dns_put_name(b, sizeof(b), "a..b"), LN_EINVAL);
	CHECK_STR(ln_mdns_scheme("_afpovertcp._tcp"), "afp");
	CHECK(ln_mdns_scheme("_http._tcp") == NULL);
}

/* response: PTR _smb._tcp.local -> "My.NAS" (compressed), additional SRV
 * (port 445, target nas.local with a pointer to "local"), TXT, A */
static const u8 canned[] = {
	0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03,
	/* 12: _smb._tcp.local */
	0x04, '_', 's', 'm', 'b', 0x04, '_', 't', 'c', 'p', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
	/* 29: PTR IN ttl 4500 rdlen 9 */
	0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x09,
	/* 39: "My.NAS" + ptr 12 */
	0x06, 'M', 'y', '.', 'N', 'A', 'S', 0xc0, 0x0c,
	/* 48: SRV name ptr 39 */
	0xc0, 39, 0x00, 0x21, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0c,
	/* 60: prio weight port 445; 66: "nas" + ptr 22 ("local") */
	0x00, 0x00, 0x00, 0x00, 0x01, 0xbd, 0x03, 'n', 'a', 's', 0xc0, 22,
	/* 72: TXT */
	0xc0, 39, 0x00, 0x10, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x10,
	0x0b, 'p', 'a', 't', 'h', '=', '/', 's', 'r', 'v', '/', 'a', 0x03, 'u', '=', '1',
	/* 100: A nas.local (ptr 66) */
	0xc0, 66, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 192, 168, 1, 10,
};

static void canned_packets(void)
{
	LnMdns *m = ln_mdns_new();
	LnService s[4];
	LnAddr a[2];
	u8 p[sizeof(canned)];
	char buf[64];
	size_t off;
	char nm[64], first[16];
	CHECK(m != NULL);
	off = 66;
	CHECK_INT(ln_dns_get_name(canned, sizeof(canned), &off, nm, sizeof(nm), first, sizeof(first)), 0);
	CHECK_STR(nm, "nas.local"); CHECK_STR(first, "nas"); CHECK_INT(off, 72);
	CHECK_INT(ln_mdns_feed(m, canned, sizeof(canned)), 4);
	CHECK_INT(ln_mdns_services(m, NULL, s, 4), 1);
	CHECK_STR(s[0].type, "_smb._tcp"); CHECK_STR(s[0].scheme, "smb");
	CHECK_STR(s[0].instance, "My.NAS"); CHECK_STR(s[0].host, "nas.local");
	CHECK_INT(s[0].port, 445); CHECK_INT(s[0].addr.family, 4);
	CHECK_HEX(s[0].addr.a, 4, "c0a8010a");
	CHECK_STR(s[0].txt, "path=/srv/a\nu=1");
	CHECK(ln_mdns_txt(&s[0], "PATH", buf, sizeof(buf)) && !strcmp(buf, "/srv/a"));
	CHECK(ln_mdns_txt(&s[0], "pat", buf, sizeof(buf)) == NULL);
	CHECK_INT(ln_mdns_addrs(m, "NAS.local", a, 2), 1);
	/* the same packet again: no duplicates */
	CHECK_INT(ln_mdns_feed(m, canned, sizeof(canned)), 4);
	CHECK_INT(ln_mdns_services(m, NULL, s, 4), 1);
	/* other types only */
	{
		const char *t[] = { "_nfs._tcp", NULL };
		CHECK_INT(ln_mdns_services(m, t, s, 4), 0);
	}
	ln_mdns_free(m);

	/* a query (QR=0) is ignored, truncated packets are errors */
	m = ln_mdns_new();
	memcpy(p, canned, sizeof(p));
	p[2] = 0;
	CHECK_INT(ln_mdns_feed(m, p, sizeof(p)), 0);
	CHECK_INT(ln_mdns_feed(m, canned, 60), LN_EPROTO);
	CHECK_INT(ln_mdns_feed(m, canned, 5), LN_EPROTO);
	/* compression loop */
	memcpy(p, canned, sizeof(p));
	p[12] = 0xc0; p[13] = 12;
	CHECK_INT(ln_mdns_feed(m, p, sizeof(p)), LN_EPROTO);
	/* goodbye (TTL 0) on the PTR: no service; A without SRV is kept */
	memcpy(p, canned, sizeof(p));
	p[35] = 0; p[36] = 0;
	ln_mdns_free(m);
	m = ln_mdns_new();
	CHECK_INT(ln_mdns_feed(m, p, sizeof(p)), 3);
	CHECK_INT(ln_mdns_services(m, NULL, s, 4), 0);
	CHECK_INT(ln_mdns_addrs(m, "nas.local", a, 2), 1);
	ln_mdns_free(m);
}

/* ---- live: tests/servers/mdns/responder.py ---- */
static pid_t rpid;
static FILE *rlog;

static int start_responder(const char *extra)
{
	int fd[2], port = 0;
	char line[64];
	if (system("python3 -c '' 2>/dev/null") != 0) return 0;
	if (pipe(fd)) return 0;
	rpid = fork();
	if (rpid == 0) {
		dup2(fd[1], 1);
		close(fd[0]);
		execlp("python3", "python3", "tests/servers/mdns/responder.py", "--addr", "127.0.0.2", extra, (char *)NULL);
		_exit(127);
	}
	close(fd[1]);
	rlog = fdopen(fd[0], "r");
	if (rlog && fgets(line, sizeof(line), rlog) && !strncmp(line, "ready ", 6))
		port = atoi(line + 6);
	/* its query log stays in the pipe (a few lines) */
	return port;
}

static void stop_responder(void)
{
	if (rpid > 0) {
		kill(rpid, SIGTERM);
		waitpid(rpid, NULL, 0);
		rpid = 0;
	}
	if (rlog) {
		fclose(rlog);
		rlog = NULL;
	}
}

static int live(const char *extra)
{
	LnAddr srv, a[4];
	LnService s[8];
	char buf[64];
	int port = start_responder(extra), n;
	u32 t0;
	if (!port) { stop_responder(); return 0; }
	memset(&srv, 0, sizeof(srv));
	srv.family = 4; srv.a[0] = 127; srv.a[3] = 1; srv.port = (u16)port;
	ln_mdns_set_server(&srv);
	t0 = ln_ms();
	n = ln_mdns_browse(NULL, 2500, s, 8);
	CHECK_INT(n, 3);
	CHECK((int)(ln_ms() - t0) < 4000);
	if (n == 3) {
		/* sorted by type: _afpovertcp, _nfs, _smb */
		CHECK_STR(s[0].scheme, "afp"); CHECK_STR(s[0].instance, "Lagoon Test AFP"); CHECK_INT(s[0].port, 548);
		CHECK_STR(s[1].scheme, "nfs"); CHECK_INT(s[1].port, 2049);
		CHECK(ln_mdns_txt(&s[1], "path", buf, sizeof(buf)) && !strcmp(buf, "/srv/lagoon"));
		CHECK_STR(s[2].scheme, "smb"); CHECK_STR(s[2].host, "lagoontest.local");
		CHECK_INT(s[2].addr.family, 4); CHECK_HEX(s[2].addr.a, 4, "7f000002");
	}
	t0 = ln_ms();
	CHECK_INT(ln_mdns_resolve("lagoontest.local.", a, 4), 1);
	CHECK_HEX(a[0].a, 4, "7f000002");
	CHECK((int)(ln_ms() - t0) < 1000);
	CHECK_INT(ln_mdns_resolve("nothere.local", a, 4), LN_ENOHOST);
	ln_mdns_set_server(NULL);
	stop_responder();
	return 1;
}

int main(void)
{
	queries();
	canned_packets();
	if (ln_net_init() == LN_OK) {
		if (!live("--count=0") || !live("--no-additional"))
			printf("t_mdns: live part skipped (no python3)\n");
	}
	T_DONE("t_mdns");
}
