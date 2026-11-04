/* Lagoon - NetBIOS name service tests: name encoding, requests, canned
 * responses, and a live discover/resolve against a private Samba nmbd
 * (tests/servers/netbios/nmbd.sh; skipped without root or nmbd).
 * SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "testutil.h"
#include "ln_netbios.h"
#include "ln_net.h"
#include "ln_sys.h"
#include <stdlib.h>
#include <stdio.h>

static void encoding(void)
{
	u8 e[34], b[64];
	char nm[16];
	u8 suf = 0;
	ln_nb_encode("fred", 0x20, e);
	CHECK_INT(e[0], 32);
	CHECK(!memcmp(e + 1, "EGFCEFEECACACACACACACACACACACACA", 32));
	CHECK_INT(e[33], 0);
	CHECK_INT(ln_nb_decode(e + 1, nm, &suf), 0);
	CHECK_STR(nm, "FRED"); CHECK_INT(suf, 0x20);
	ln_nb_encode("*", 0, e);
	CHECK(!memcmp(e + 1, "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32));
	e[5] = 'Z';
	CHECK_INT(ln_nb_decode(e + 1, nm, &suf), LN_EPROTO);
	ln_nb_encode("AVERYLONGNAMEXXXXX", 0, e);           /* cut at 15 */
	ln_nb_decode(e + 1, nm, &suf); CHECK_STR(nm, "AVERYLONGNAMEXX");

	CHECK_INT(ln_nb_build_query(b, sizeof(b), 0x1234, "nas", 0x20, 1), 50);
	CHECK_HEX(b, 12, "123401100001000000000000");
	CHECK_HEX(b + 46, 4, "00200001");
	CHECK_INT(ln_nb_build_query(b, sizeof(b), 0x1234, "nas", 0x20, 0), 50);
	CHECK_HEX(b + 2, 2, "0100");
	CHECK_INT(ln_nb_build_status(b, sizeof(b), 7), 50);
	CHECK_HEX(b, 4, "00070000");
	CHECK_HEX(b + 46, 4, "00210001");
	CHECK_INT(ln_nb_build_status(b, 20, 7), LN_ENOSPC);
}

static size_t answer_hdr(u8 *p, u16 id, u16 flags, const char *name, u8 suf, u16 type, u16 rdlen)
{
	memset(p, 0, 12);
	ln_put_be16(p, id);
	ln_put_be16(p + 2, flags);
	ln_put_be16(p + 6, 1);
	ln_nb_encode(name, suf, p + 12);
	ln_put_be16(p + 46, type);
	ln_put_be16(p + 48, 1);
	ln_put_be32(p + 50, 300000);
	ln_put_be16(p + 54, rdlen);
	return 56;
}

static void put_entry(u8 *p, const char *name, u8 suf, u16 fl)
{
	memset(p, ' ', 15);
	memcpy(p, name, strlen(name));
	p[15] = suf;
	ln_put_be16(p + 16, fl);
}

static void canned(void)
{
	u8 p[300];
	LnAddr a[4];
	LnNbHost h;
	size_t o;
	/* positive name query response, two addresses */
	o = answer_hdr(p, 0x4242, 0x8500, "LAGOONNB", 0, 0x20, 12);
	ln_put_be16(p + o, 0); p[o + 2] = 192; p[o + 3] = 168; p[o + 4] = 99; p[o + 5] = 1;
	ln_put_be16(p + o + 6, 0x6000); p[o + 8] = 10; p[o + 9] = 0; p[o + 10] = 0; p[o + 11] = 7;
	o += 12;
	CHECK_INT(ln_nb_parse_query(p, o, 0x4242, a, 4), 2);
	CHECK_HEX(a[0].a, 4, "c0a86301"); CHECK_HEX(a[1].a, 4, "0a000007"); CHECK_INT(a[0].family, 4);
	CHECK_INT(ln_nb_parse_query(p, o, 0x4243, a, 4), 0);      /* other transaction */
	CHECK_INT(ln_nb_parse_query(p, o, 0x4242, a, 1), 1);
	CHECK_INT(ln_nb_parse_query(p, 40, 0x4242, a, 4), LN_EPROTO);
	p[3] = 0x03;                                               /* rcode 3: negative */
	CHECK_INT(ln_nb_parse_query(p, o, 0x4242, a, 4), 0);
	p[3] = 0;
	CHECK(ln_nb_parse_status(p, o, &h) != LN_OK);              /* not a status reply */

	/* node status response */
	o = answer_hdr(p, 0x0007, 0x8400, "*", 0, 0x21, 1 + 4 * 18 + 46);
	p[o++] = 4;
	put_entry(p + o, "LAGOONNB", 0x00, 0x0400); o += 18;
	put_entry(p + o, "LAGOONNB", 0x03, 0x0400); o += 18;
	put_entry(p + o, "LAGOONWG", 0x00, 0x8400); o += 18;
	put_entry(p + o, "LAGOONNB", 0x20, 0x0400); o += 18;
	memset(p + o, 0, 46); o += 46;
	memset(&h, 0, sizeof(h));
	CHECK_INT(ln_nb_parse_status(p, o, &h), LN_OK);
	CHECK_STR(h.name, "LAGOONNB"); CHECK_STR(h.group, "LAGOONWG"); CHECK_INT(h.server, 1);
	p[56] = 20;                                                /* too many names */
	CHECK_INT(ln_nb_parse_status(p, o, &h), LN_EPROTO);
	/* a workstation without the server service */
	o = answer_hdr(p, 0x0007, 0x8400, "*", 0, 0x21, 1 + 18);
	p[o++] = 1;
	put_entry(p + o, "PC1", 0x00, 0x0400); o += 18;
	CHECK_INT(ln_nb_parse_status(p, o, &h), LN_OK);
	CHECK_STR(h.name, "PC1"); CHECK_STR(h.group, ""); CHECK_INT(h.server, 0);
}

static void live(void)
{
	char dir[] = "/tmp/lagoon-nb.XXXXXX", cmd[256];
	LnAddr t, a[4];
	LnNbHost h[8];
	int r, n, i, found = 0;
	if (!mkdtemp(dir)) return;
	ln_snprintf(cmd, sizeof(cmd), "tests/servers/netbios/nmbd.sh start %s >/dev/null 2>&1", dir);
	r = system(cmd);
	if (r != 0) {
		printf("t_netbios: live part skipped (nmbd.sh start: %d)\n", r);
		ln_snprintf(cmd, sizeof(cmd), "tests/servers/netbios/nmbd.sh stop %s", dir);
		if (system(cmd)) {}
		return;
	}
	memset(&t, 0, sizeof(t));
	t.family = 4; t.a[0] = 192; t.a[1] = 168; t.a[2] = 99; t.a[3] = 255; t.port = LN_NB_PORT;
	ln_nb_set_target(&t);                 /* the veth's subnet broadcast */
	n = ln_nb_discover(1500, h, 8);
	CHECK(n >= 1);
	for (i = 0; i < n; i++)
		if (!strcmp(h[i].name, "LAGOONNB")) {
			found = 1;
			CHECK_STR(h[i].group, "LAGOONWG");
			CHECK_INT(h[i].server, 1);
			CHECK_HEX(h[i].addr.a, 4, "c0a86301");
		}
	CHECK(found);
	CHECK_INT(ln_nb_resolve("lagoonnb", a, 4), 1);
	CHECK_HEX(a[0].a, 4, "c0a86301");
	CHECK_INT(ln_nb_resolve("NOSUCHHOST", a, 4), LN_ENOHOST);
	CHECK_INT(ln_nb_resolve("", a, 4), LN_EINVAL);
	ln_nb_set_target(NULL);
	ln_snprintf(cmd, sizeof(cmd), "tests/servers/netbios/nmbd.sh stop %s", dir);
	if (system(cmd)) {}
}

int main(void)
{
	encoding();
	canned();
	if (ln_net_init() == LN_OK)
		live();
	T_DONE("t_netbios");
}
