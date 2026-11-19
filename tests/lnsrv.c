/*
 * Lagoon - lnsrv: the SMB server core on the host, sharing host
 * directories (for the end-to-end tests with smbclient/impacket, and for
 * trying the server by hand).
 *
 *   lnsrv [-p port] [-n NAME] [-v level] [-c lagoon.conf]
 *         [-s name=dir[,ro][,guest][,users=a+b]] [-u user:password]
 *         [-d max_dialect_hex] [-S (signing required)] [--nbns port] [--mdns port]
 *
 * Exports in a lagoon.conf given with -c use host directories as paths.
 * Stops on SIGTERM/SIGINT.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "ln_srv.h"
#include "ln_conf.h"
#include "ln_sys.h"
#include "../src/host/fs_posix.h"

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }
static int poll_cb(void *ud) { (void)ud; return stop ? 1 : 0; }

static int open_dir(void *ud, const char *path, int ro, const LnOps **ops, LnFs **fs)
{
	(void)ud;
	*ops = &ln_posixfs_ops;
	return ln_posixfs_open(path, ro, fs);
}

static char *slurp(const char *p)
{
	FILE *f = fopen(p, "rb");
	char *b;
	long n;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	b = calloc(1, (size_t)n + 1);
	if (b && fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); b = NULL; }
	fclose(f);
	return b;
}

int main(int argc, char **argv)
{
	LnConf *c = calloc(1, sizeof(LnConf));
	LnSrvNet net;
	LnSrv *s;
	int i, r, failed, maxd = 0, signreq = 0;
	char name[16] = "";
	if (!c) return 1;
	ln_conf_init(c);
	memset(&net, 0, sizeof(net));
	net.port = 4450;
	for (i = 1; i < argc; i++) {
		const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
		if (!strcmp(a, "-p") && v) { net.port = (u16)atoi(v); i++; }
		else if (!strcmp(a, "-n") && v) { snprintf(name, sizeof(name), "%s", v); i++; }
		else if (!strcmp(a, "-v") && v) { ln_log_level = atoi(v); i++; }
		else if (!strcmp(a, "-d") && v) { maxd = (int)strtol(v, NULL, 16); i++; }
		else if (!strcmp(a, "-S")) signreq = 1;
		else if (!strcmp(a, "--nbns") && v) { net.nbns_port = (u16)atoi(v); i++; }
		else if (!strcmp(a, "--mdns") && v) { net.mdns_port = (u16)atoi(v); i++; }
		else if (!strcmp(a, "--nbt") && v) { net.nbt_port = (u16)atoi(v); i++; }
		else if (!strcmp(a, "-c") && v) {
			char *t = slurp(v);
			int line = 0;
			if (!t || ln_conf_parse(c, t, &line) != LN_OK) {
				fprintf(stderr, "lnsrv: cannot read %s (line %d)\n", v, line);
				return 2;
			}
			free(t);
			i++;
		} else if (!strcmp(a, "-s") && v) {
			LnExport e;
			char buf[600], *eq, *opt;
			memset(&e, 0, sizeof(e));
			snprintf(buf, sizeof(buf), "%s", v);
			eq = strchr(buf, '=');
			if (!eq) { fprintf(stderr, "lnsrv: -s name=dir\n"); return 2; }
			*eq = 0;
			ln_strlcpy(e.name, buf, sizeof(e.name));
			opt = strchr(eq + 1, ',');
			if (opt) *opt++ = 0;
			ln_strlcpy(e.path, eq + 1, sizeof(e.path));
			while (opt && *opt) {
				char *nx = strchr(opt, ',');
				if (nx) *nx++ = 0;
				if (!strcmp(opt, "ro")) e.readonly = 1;
				else if (!strcmp(opt, "guest")) e.guest = 1;
				else if (!strncmp(opt, "users=", 6)) {
					char *q;
					ln_strlcpy(e.users, opt + 6, sizeof(e.users));
					for (q = e.users; *q; q++) if (*q == '+') *q = ' ';
				}
				opt = nx;
			}
			ln_conf_put_export(c, &e);
			i++;
		} else if (!strcmp(a, "-u") && v) {
			char buf[200], *colon;
			snprintf(buf, sizeof(buf), "%s", v);
			colon = strchr(buf, ':');
			if (!colon) { fprintf(stderr, "lnsrv: -u user:password\n"); return 2; }
			*colon = 0;
			ln_conf_put_user(c, buf, colon + 1);
			ln_wipe(buf, sizeof(buf));
			i++;
		} else {
			fprintf(stderr, "usage: lnsrv [-p port] [-n NAME] [-v level] [-c conf] [-s name=dir[,ro][,guest][,users=a+b]]\n"
			                "             [-u user:password] [-d max_dialect_hex] [-S] [--nbns port] [--mdns port] [--nbt port]\n");
			return 2;
		}
	}
	if (name[0]) ln_strlcpy(c->server.name, name, sizeof(c->server.name));
	if (signreq) c->server.signing = 1;
	signal(SIGTERM, on_sig);
	signal(SIGINT, on_sig);
	signal(SIGPIPE, SIG_IGN);
	s = ln_srv_from_conf(c, open_dir, NULL, &failed);
	if (!s) return 1;
	if (maxd)
		ln_srv_set_max_dialect(s, (u16)maxd);
	r = ln_srv_serve(s, &net, poll_cb, NULL);
	ln_srv_free_all(s);
	ln_wipe(c, sizeof(*c));
	free(c);
	return r == 1 || r == LN_OK ? 0 : 1;
}
