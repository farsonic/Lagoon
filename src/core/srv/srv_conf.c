/*
 * Lagoon - SMB2 server: building a server from lagoon.conf's server,
 * export and user lines (ln_conf.h).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "srv_int.h"
#include "../ln_conf.h"

LnSrv *ln_srv_from_conf(const LnConf *c, ln_srv_open_fn open_share, void *ud, int *failed)
{
	LnSrvCfg cfg;
	LnSrv *s;
	int i;
	if (failed)
		*failed = 0;
	memset(&cfg, 0, sizeof(cfg));
	ln_strlcpy(cfg.name, c->server.name[0] ? c->server.name : ln_hostname(), sizeof(cfg.name));
	for (i = 0; cfg.name[i]; i++)
		if (cfg.name[i] == '.' || cfg.name[i] == ' ') {
			cfg.name[i] = 0;
			break;
		}
	ln_strlcpy(cfg.domain, c->server.workgroup, sizeof(cfg.domain));
	ln_strlcpy(cfg.comment, c->server.comment[0] ? c->server.comment : "Amiga (Lagoon)", sizeof(cfg.comment));
	cfg.sign_required = c->server.signing;
	s = ln_srv_new(&cfg);
	if (!s)
		return NULL;
	for (i = 0; i < c->nusers; i++)
		ln_srv_add_user(s, c->user[i].name, c->user[i].nthash);
	for (i = 0; i < c->nexports; i++) {
		const LnExport *e = &c->export_[i];
		LnSrvShare sh;
		int r;
		memset(&sh, 0, sizeof(sh));
		ln_strlcpy(sh.name, e->name, sizeof(sh.name));
		ln_strlcpy(sh.comment, e->comment, sizeof(sh.comment));
		ln_strlcpy(sh.path, e->path, sizeof(sh.path));
		ln_strlcpy(sh.users, e->users, sizeof(sh.users));
		sh.readonly = e->readonly;
		sh.guest = e->guest;
		r = open_share(ud, e->path, e->readonly, &sh.ops, &sh.fs);
		if (r == LN_OK && (r = ln_srv_add_share(s, &sh)) != LN_OK)
			sh.ops->unmount(sh.fs);
		if (r != LN_OK) {
			LN_LOG(0, "server: share \"%s\" (%s) left out: %s", e->name, e->path, ln_strerror(r));
			if (failed)
				(*failed)++;
		}
	}
	return s;
}

void ln_srv_free_all(LnSrv *s)
{
	int i;
	if (!s)
		return;
	for (i = 0; i < s->nshares; i++)
		if (s->share[i].ops && s->share[i].fs)
			s->share[i].ops->unmount(s->share[i].fs);
	ln_srv_free(s);
}
