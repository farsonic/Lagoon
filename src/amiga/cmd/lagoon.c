/*
 * Lagoon - C:Lagoon, the command-line tool: mount, unmount, list and test
 * network shares (see docs/lagoon-command.md).
 *
 *   Lagoon MOUNT <name|URL> [AS <device>] [USER u] [PASSWORD p] [DOMAIN d]
 *                [READONLY] [VOLUME label]
 *   Lagoon UNMOUNT <device>
 *   Lagoon LIST
 *   Lagoon MOUNTALL [WAIT seconds]
 *   Lagoon STATUS [device]
 *   Lagoon SHARES <URL> [USER u] [PASSWORD p] [DOMAIN d]
 *   Lagoon TEST <name|URL> [USER u] [PASSWORD p] [DOMAIN d]
 *   Lagoon HELP
 *
 * Return codes: 0 ok, 5 (WARN) some shares of MOUNTALL failed, 10 (ERROR)
 * the operation failed, 20 (FAIL) bad arguments.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <exec/types.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/rdargs.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <stdarg.h>
#include "ln_vfs.h"
#include "ln_sys.h"
#include "ln_net.h"
#include "ln_conf.h"
#include "mount.h"

static const char version[] = "$VER: Lagoon 0.1 (30.10.2026)";

#define TEMPLATE "COMMAND/A,NAME,AS/K,USER/K,PASSWORD/K,DOMAIN/K,READONLY/S,VOLUME/K,WAIT/K/N"
enum { A_CMD, A_NAME, A_AS, A_USER, A_PASS, A_DOMAIN, A_RO, A_VOLUME, A_WAIT, A_COUNT };

static const char help[] =
	"Lagoon - network shares (SMB, AFP, NFS) as AmigaDOS volumes\n"
	"\n"
	"  Lagoon MOUNT <name|URL> [AS <device>] [USER u] [PASSWORD p] [DOMAIN d]\n"
	"               [READONLY] [VOLUME label]\n"
	"      mount a share from ENV:Lagoon/lagoon.conf, or a URL such as\n"
	"      smb://server/share, afp://mac/Volume, nfs://host/export\n"
	"  Lagoon UNMOUNT <device>      unmount (fails while files are open)\n"
	"  Lagoon LIST                  configured shares and where they are mounted\n"
	"  Lagoon MOUNTALL [WAIT secs]  mount the shares marked automount; WAIT\n"
	"                               retries until the network is up\n"
	"  Lagoon STATUS [device]       mounted shares, server, traffic\n"
	"  Lagoon SHARES <URL>          list the shares a server offers\n"
	"  Lagoon TEST <name|URL>       connect, log on and read the root, no mount\n";

int ln_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);

static void out(const char *fmt, ...)
{
	char b[512];
	va_list ap;
	va_start(ap, fmt);
	ln_vsnprintf(b, sizeof(b), fmt, ap);
	va_end(ap);
	PutStr((STRPTR)b);
}

static void size_str(u64 v, char *b, size_t n)
{
	static const char *const u[] = { "bytes", "KB", "MB", "GB", "TB" };
	int i = 0;
	u64 frac = 0;
	while (v >= 1024 * 10 && i < 4) {
		frac = (v % 1024) * 10 / 1024;
		v /= 1024;
		i++;
	}
	if (i)
		ln_snprintf(b, n, "%lu.%lu %s", (unsigned long)v, (unsigned long)frac, u[i]);
	else
		ln_snprintf(b, n, "%lu %s", (unsigned long)v, u[0]);
}

/* remove "user:pass@" from a URL (they go into the share's fields) */
static void strip_userinfo(const char *url, char *o, size_t n)
{
	const char *s = strstr(url, "://"), *at, *slash;
	if (!s) {
		ln_strlcpy(o, url, n);
		return;
	}
	s += 3;
	slash = strchr(s, '/');
	at = s;
	{
		const char *t, *last = NULL;
		for (t = s; *t && (!slash || t < slash); t++)
			if (*t == '@')
				last = t;
		at = last;
	}
	if (!at) {
		ln_strlcpy(o, url, n);
		return;
	}
	{
		size_t k = (size_t)(s - url);
		if (k >= n)
			k = n - 1;
		memcpy(o, url, k);
		o[k] = 0;
		ln_strlcat(o, at + 1, n);
	}
}

/* the share for MOUNT/TEST: named from the config, or an ad-hoc URL,
 * with the command line overrides; LN_OK or prints why not */
static int get_share(LnConf *c, LONG *args, LnShare *sh)
{
	const char *name = (const char *)args[A_NAME];
	if (!name) {
		out("Lagoon: share name or URL missing\n");
		return LN_EINVAL;
	}
	memset(sh, 0, sizeof(*sh));
	if (strstr(name, "://")) {
		LnUrl *u = ln_alloc(sizeof(LnUrl));
		if (!u)
			return LN_ENOMEM;
		if (ln_url_parse(name, u) != LN_OK || !ln_vfs_find(u->scheme)) {
			out("Lagoon: bad URL \"%s\"\n", name);
			ln_free(u);
			return LN_EINVAL;
		}
		strip_userinfo(name, sh->url, sizeof(sh->url));
		ln_strlcpy(sh->user, u->user, sizeof(sh->user));
		ln_strlcpy(sh->password, u->password, sizeof(sh->password));
		ln_strlcpy(sh->domain, u->domain, sizeof(sh->domain));
		ln_strlcpy(sh->volume, u->share[0] == '/' ? ln_path_base(u->share) : u->share, sizeof(sh->volume));
		ln_wipe(u, sizeof(*u));
		ln_free(u);
	} else {
		LnShare *s = ln_conf_find(c, name);
		if (!s) {
			out("Lagoon: no share \"%s\" in ENV:Lagoon/lagoon.conf\n", name);
			return LN_ENOSHARE;
		}
		*sh = *s;
	}
	if (args[A_USER])
		ln_strlcpy(sh->user, (const char *)args[A_USER], sizeof(sh->user));
	if (args[A_PASS])
		ln_strlcpy(sh->password, (const char *)args[A_PASS], sizeof(sh->password));
	if (args[A_DOMAIN])
		ln_strlcpy(sh->domain, (const char *)args[A_DOMAIN], sizeof(sh->domain));
	if (args[A_RO])
		sh->readonly = 1;
	if (args[A_VOLUME])
		ln_strlcpy(sh->volume, (const char *)args[A_VOLUME], sizeof(sh->volume));
	return LN_OK;
}

static int cmd_mount(LnConf *c, LONG *args)
{
	LnShare *sh = ln_alloc(sizeof(LnShare));
	char dev[40], err[160];
	int r;
	if (!sh)
		return RETURN_FAIL;
	if (get_share(c, args, sh) != LN_OK) {
		ln_free(sh);
		return RETURN_ERROR;
	}
	r = ln_amiga_mount(sh, (const char *)args[A_AS], dev, sizeof(dev), err, sizeof(err));
	if (r != LN_OK)
		out("Lagoon: cannot mount %s: %s\n", (const char *)args[A_NAME], err[0] ? err : ln_strerror(r));
	else
		out("Mounted %s as %s:\n", sh->name[0] ? sh->name : sh->url, dev);
	ln_wipe(sh, sizeof(*sh));
	ln_free(sh);
	return r == LN_OK ? RETURN_OK : RETURN_ERROR;
}

static int cmd_unmount(LONG *args)
{
	char err[160];
	int r;
	if (!args[A_NAME]) {
		out("Lagoon: which device? (Lagoon UNMOUNT NAS:)\n");
		return RETURN_FAIL;
	}
	r = ln_amiga_unmount((const char *)args[A_NAME], err, sizeof(err));
	if (r != LN_OK) {
		out("Lagoon: cannot unmount %s: %s\n", (const char *)args[A_NAME], err[0] ? err : ln_strerror(r));
		return RETURN_ERROR;
	}
	out("Unmounted %s\n", (const char *)args[A_NAME]);
	return RETURN_OK;
}

typedef struct ListCtx { LnConf *c; int n; } ListCtx;

static void list_adhoc(void *ud, const char *device, const LnMountInfo *mi)
{
	ListCtx *x = ud;
	const char *nm = mi ? mi->share.name : "";
	if (!nm[0] || !ln_conf_find(x->c, nm)) {
		if (!x->n++)
			out("\nOther Lagoon devices:\n");
		out("  %-12s %s\n", device, mi ? mi->share.url : "(from a DOSDriver)");
	}
}

static int cmd_list(LnConf *c)
{
	int i;
	ListCtx x;
	if (!c->nshares)
		out("No shares configured (ENV:Lagoon/lagoon.conf). Use LagoonPrefs or Lagoon MOUNT <URL>.\n");
	else
		out("%-12s %-8s %-12s %s\n", "Share", "Flags", "Mounted", "URL");
	for (i = 0; i < c->nshares; i++) {
		const LnShare *s = &c->share[i];
		char dev[40], flags[16], mnt[44];
		flags[0] = 0;
		if (s->automount)
			ln_strlcat(flags, "auto ", sizeof(flags));
		if (s->readonly)
			ln_strlcat(flags, "ro", sizeof(flags));
		if (ln_amiga_find_mount(s->name, dev, sizeof(dev)))
			ln_snprintf(mnt, sizeof(mnt), "%s:", dev);
		else
			ln_strlcpy(mnt, "-", sizeof(mnt));
		out("%-12s %-8s %-12s %s\n", s->name, flags, mnt, s->url);
	}
	x.c = c;
	x.n = 0;
	ln_amiga_list_mounts(list_adhoc, &x);
	return RETURN_OK;
}

static int net_error(int r)
{
	return r == LN_ENONET || r == LN_EHOSTUNREACH || r == LN_ETIMEDOUT || r == LN_ECONNREFUSED ||
	       r == LN_ENOHOST || r == LN_ECONNRESET;
}

static int cmd_mountall(LnConf *c, LONG *args)
{
	LONG wait = args[A_WAIT] ? *(LONG *)args[A_WAIT] : 0;
	u32 start = ln_ms();
	int i, failed = 0, todo = 0;
	char *done = ln_alloc(LN_CONF_MAX_SHARES);
	if (!done)
		return RETURN_FAIL;
	for (i = 0; i < c->nshares; i++)
		if (c->share[i].automount)
			todo++;
	if (!todo) {
		out("Lagoon: no shares are marked automount\n");
		ln_free(done);
		return RETURN_OK;
	}
	/* WAIT: first the TCP/IP stack */
	for (;;) {
		struct Library *sb = OpenLibrary((STRPTR)"bsdsocket.library", 4);
		if (sb) {
			CloseLibrary(sb);
			break;
		}
		if ((u32)(ln_ms() - start) >= (u32)wait * 1000UL) {
			out("Lagoon: %s\n", ln_strerror(LN_ENONET));
			ln_free(done);
			return RETURN_ERROR;
		}
		if (CheckSignal(SIGBREAKF_CTRL_C)) {
			ln_free(done);
			return RETURN_WARN;
		}
		Delay(50);
	}
	for (;;) {
		int pending = 0;
		for (i = 0; i < c->nshares; i++) {
			LnShare *s = &c->share[i];
			char dev[40], err[160];
			int r;
			if (!s->automount || done[i])
				continue;
			if (ln_amiga_find_mount(s->name, dev, sizeof(dev))) {
				done[i] = 1;
				continue;
			}
			r = ln_amiga_mount(s, NULL, dev, sizeof(dev), err, sizeof(err));
			if (r == LN_OK) {
				out("Mounted %s as %s:\n", s->name, dev);
				done[i] = 1;
			} else if (net_error(r) && (u32)(ln_ms() - start) < (u32)wait * 1000UL) {
				pending++;
			} else {
				out("Lagoon: cannot mount %s: %s\n", s->name, err[0] ? err : ln_strerror(r));
				done[i] = 2;
				failed++;
			}
		}
		if (!pending || CheckSignal(SIGBREAKF_CTRL_C))
			break;
		Delay(100);
	}
	for (i = 0; i < c->nshares; i++)
		if (c->share[i].automount && !done[i]) {
			out("Lagoon: cannot mount %s: server not reachable\n", c->share[i].name);
			failed++;
		}
	ln_free(done);
	return failed ? (failed == todo ? RETURN_ERROR : RETURN_WARN) : RETURN_OK;
}

static int status_one(const char *device)
{
	LnStatus *st = ln_alloc(sizeof(LnStatus));
	char r1[32], w1[32];
	int r;
	if (!st)
		return RETURN_FAIL;
	r = ln_amiga_status(device, st);
	if (r == LN_ENOSHARE)
		out("%s: not started (DOS starts the handler on first use)\n", device);
	else if (r != LN_OK)
		out("%s: %s\n", device, r == LN_ENOENT ? "no such device" : ln_strerror(r));
	else {
		size_str(st->bytes_read, r1, sizeof(r1));
		size_str(st->bytes_written, w1, sizeof(w1));
		out("%s: volume %s: %s%s\n", st->device, st->volume, st->online ? "online" : "OFFLINE (server unreachable)",
		    st->readonly ? ", read-only" : "");
		out("  share %s  %s\n", st->share[0] ? st->share : "(ad hoc)", st->url);
		out("  backend %s\n", st->backend);
		out("  %lu locks, %lu open files, %lu reconnects, read %s, written %s\n", (unsigned long)st->locks,
		    (unsigned long)st->files, (unsigned long)st->reconnects, r1, w1);
	}
	ln_free(st);
	return r == LN_OK || r == LN_ENOSHARE ? RETURN_OK : RETURN_ERROR;
}

typedef struct StCtx { int n, rc; } StCtx;

static void status_cb(void *ud, const char *device, const LnMountInfo *mi)
{
	StCtx *x = ud;
	int r;
	(void)mi;
	x->n++;
	r = status_one(device);
	if (r > x->rc)
		x->rc = r;
}

static int cmd_status(LONG *args)
{
	StCtx x;
	if (args[A_NAME])
		return status_one((const char *)args[A_NAME]);
	x.n = 0;
	x.rc = 0;
	ln_amiga_list_mounts(status_cb, &x);
	if (!x.n)
		out("No Lagoon devices mounted\n");
	return x.rc;
}

static void share_cb(void *ud, const char *name, const char *comment)
{
	int *n = ud;
	(*n)++;
	out("  %-24s %s\n", name, comment ? comment : "");
}

static int cmd_shares(LONG *args)
{
	LnUrl *u = ln_alloc(sizeof(LnUrl));
	LnCreds *cr = ln_alloc(sizeof(LnCreds));
	const LnOps *ops;
	int r, n = 0;
	if (!u || !cr) {
		ln_free(u);
		ln_free(cr);
		return RETURN_FAIL;
	}
	if (!args[A_NAME] || ln_url_parse((const char *)args[A_NAME], u) != LN_OK || !(ops = ln_vfs_find(u->scheme))) {
		out("Lagoon: SHARES needs a URL such as smb://server\n");
		ln_free(u);
		ln_free(cr);
		return RETURN_FAIL;
	}
	ln_strlcpy(cr->user, args[A_USER] ? (const char *)args[A_USER] : u->user, sizeof(cr->user));
	ln_strlcpy(cr->password, args[A_PASS] ? (const char *)args[A_PASS] : u->password, sizeof(cr->password));
	ln_strlcpy(cr->domain, args[A_DOMAIN] ? (const char *)args[A_DOMAIN] : u->domain, sizeof(cr->domain));
	if (!ops->list_shares)
		r = LN_ENOTSUP;
	else if ((r = ln_net_init()) == LN_OK)
		r = ops->list_shares(u, cr, share_cb, &n);
	if (r != LN_OK)
		out("Lagoon: cannot list shares on %s: %s\n", u->host, ln_strerror(r));
	else if (!n)
		out("No shares found on %s\n", u->host);
	ln_wipe(cr, sizeof(*cr));
	ln_wipe(u, sizeof(*u));
	ln_free(u);
	ln_free(cr);
	return r == LN_OK ? RETURN_OK : RETURN_ERROR;
}

static int cmd_test(LnConf *c, LONG *args)
{
	LnShare *sh = ln_alloc(sizeof(LnShare));
	LnCreds *cr = ln_alloc(sizeof(LnCreds));
	const LnOps *ops;
	LnFs *fs;
	int r, n = 0;
	if (!sh || !cr) {
		ln_free(sh);
		ln_free(cr);
		return RETURN_FAIL;
	}
	r = get_share(c, args, sh);
	if (r == LN_OK) {
		ln_strlcpy(cr->user, sh->user, sizeof(cr->user));
		ln_strlcpy(cr->password, sh->password, sizeof(cr->password));
		ln_strlcpy(cr->domain, sh->domain, sizeof(cr->domain));
		out("Connecting to %s ...\n", sh->url);
		r = ln_net_init();
		if (r == LN_OK)
			r = ln_vfs_mount_url(sh->url, cr, &ops, &fs);
		if (r != LN_OK)
			out("Lagoon: %s: %s\n", sh->url, ln_strerror(r));
		else {
			LnStatFs sf;
			LnDir *d;
			out("Connected (%s)\n", ops->name);
			if ((r = ops->statfs(fs, &sf)) == LN_OK) {
				char t[32], f[32];
				size_str(sf.total_bytes, t, sizeof(t));
				size_str(sf.free_bytes, f, sizeof(f));
				out("  %s free of %s%s\n", f, t, sf.readonly ? ", read-only" : "");
			}
			if (r == LN_OK && (r = ops->opendir(fs, "", &d)) == LN_OK) {
				char *nm = ln_alloc(1024);
				LnStat *st = ln_alloc(sizeof(LnStat));
				while (nm && st && ops->readdir(d, nm, 1024, st) > 0)
					n++;
				ops->closedir(d);
				ln_free(nm);
				ln_free(st);
				out("  %d entries in the root directory\n", n);
			}
			if (r != LN_OK)
				out("Lagoon: %s\n", ln_strerror(r));
			else
				out("Test OK\n");
			ops->unmount(fs);
		}
	}
	ln_wipe(cr, sizeof(*cr));
	ln_wipe(sh, sizeof(*sh));
	ln_free(sh);
	ln_free(cr);
	return r == LN_OK ? RETURN_OK : RETURN_ERROR;
}

int main(void)
{
	LONG args[A_COUNT];
	struct RDArgs *rd;
	LnConf *c;
	const char *cmd;
	int rc;
	(void)version;
	memset(args, 0, sizeof(args));
	rd = ReadArgs((STRPTR)TEMPLATE, args, NULL);
	if (!rd) {
		PrintFault(IoErr(), (STRPTR)"Lagoon");
		PutStr((STRPTR)help);
		return RETURN_FAIL;
	}
	cmd = (const char *)args[A_CMD];
	c = ln_alloc(sizeof(LnConf));
	if (!c) {
		FreeArgs(rd);
		return RETURN_FAIL;
	}
	if (ln_amiga_load_conf(c) != LN_OK)
		out("Lagoon: warning: ENV:Lagoon/lagoon.conf has errors\n");
	if (c->loglevel > 0)
		ln_log_level = c->loglevel;
	if (!ln_strcasecmp(cmd, "MOUNT"))
		rc = cmd_mount(c, args);
	else if (!ln_strcasecmp(cmd, "UNMOUNT") || !ln_strcasecmp(cmd, "UMOUNT"))
		rc = cmd_unmount(args);
	else if (!ln_strcasecmp(cmd, "LIST"))
		rc = cmd_list(c);
	else if (!ln_strcasecmp(cmd, "MOUNTALL"))
		rc = cmd_mountall(c, args);
	else if (!ln_strcasecmp(cmd, "STATUS"))
		rc = cmd_status(args);
	else if (!ln_strcasecmp(cmd, "SHARES"))
		rc = cmd_shares(args);
	else if (!ln_strcasecmp(cmd, "TEST"))
		rc = cmd_test(c, args);
	else if (!ln_strcasecmp(cmd, "HELP")) {
		PutStr((STRPTR)help);
		rc = RETURN_OK;
	} else {
		out("Lagoon: unknown command \"%s\"\n\n", cmd);
		PutStr((STRPTR)help);
		rc = RETURN_FAIL;
	}
	ln_net_exit();
	ln_wipe(c, sizeof(*c));
	ln_free(c);
	FreeArgs(rd);
	return rc;
}
