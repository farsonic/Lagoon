/*
 * Lagoon - C:Lagoon SERVE, SHARE and USER: share Amiga folders over SMB
 * (the server core is src/core/srv, folders come from src/amiga/fs_dos.c).
 *
 *   Lagoon SHARE                         list shared folders, users, server state
 *   Lagoon SHARE Work PATH Work: [READONLY] [GUEST] [USERS "bob alice"] [COMMENT c]
 *   Lagoon SHARE Work [READWRITE|READONLY] [GUEST|NOGUEST] ...   change one
 *   Lagoon SHARE Work DELETE
 *   Lagoon USER                          list users
 *   Lagoon USER bob PASSWORD secret      add a user / set the password
 *   Lagoon USER bob DELETE
 *   Lagoon SERVE [WAIT s] [LOG file] [PORT n] [AS name] [DOMAIN workgroup]
 *                                        run the server until Ctrl-C (AS and
 *                                        DOMAIN override the saved names)
 *   Lagoon SERVE AUTO ...                the same, if "Start at boot" is set
 *   Lagoon SERVE STOP | RELOAD           stop / reload the running server
 *
 * SHARE and USER write ENV: and ENVARC:Lagoon/lagoon.conf and tell a
 * running server to reload (Ctrl-F). The server process is named
 * "Lagoon server" (LN_SERVER_TASK) so STOP and LagoonPrefs can find it;
 * `Run >NIL: Lagoon SERVE` puts it in the background.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <exec/types.h>
#include <exec/tasks.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "ln_srv.h"
#include "ln_sys.h"
#include "ln_net.h"
#include "ln_conf.h"
#include "mount.h"
#include "fs_dos.h"
#include "cmd.h"

#define out lagoon_out

extern const char *ln_log_file;       /* sys_amiga.c */

static int save(LnConf *c)
{
	int r = ln_amiga_save_conf(c, 1);
	if (r != LN_OK) {
		out("Lagoon: cannot write ENVARC:Lagoon/lagoon.conf: %s\n", ln_strerror(r));
		return RETURN_ERROR;
	}
	if (ln_amiga_server_signal(SIGBREAKF_CTRL_F))
		out("The running server takes the change now.\n");
	return RETURN_OK;
}

static int good_name(const char *n)
{
	size_t l = strlen(n);
	if (!l || l > 31)
		return 0;
	for (; *n; n++)
		if (*n == '\\' || *n == '/' || *n == ':' || *n == '"' || *n == '*' || *n == '?' || (u8)*n < 32 ||
		    *n == '<' || *n == '>' || *n == '|' || *n == '[' || *n == ']' || *n == ';' || *n == '=' || *n == ',' || *n == '+')
			return 0;
	return 1;
}

static int is_dir(const char *path)
{
	struct Process *me = (struct Process *)FindTask(NULL);
	APTR win = me->pr_WindowPtr;
	BPTR l;
	struct FileInfoBlock *fib;
	int r = 0;
	me->pr_WindowPtr = (APTR)-1;
	l = Lock((STRPTR)path, SHARED_LOCK);
	me->pr_WindowPtr = win;
	if (!l)
		return 0;
	fib = AllocDosObject(DOS_FIB, NULL);
	if (fib && Examine(l, fib))
		r = fib->fib_DirEntryType > 0;
	if (fib)
		FreeDosObject(DOS_FIB, fib);
	UnLock(l);
	return r;
}

static void list(LnConf *c)
{
	int i;
	const char *nm = c->server.name[0] ? c->server.name : ln_hostname();
	out("SMB server \"%s\" (workgroup %s): %s%s\n", nm, c->server.workgroup[0] ? c->server.workgroup : "WORKGROUP",
	    ln_amiga_server_running() ? "running" : "not running",
	    c->server.autostart ? ", starts at boot" : "");
	if (!c->nexports)
		out("No shared folders. Lagoon SHARE <name> PATH <folder> [GUEST] shares one.\n");
	else
		out("%-16s %-24s %s\n", "Share", "Folder", "Access");
	for (i = 0; i < c->nexports; i++) {
		const LnExport *e = &c->export_[i];
		char acc[200];
		ln_snprintf(acc, sizeof(acc), "%s%s%s%s", e->readonly ? "read-only" : "read/write",
		            e->guest ? ", guests" : "", e->users[0] ? ", users " : !e->guest ? ", every user" : "",
		            e->users);
		out("%-16s %-24s %s\n", e->name, e->path, acc);
	}
	if (c->nusers) {
		out("Users:");
		for (i = 0; i < c->nusers; i++)
			out(" %s", c->user[i].name);
		out("\n");
	}
}

int cmd_share(LnConf *c, LONG *args)
{
	const char *name = (const char *)args[A_NAME];
	LnExport e, *old;
	if (!name) {
		list(c);
		return RETURN_OK;
	}
	old = ln_conf_find_export(c, name);
	if (args[A_DELETE]) {
		if (ln_conf_remove_export(c, name) != LN_OK) {
			out("Lagoon: no shared folder \"%s\"\n", name);
			return RETURN_WARN;
		}
		out("\"%s\" is no longer shared.\n", name);
		return save(c);
	}
	if (!good_name(name)) {
		out("Lagoon: \"%s\" cannot be a share name (1 to 31 characters, no \\ / : * ? \" < > | [ ] ; = , +)\n", name);
		return RETURN_FAIL;
	}
	if (old)
		e = *old;
	else {
		memset(&e, 0, sizeof(e));
		if (!args[A_PATH]) {
			out("Lagoon: which folder? (Lagoon SHARE %s PATH Work:)\n", name);
			return RETURN_FAIL;
		}
	}
	ln_strlcpy(e.name, name, sizeof(e.name));
	if (args[A_PATH]) {
		const char *p = (const char *)args[A_PATH];
		if (!is_dir(p)) {
			out("Lagoon: \"%s\" is not a folder\n", p);
			return RETURN_ERROR;
		}
		ln_strlcpy(e.path, p, sizeof(e.path));
	}
	if (args[A_RO]) e.readonly = 1;
	if (args[A_RW]) e.readonly = 0;
	if (args[A_GUEST]) e.guest = 1;
	if (args[A_NOGUEST]) e.guest = 0;
	if (args[A_USERS]) ln_strlcpy(e.users, (const char *)args[A_USERS], sizeof(e.users));
	if (args[A_COMMENT]) ln_strlcpy(e.comment, (const char *)args[A_COMMENT], sizeof(e.comment));
	if (ln_conf_put_export(c, &e) != LN_OK) {
		out("Lagoon: at most %d shared folders\n", LN_CONF_MAX_EXPORTS);
		return RETURN_ERROR;
	}
	out("%s is shared as \"%s\" (%s%s).\n", e.path, e.name, e.readonly ? "read-only" : "read/write",
	    e.guest ? ", guests welcome" : ", password needed");
	if (!e.guest && !c->nusers)
		out("Nobody can connect yet: add a user (Lagoon USER <name> PASSWORD <p>) or allow GUEST.\n");
	if (!ln_amiga_server_running())
		out("Start the server with: Run >NIL: Lagoon SERVE\n");
	return save(c);
}

int cmd_user(LnConf *c, LONG *args)
{
	const char *name = (const char *)args[A_NAME];
	const char *pass = (const char *)args[A_PASS];
	int i, r;
	if (!name) {
		if (!c->nusers)
			out("No users. Lagoon USER <name> PASSWORD <password> adds one.\n");
		for (i = 0; i < c->nusers; i++)
			out("%s\n", c->user[i].name);
		return RETURN_OK;
	}
	if (args[A_DELETE]) {
		if (ln_conf_remove_user(c, name) != LN_OK) {
			out("Lagoon: no user \"%s\"\n", name);
			return RETURN_WARN;
		}
		out("User %s removed.\n", name);
		return save(c);
	}
	if (!pass || !pass[0]) {
		out("Lagoon: a password, please (Lagoon USER %s PASSWORD <password>)\n", name);
		return RETURN_FAIL;
	}
	if (!good_name(name) || strchr(name, ' ') || strchr(name, '@')) {
		out("Lagoon: \"%s\" cannot be a user name\n", name);
		return RETURN_FAIL;
	}
	r = ln_conf_put_user(c, name, pass);
	if (r != LN_OK) {
		out("Lagoon: at most %d users\n", LN_CONF_MAX_USERS);
		return RETURN_ERROR;
	}
	out("User %s can log on now (on shares without a USERS list, or with %s in it).\n", name, name);
	return save(c);
}

/* ------------------------------------------------------------ SERVE */

static int open_folder(void *ud, const char *path, int ro, const LnOps **ops, LnFs **fs)
{
	(void)ud;
	*ops = &ln_dosfs_ops;
	return ln_dosfs_open(path, ro, fs);
}

/* 1 = stop, 2 = reload */
static int poll_cb(void *ud)
{
	ULONG s = SetSignal(0, SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_F);
	(void)ud;
	if (s & SIGBREAKF_CTRL_C)
		return 1;
	if (s & SIGBREAKF_CTRL_F)
		return 2;
	return 0;
}

int cmd_serve(LnConf *c, LONG *args)
{
	const char *what = (const char *)args[A_NAME];
	LONG wait = args[A_WAIT] ? *(LONG *)args[A_WAIT] : 0;
	struct Process *me = (struct Process *)FindTask(NULL);
	char *oldname;
	APTR oldwin;
	u32 start = ln_ms();
	int r, rc = RETURN_OK;
	static char logname[128];

	if (what && !ln_strcasecmp(what, "STOP")) {
		int i;
		if (!ln_amiga_server_signal(SIGBREAKF_CTRL_C)) {
			out("Lagoon: the server is not running\n");
			return RETURN_WARN;
		}
		for (i = 0; i < 50 && ln_amiga_server_running(); i++)
			Delay(10);
		out(ln_amiga_server_running() ? "Lagoon: the server is still stopping\n" : "Server stopped.\n");
		return RETURN_OK;
	}
	if (what && !ln_strcasecmp(what, "RELOAD")) {
		if (!ln_amiga_server_signal(SIGBREAKF_CTRL_F)) {
			out("Lagoon: the server is not running\n");
			return RETURN_WARN;
		}
		return RETURN_OK;
	}
	if (what && ln_strcasecmp(what, "AUTO")) {
		out("Lagoon: SERVE takes STOP, RELOAD or AUTO, not \"%s\"\n", what);
		return RETURN_FAIL;
	}
	if (what && (!c->server.autostart || !c->nexports))
		return RETURN_OK;                   /* AUTO: sharing is not switched on */
	if (ln_amiga_server_running()) {
		out("Lagoon: the server is already running (Lagoon SERVE STOP stops it)\n");
		return RETURN_WARN;
	}
	/* WAIT: for the TCP/IP stack */
	while (ln_net_init() != LN_OK) {
		if ((u32)(ln_ms() - start) >= (u32)wait * 1000UL) {
			out("Lagoon: %s\n", ln_strerror(LN_ENONET));
			return RETURN_ERROR;
		}
		if (CheckSignal(SIGBREAKF_CTRL_C))
			return RETURN_WARN;
		Delay(50);
	}
	if (args[A_LOG])
		ln_strlcpy(logname, (const char *)args[A_LOG], sizeof(logname));
	else
		ln_strlcpy(logname, c->server.log, sizeof(logname));
	if (logname[0]) {
		ln_log_file = logname;
		if (ln_log_level < 1)
			ln_log_level = 1;
	}
	if (c->server.loglevel > ln_log_level)
		ln_log_level = c->server.loglevel;

	/* no "please insert volume" requesters from a server; findable by name */
	oldwin = me->pr_WindowPtr;
	me->pr_WindowPtr = (APTR)-1;
	oldname = me->pr_Task.tc_Node.ln_Name;
	me->pr_Task.tc_Node.ln_Name = (char *)LN_SERVER_TASK;
	SetSignal(0, SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_F);

	for (;;) {
		LnSrv *s;
		LnSrvNet net;
		int failed = 0;
		if (args[A_AS])
			ln_strlcpy(c->server.name, (const char *)args[A_AS], sizeof(c->server.name));
		if (args[A_DOMAIN])
			ln_strlcpy(c->server.workgroup, (const char *)args[A_DOMAIN], sizeof(c->server.workgroup));
		s = ln_srv_from_conf(c, open_folder, NULL, &failed);
		if (!s) {
			out("Lagoon: not enough memory for the server\n");
			rc = RETURN_FAIL;
			break;
		}
		memset(&net, 0, sizeof(net));
		net.port = (u16)(args[A_PORT] ? *(LONG *)args[A_PORT] : c->server.port ? c->server.port : 445);
		net.nbt_port = net.port == 445 ? 139 : 0;
		net.nbns_port = c->server.netbios ? 137 : 0;
		net.mdns_port = c->server.mdns ? 5353 : 0;
		out("Lagoon: sharing %d folder%s as \\\\%s on port %u%s. Ctrl-C stops, Ctrl-F reloads.\n",
		    c->nexports - failed, c->nexports - failed == 1 ? "" : "s", ln_srv_cfg(s)->name, net.port,
		    failed ? " (some folders are missing)" : "");
		r = ln_srv_serve(s, &net, poll_cb, NULL);
		ln_srv_free_all(s);
		if (r == 2) {
			if (ln_amiga_load_conf(c) != LN_OK)
				out("Lagoon: ENV:Lagoon/lagoon.conf has errors\n");
			out("Lagoon: reloaded the shared folders\n");
			continue;
		}
		if (r < 0 && r != LN_EBREAK) {
			out("Lagoon: the server stopped: %s%s\n", ln_strerror(r),
			    r == LN_EINUSE ? " (is another SMB server running on this Amiga?)" : "");
			rc = RETURN_ERROR;
		} else
			out("Lagoon: server stopped\n");
		break;
	}
	me->pr_Task.tc_Node.ln_Name = oldname;
	me->pr_WindowPtr = oldwin;
	return rc;
}
