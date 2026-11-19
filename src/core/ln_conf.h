/*
 * Lagoon - the share list, ENVARC:Lagoon/lagoon.conf (copied to
 * ENV:Lagoon/ at boot). Written by LagoonPrefs, read by the Lagoon
 * command and lagoon-handler. One share per line, key="value" pairs:
 *
 *   # Lagoon shares
 *   share name="NAS" url="smb://nas.local/Public" user="bob" pass="~b64..."
 *         automount=yes readonly=no volume="Public"
 *   option loglevel=1
 *
 * (a share is one line; the wrap above is for reading). Passwords are
 * obfuscated ("~" + base64 of the password XORed with a fixed key), not
 * encrypted: the file is only as private as your Amiga.
 * Unknown keys are kept and written back.
 *
 * Sharing Amiga folders (the SMB server, `Lagoon SERVE`, src/core/srv):
 *
 *   server name="AMIGA" workgroup="WORKGROUP" comment="Amiga" signing=auto
 *          netbios=yes mdns=yes autostart=yes log="T:lagoon-server.log"
 *   export name="Work" path="Work:" readonly=no guest=yes users="bob alice"
 *   user name="bob" nthash="8846f7eaee8fb117ad06bdd830b7586c"
 *
 * An export without guest=yes needs one of the users listed (users="" =
 * any configured user). A user's nthash is MD4 of the UTF-16LE password
 * (the NT hash NTLM needs): the plain password is never stored, but the
 * hash is as good as the password to an NTLM client, so keep the file
 * private.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_CONF_H
#define LN_CONF_H

#include "ln_types.h"
#include "ln_url.h"

#define LN_CONF_MAX_SHARES 32

typedef struct LnShare {
	char name[32];           /* DOS device name without ':' (e.g. "NAS") */
	char url[LN_URL_MAX];    /* without password */
	char user[64];
	char domain[64];
	char password[128];      /* plain text in memory */
	char volume[64];         /* volume label shown on Workbench; "" = share name */
	int  automount;          /* mount at startup (Lagoon MOUNTALL) */
	int  readonly;
	char extra[256];         /* unknown key=value pairs, kept verbatim */
} LnShare;

/* ---- the SMB server: shared folders, users, settings ---- */
#define LN_CONF_MAX_EXPORTS 16
#define LN_CONF_MAX_USERS   16

typedef struct LnExport {
	char name[32];           /* share name clients see ("Work") */
	char path[256];          /* Amiga path ("Work:", "DH0:Projects") */
	char comment[64];
	int  readonly;
	int  guest;              /* guests (no password) may connect */
	char users[128];         /* user names separated by spaces or commas; "" = every user */
	char extra[128];
} LnExport;

typedef struct LnAccount {
	char name[64];
	u8   nthash[16];
	char extra[64];
} LnAccount;

typedef struct LnServerConf {
	char name[16];           /* NetBIOS / computer name, "" = from HOSTNAME */
	char workgroup[16];      /* "" = WORKGROUP */
	char comment[64];
	int  signing;            /* 0 = when the client asks, 1 = required */
	int  netbios;            /* answer NetBIOS name queries (UDP 137) */
	int  mdns;               /* announce _smb._tcp by mDNS (UDP 5353) */
	int  autostart;          /* Install_Lagoon's User-Startup line starts the server */
	int  port;               /* TCP port, 0 = 445 */
	char log[128];           /* log file, "" = none */
	int  loglevel;
	char extra[128];
} LnServerConf;

typedef struct LnConf {
	int     nshares;
	LnShare share[LN_CONF_MAX_SHARES];
	int     loglevel;
	char    extra[256];      /* unknown option pairs */
	LnServerConf server;
	int     nexports;
	LnExport export_[LN_CONF_MAX_EXPORTS];
	int     nusers;
	LnAccount user[LN_CONF_MAX_USERS];
} LnConf;

void ln_conf_init(LnConf *c);
/* parse text (NUL terminated); LN_OK or LN_EINVAL (line number in *errline) */
int  ln_conf_parse(LnConf *c, const char *text, int *errline);
/* format into buf; returns length or -1 if buf is too small */
int  ln_conf_format(const LnConf *c, char *buf, size_t n);
LnShare *ln_conf_find(LnConf *c, const char *name);   /* case-insensitive */
/* add (or replace same name); LN_ENOSPC if full */
int  ln_conf_put(LnConf *c, const LnShare *s);
int  ln_conf_remove(LnConf *c, const char *name);

/* exports and users (names case-insensitive); put replaces the same name,
 * LN_ENOSPC when full */
void ln_conf_server_defaults(LnServerConf *s);
LnExport  *ln_conf_find_export(LnConf *c, const char *name);
int        ln_conf_put_export(LnConf *c, const LnExport *e);
int        ln_conf_remove_export(LnConf *c, const char *name);
LnAccount *ln_conf_find_user(LnConf *c, const char *name);
int        ln_conf_put_user(LnConf *c, const char *name, const char *password);
int        ln_conf_remove_user(LnConf *c, const char *name);
/* is user (case-insensitive) in a users="a b,c" list? */
int        ln_conf_user_listed(const char *list, const char *user);
/* the NT hash of a password: MD4(UTF-16LE(password)) */
void       ln_nthash(const char *password, u8 out[16]);

/* password obfuscation used by the file format */
void ln_conf_hide(const char *plain, char *out, size_t n);
int  ln_conf_unhide(const char *hidden, char *out, size_t n);

#endif
