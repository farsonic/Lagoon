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

typedef struct LnConf {
	int     nshares;
	LnShare share[LN_CONF_MAX_SHARES];
	int     loglevel;
	char    extra[256];      /* unknown option pairs */
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

/* password obfuscation used by the file format */
void ln_conf_hide(const char *plain, char *out, size_t n);
int  ln_conf_unhide(const char *hidden, char *out, size_t n);

#endif
