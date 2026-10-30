/*
 * Lagoon - share URLs:
 *   smb://[domain;][user[:password]@]host[:port]/share[/path]
 *   afp://[user[:password]@]host[:port]/volume[/path]
 *   nfs://host[:port]/export/path[?uid=N&gid=N&version=3]
 *   cifs:// is a synonym of smb://. Percent-escapes are decoded.
 *   ?key=value&... options are kept in opts for the backend
 *   (e.g. smb: sign=required, encrypt=yes, dialect=3.1.1; nfs: uid, gid).
 * For nfs the "share" is the whole export path ("/srv/data"); path is empty.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_URL_H
#define LN_URL_H

#include "ln_types.h"

#define LN_URL_MAX 256

typedef struct LnUrl {
	char scheme[8];          /* "smb", "afp", "nfs" (lower case) */
	char domain[64];
	char user[64];
	char password[128];
	char host[128];
	u16  port;               /* 0 = default for the scheme */
	char share[128];         /* SMB share / AFP volume / NFS export path */
	char path[LN_URL_MAX];   /* subdirectory inside the share, no leading '/' */
	char opts[LN_URL_MAX];   /* "k=v&k=v" */
} LnUrl;

int  ln_url_parse(const char *s, LnUrl *u);            /* LN_OK / LN_EINVAL */
/* format without the password (for display) */
void ln_url_format(const LnUrl *u, char *buf, size_t n);
/* option lookup; returns def if absent */
const char *ln_url_opt(const LnUrl *u, const char *key, const char *def, char *buf, size_t n);
int  ln_url_opt_int(const LnUrl *u, const char *key, int def);

#endif
