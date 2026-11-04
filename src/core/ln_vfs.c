/*
 * Lagoon - backend registry, URL mounting, path helpers.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "ln_vfs.h"
#include "ln_sys.h"

extern const LnOps ln_smb_ops;   /* src/core/smb */
extern const LnOps ln_afp_ops;   /* src/core/afp */
extern const LnOps ln_nfs_ops;   /* src/core/nfs */
extern const LnOps ln_mem_ops;   /* src/core/mem: in-memory test file system */

static const LnOps *const backends[] = { &ln_smb_ops, &ln_afp_ops, &ln_nfs_ops, &ln_mem_ops };

const LnOps *ln_vfs_backend(int i)
{
	return (i >= 0 && i < (int)LN_ARRAY_SIZE(backends)) ? backends[i] : NULL;
}

const LnOps *ln_vfs_find(const char *scheme)
{
	int i;
	if (!ln_strcasecmp(scheme, "cifs"))
		scheme = "smb";
	for (i = 0; i < (int)LN_ARRAY_SIZE(backends); i++)
		if (!ln_strcasecmp(backends[i]->scheme, scheme))
			return backends[i];
	return NULL;
}

int ln_vfs_mount_url(const char *url, const LnCreds *cr, const LnOps **ops, LnFs **fs)
{
	LnUrl *u = ln_alloc(sizeof(*u));
	LnCreds c;
	int r;
	if (!u)
		return LN_ENOMEM;
	r = ln_url_parse(url, u);
	if (r == LN_OK) {
		*ops = ln_vfs_find(u->scheme);
		if (!*ops)
			r = LN_ENOTSUP;
	}
	if (r == LN_OK) {
		memset(&c, 0, sizeof(c));
		if (cr)
			c = *cr;
		if (u->user[0]) {
			ln_strlcpy(c.user, u->user, sizeof(c.user));
			ln_strlcpy(c.domain, u->domain, sizeof(c.domain));
			ln_strlcpy(c.password, u->password, sizeof(c.password));
		}
		r = (*ops)->mount(u, &c, fs);
		ln_wipe(&c, sizeof(c));
	}
	ln_wipe(u, sizeof(*u));
	ln_free(u);
	return r;
}

int ln_path_join(char *out, size_t n, const char *dir, const char *name)
{
	size_t l;
	if (!dir[0])
		l = ln_strlcpy(out, name, n);
	else if (!name[0])
		l = ln_strlcpy(out, dir, n);
	else {
		ln_strlcpy(out, dir, n);
		ln_strlcat(out, "/", n);
		l = ln_strlcat(out, name, n);
	}
	return l < n ? LN_OK : LN_ENAMETOOLONG;
}

void ln_path_parent(char *out, size_t n, const char *path)
{
	const char *s = strrchr(path, '/');
	size_t l = s ? (size_t)(s - path) : 0;
	if (l >= n)
		l = n - 1;
	memcpy(out, path, l);
	out[l] = 0;
}

const char *ln_path_base(const char *path)
{
	const char *s = strrchr(path, '/');
	return s ? s + 1 : path;
}
