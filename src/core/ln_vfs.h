/*
 * Lagoon - the interface every protocol backend implements (SMB2/3, AFP,
 * NFSv3) and the Amiga handler / CLI / prefs / tests call.
 *
 * Paths are UTF-8 (NFC), '/'-separated, relative to the share root with no
 * leading or trailing '/'; "" is the root. Backends never see Amiga names.
 * Times are Unix seconds UTC. All calls return LN_OK (0) / a count, or a
 * negative LN_E* code. LN_ECONNRESET means the connection was lost: the
 * caller (handler) calls ops->reconnect() and retries once; open files and
 * directories are invalid after a reconnect unless the backend reopened them
 * (backends should transparently reopen files by path when they can).
 *
 * One LnFs is used by one task at a time (the handler is single threaded).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_VFS_H
#define LN_VFS_H

#include "ln_types.h"
#include "ln_err.h"
#include "ln_url.h"

enum { LN_T_FILE = 1, LN_T_DIR = 2, LN_T_LINK = 3 };

/* Amiga-style protection, but positive logic: bit set = allowed. The
 * handler converts to FIBF_* (where RWED are inverted). */
#define LN_P_READ    0x01
#define LN_P_WRITE   0x02
#define LN_P_EXEC    0x04
#define LN_P_DELETE  0x08
#define LN_P_ARCHIVE 0x10    /* "archived": SMB !ATTR_ARCHIVE */
#define LN_P_HIDDEN  0x20    /* hidden (SMB attribute, dot files are not hidden) */
#define LN_P_SCRIPT  0x40
#define LN_P_PURE    0x80

typedef struct LnStat {
	int  type;               /* LN_T_* */
	u64  size;
	u32  mtime;              /* Unix seconds UTC */
	u32  ctime;              /* creation (birth) time if known, else mtime */
	u32  prot;               /* LN_P_* */
	u32  mode;               /* Unix mode bits if the server has them (NFS, AFP UNIX privs, SMB posix), else 0 */
	u32  uid, gid;
	u64  fileid;             /* server inode / file id, 0 if unknown (used for locks/SameLock) */
	char comment[80];        /* file note if the server keeps one (AFP comment, SMB stream later), UTF-8 */
} LnStat;

/* which fields of LnStat a setattr changes */
#define LN_SET_MTIME   0x01
#define LN_SET_PROT    0x02
#define LN_SET_MODE    0x04
#define LN_SET_SIZE    0x08
#define LN_SET_COMMENT 0x10

typedef struct LnStatFs {
	u64  total_bytes, free_bytes;
	u32  block_size;         /* preferred I/O / allocation unit, e.g. 4096 */
	int  readonly;
	char volume[64];         /* server-side volume label if any, UTF-8 */
} LnStatFs;

/* open flags */
#define LN_O_READ   0x01
#define LN_O_WRITE  0x02
#define LN_O_CREATE 0x04     /* create if missing */
#define LN_O_TRUNC  0x08     /* truncate to 0 */
#define LN_O_EXCL   0x10     /* fail with LN_EEXIST if it exists */

typedef struct LnFs   LnFs;     /* a mounted share (backend private) */
typedef struct LnFile LnFile;   /* an open file (backend private) */
typedef struct LnDir  LnDir;    /* an open directory listing (backend private) */

typedef struct LnCreds {
	char domain[64];
	char user[64];
	char password[128];      /* empty user = guest / anonymous */
} LnCreds;

/* share enumeration (for the prefs Browse button) */
typedef void (*ln_share_cb)(void *ud, const char *name, const char *comment);

typedef struct LnOps {
	const char *scheme;      /* "smb", "afp", "nfs" */
	const char *name;        /* "SMB 2/3 (Windows, macOS, Samba)" */
	u16 default_port;

	/* connect + authenticate + attach to url->share; *out on success */
	int  (*mount)(const LnUrl *url, const LnCreds *cr, LnFs **out);
	void (*unmount)(LnFs *fs);
	/* re-establish a lost connection (same share and credentials) */
	int  (*reconnect)(LnFs *fs);
	/* keep-alive / connection check; called every ~60 s when idle */
	int  (*ping)(LnFs *fs);

	int  (*statfs)(LnFs *fs, LnStatFs *st);
	int  (*stat)(LnFs *fs, const char *path, LnStat *st);

	int  (*opendir)(LnFs *fs, const char *path, LnDir **out);
	/* next entry (never "." or ".."): 1 = got one, 0 = end, <0 = error */
	int  (*readdir)(LnDir *d, char *name, size_t namemax, LnStat *st);
	void (*closedir)(LnDir *d);

	int  (*open)(LnFs *fs, const char *path, int flags, LnFile **out);
	/* positional I/O; return bytes (0 = EOF for read) */
	long (*read)(LnFile *f, u64 off, void *buf, long n);
	long (*write)(LnFile *f, u64 off, const void *buf, long n);
	int  (*fstat)(LnFile *f, LnStat *st);
	int  (*truncate)(LnFile *f, u64 size);
	int  (*flush)(LnFile *f);
	int  (*close)(LnFile *f);

	int  (*mkdir)(LnFs *fs, const char *path);
	/* removes a file or an empty directory */
	int  (*remove)(LnFs *fs, const char *path);
	/* rename/move within the share; fails with LN_EEXIST if 'to' exists */
	int  (*rename)(LnFs *fs, const char *from, const char *to);
	int  (*setattr)(LnFs *fs, const char *path, const LnStat *st, u32 mask);

	/* list shares/volumes/exports on url->host (url->share ignored);
	 * may be NULL if unsupported */
	int  (*list_shares)(const LnUrl *url, const LnCreds *cr, ln_share_cb cb, void *ud);

	/* largest efficient read/write request in bytes (handler splits I/O) */
	long (*max_io)(LnFs *fs);
} LnOps;

/* backend registry (src/core/ln_vfs.c) */
const LnOps *ln_vfs_find(const char *scheme);          /* NULL if unknown */
const LnOps *ln_vfs_backend(int i);                    /* NULL past the end */

/* convenience: parse url, take credentials from it (or cr if non-NULL),
 * find the backend and mount. */
int ln_vfs_mount_url(const char *url, const LnCreds *cr, const LnOps **ops, LnFs **fs);

/* path helpers for backends and the handler */
/* join dir + "/" + name into out (handles dir == "") */
int  ln_path_join(char *out, size_t n, const char *dir, const char *name);
/* parent of path into out ("" for top-level entries) */
void ln_path_parent(char *out, size_t n, const char *path);
/* last component */
const char *ln_path_base(const char *path);

#endif
