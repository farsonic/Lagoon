/*
 * Lagoon - "local" backend: a host directory behind the LnOps interface, so
 * the SMB server core (src/core/srv) can share a folder natively in the
 * tests and with build/host/lnsrv. Names are looked up case-insensitively
 * when the exact name is missing (like the Amiga's file systems and what
 * Windows expects). The Amiga equivalent is src/amiga/fs_dos.c.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <strings.h>
#include "../core/ln_vfs.h"
#include "../core/ln_sys.h"
#include "fs_posix.h"

struct LnFs {
	char root[1024];
	int  ro;
};
struct LnFile { int fd; };
struct LnDir { DIR *d; char path[1200]; };

static int map(int e)
{
	switch (e) {
	case ENOENT: return LN_ENOENT;
	case EEXIST: return LN_EEXIST;
	case ENOTDIR: return LN_ENOTDIR;
	case EISDIR: return LN_EISDIR;
	case ENOTEMPTY: return LN_ENOTEMPTY;
	case EACCES: case EPERM: return LN_EACCES;
	case EROFS: return LN_EROFS;
	case ENOSPC: case EDQUOT: return LN_ENOSPC;
	case EBUSY: case ETXTBSY: return LN_EINUSE;
	case ENAMETOOLONG: return LN_ENAMETOOLONG;
	case ENOMEM: return LN_ENOMEM;
	case EINVAL: return LN_EINVAL;
	}
	return LN_EIO;
}

/* root + path, each missing component matched case-insensitively */
static int full(LnFs *fs, const char *path, char *out, size_t n)
{
	const char *p = path;
	struct stat st;
	if (ln_strlcpy(out, fs->root, n) >= n)
		return LN_ENAMETOOLONG;
	while (*p) {
		const char *e = strchr(p, '/');
		size_t l = e ? (size_t)(e - p) : strlen(p), base = strlen(out);
		char comp[256];
		if (l >= sizeof(comp) || base + 1 + l >= n)
			return LN_ENAMETOOLONG;
		memcpy(comp, p, l);
		comp[l] = 0;
		out[base] = '/';
		memcpy(out + base + 1, comp, l + 1);
		if (lstat(out, &st) != 0) {
			DIR *d;
			struct dirent *de;
			out[base] = 0;
			d = opendir(out);
			out[base] = '/';
			if (d) {
				while ((de = readdir(d)) != NULL)
					if (!strcasecmp(de->d_name, comp) && strlen(de->d_name) == l) {
						memcpy(out + base + 1, de->d_name, l + 1);
						break;
					}
				closedir(d);
			}
		}
		p += l;
		if (*p == '/')
			p++;
	}
	return LN_OK;
}

static void fill(const struct stat *s, LnStat *st)
{
	memset(st, 0, sizeof(*st));
	st->type = S_ISDIR(s->st_mode) ? LN_T_DIR : LN_T_FILE;
	st->size = (u64)s->st_size;
	st->mtime = (u32)s->st_mtime;
	st->ctime = (u32)s->st_mtime;
	st->prot = LN_P_READ | LN_P_EXEC | LN_P_DELETE | LN_P_ARCHIVE;
	if (s->st_mode & S_IWUSR)
		st->prot |= LN_P_WRITE;
	st->mode = (u32)s->st_mode & 07777;
	st->uid = (u32)s->st_uid;
	st->gid = (u32)s->st_gid;
	st->fileid = (u64)s->st_ino;
}

int ln_posixfs_open(const char *root, int readonly, LnFs **out)
{
	struct stat st;
	LnFs *fs;
	if (stat(root, &st) != 0 || !S_ISDIR(st.st_mode))
		return LN_ENOSHARE;
	fs = ln_alloc(sizeof(LnFs));
	if (!fs)
		return LN_ENOMEM;
	ln_strlcpy(fs->root, root, sizeof(fs->root));
	{
		size_t l = strlen(fs->root);
		while (l > 1 && fs->root[l - 1] == '/')
			fs->root[--l] = 0;
	}
	fs->ro = readonly;
	*out = fs;
	return LN_OK;
}

static int px_mount(const LnUrl *url, const LnCreds *cr, LnFs **out)
{
	char p[600];
	(void)cr;
	ln_snprintf(p, sizeof(p), "/%s%s%s", url->share, url->path[0] ? "/" : "", url->path);
	return ln_posixfs_open(p, ln_url_opt_int(url, "ro", 0), out);
}

static void px_unmount(LnFs *fs) { ln_free(fs); }
static int px_reconnect(LnFs *fs) { (void)fs; return LN_OK; }
static int px_ping(LnFs *fs) { (void)fs; return LN_OK; }

static int px_statfs(LnFs *fs, LnStatFs *st)
{
	struct statvfs v;
	memset(st, 0, sizeof(*st));
	if (statvfs(fs->root, &v) != 0)
		return map(errno);
	st->total_bytes = (u64)v.f_blocks * v.f_frsize;
	st->free_bytes = (u64)v.f_bavail * v.f_frsize;
	st->block_size = 4096;
	st->readonly = fs->ro;
	return LN_OK;
}

static int px_stat(LnFs *fs, const char *path, LnStat *st)
{
	char p[1200];
	struct stat s;
	int r = full(fs, path, p, sizeof(p));
	if (r)
		return r;
	if (stat(p, &s) != 0)
		return map(errno);
	fill(&s, st);
	return LN_OK;
}

static int px_opendir(LnFs *fs, const char *path, LnDir **out)
{
	LnDir *d = ln_alloc(sizeof(LnDir));
	int r;
	if (!d)
		return LN_ENOMEM;
	if ((r = full(fs, path, d->path, sizeof(d->path))) != LN_OK || !(d->d = opendir(d->path))) {
		r = r ? r : map(errno);
		ln_free(d);
		return r;
	}
	*out = d;
	return LN_OK;
}

static int px_readdir(LnDir *d, char *name, size_t n, LnStat *st)
{
	struct dirent *de;
	while ((de = readdir(d->d)) != NULL) {
		char p[1500];
		struct stat s;
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		ln_snprintf(p, sizeof(p), "%s/%s", d->path, de->d_name);
		if (stat(p, &s) != 0)
			continue;
		ln_strlcpy(name, de->d_name, n);
		fill(&s, st);
		return 1;
	}
	return 0;
}

static void px_closedir(LnDir *d)
{
	closedir(d->d);
	ln_free(d);
}

static int px_open(LnFs *fs, const char *path, int flags, LnFile **out)
{
	char p[1200];
	int of = 0, fd, r;
	if (fs->ro && (flags & (LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC)))
		return LN_EROFS;
	if ((r = full(fs, path, p, sizeof(p))) != LN_OK)
		return r;
	of = (flags & LN_O_WRITE) ? O_RDWR : O_RDONLY;
	if (flags & LN_O_CREATE) of |= O_CREAT;
	if (flags & LN_O_TRUNC) of |= O_TRUNC;
	if (flags & LN_O_EXCL) of |= O_EXCL;
	fd = open(p, of, 0644);
	if (fd < 0)
		return map(errno);
	{
		struct stat s;
		if (fstat(fd, &s) == 0 && S_ISDIR(s.st_mode)) {
			close(fd);
			return LN_EISDIR;
		}
	}
	*out = ln_alloc(sizeof(LnFile));
	if (!*out) {
		close(fd);
		return LN_ENOMEM;
	}
	(*out)->fd = fd;
	return LN_OK;
}

static long px_read(LnFile *f, u64 off, void *buf, long n)
{
	ssize_t r = pread(f->fd, buf, (size_t)n, (off_t)off);
	return r < 0 ? map(errno) : (long)r;
}

static long px_write(LnFile *f, u64 off, const void *buf, long n)
{
	ssize_t r = pwrite(f->fd, buf, (size_t)n, (off_t)off);
	return r < 0 ? map(errno) : (long)r;
}

static int px_fstat(LnFile *f, LnStat *st)
{
	struct stat s;
	if (fstat(f->fd, &s) != 0)
		return map(errno);
	fill(&s, st);
	return LN_OK;
}

static int px_truncate(LnFile *f, u64 size)
{
	return ftruncate(f->fd, (off_t)size) ? map(errno) : LN_OK;
}

static int px_flush(LnFile *f) { (void)f; return LN_OK; }

static int px_close(LnFile *f)
{
	close(f->fd);
	ln_free(f);
	return LN_OK;
}

static int px_mkdir(LnFs *fs, const char *path)
{
	char p[1200];
	int r;
	if (fs->ro) return LN_EROFS;
	if ((r = full(fs, path, p, sizeof(p))) != LN_OK) return r;
	return mkdir(p, 0755) ? map(errno) : LN_OK;
}

static int px_remove(LnFs *fs, const char *path)
{
	char p[1200];
	struct stat s;
	int r;
	if (fs->ro) return LN_EROFS;
	if ((r = full(fs, path, p, sizeof(p))) != LN_OK) return r;
	if (lstat(p, &s) != 0) return map(errno);
	if (S_ISDIR(s.st_mode))
		return rmdir(p) ? map(errno) : LN_OK;
	return unlink(p) ? map(errno) : LN_OK;
}

static int px_rename(LnFs *fs, const char *from, const char *to)
{
	char a[1200], b[1200];
	struct stat s;
	int r;
	if (fs->ro) return LN_EROFS;
	if ((r = full(fs, from, a, sizeof(a))) != LN_OK || (r = full(fs, to, b, sizeof(b))) != LN_OK)
		return r;
	if (strcasecmp(a, b) && lstat(b, &s) == 0)
		return LN_EEXIST;
	if (!strcasecmp(a, b)) {
		/* case-only rename: the exact new spelling */
		ln_snprintf(b, sizeof(b), "%s/%s", fs->root, to);
	}
	return rename(a, b) ? map(errno) : LN_OK;
}

static int px_setattr(LnFs *fs, const char *path, const LnStat *st, u32 mask)
{
	char p[1200];
	struct stat s;
	int r;
	if (fs->ro) return LN_EROFS;
	if ((r = full(fs, path, p, sizeof(p))) != LN_OK) return r;
	if (stat(p, &s) != 0) return map(errno);
	if (mask & LN_SET_MTIME) {
		struct timeval tv[2];
		tv[0].tv_sec = (time_t)st->mtime; tv[0].tv_usec = 0;
		tv[1] = tv[0];
		if (utimes(p, tv) != 0) return map(errno);
	}
	if (mask & LN_SET_PROT) {
		mode_t m = s.st_mode & 07777;
		if (st->prot & LN_P_WRITE) m |= S_IWUSR; else m &= ~(mode_t)(S_IWUSR | S_IWGRP | S_IWOTH);
		if (chmod(p, m) != 0) return map(errno);
	}
	if (mask & LN_SET_SIZE) {
		if (truncate(p, (off_t)st->size) != 0) return map(errno);
	}
	return LN_OK;
}

static long px_max_io(LnFs *fs) { (void)fs; return 65536; }

const LnOps ln_posixfs_ops = {
	"local", "Host directory", 0,
	px_mount, px_unmount, px_reconnect, px_ping,
	px_statfs, px_stat,
	px_opendir, px_readdir, px_closedir,
	px_open, px_read, px_write, px_fstat, px_truncate, px_flush, px_close,
	px_mkdir, px_remove, px_rename, px_setattr,
	NULL, px_max_io
};
