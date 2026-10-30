/* Lagoon - NFSv3 backend against a real server: nfs-ganesha (FSAL VFS,
 * NFSv3 over TCP) started from tests/servers/nfs/ganesha.sh on ports
 * 20490 (NFS) / 20491 (MOUNT), with rpcbind if none is running. Exercises
 * every LnOps call, 1.5 MB byte-compared transfers (checked on the server's
 * disk too), errors, statfs, list_shares (EXPORT), symlinks, stale handles,
 * reconnect and a server restart with uncommitted writes.
 * Exit 77 if the server cannot run (not root, no ganesha).
 * SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "testutil.h"
#include "ln_vfs.h"
#include "ln_net.h"
#include "ln_sys.h"

#define PORT 20490
static char dir[512], url[1024], cmd[1400];
static const LnOps *ops;

static int server(const char *what)
{
	snprintf(cmd, sizeof(cmd), "tests/servers/nfs/ganesha.sh %s %s %d >/dev/null 2>&1", what, dir, PORT);
	return WEXITSTATUS(system(cmd));
}

static void hpath(char *out, size_t n, const char *rel)
{
	snprintf(out, n, "%s/export/%s", dir, rel);
}

static long hsize(const char *rel)
{
	char p[1024];
	struct stat st;
	hpath(p, sizeof(p), rel);
	return stat(p, &st) ? -1 : (long)st.st_size;
}

static int hcompare(const char *rel, const u8 *data, long n)
{
	char p[1024];
	FILE *f;
	u8 *b;
	int ok;
	hpath(p, sizeof(p), rel);
	if (!(f = fopen(p, "rb"))) return 0;
	b = malloc((size_t)n + 1);
	ok = (long)fread(b, 1, (size_t)n + 1, f) == n && !memcmp(b, data, (size_t)n);
	fclose(f);
	free(b);
	return ok;
}

static void hwrite(const char *rel, const char *text)
{
	char p[1024];
	FILE *f;
	hpath(p, sizeof(p), rel);
	if ((f = fopen(p, "w"))) { fputs(text, f); fclose(f); }
}

static int mnt(const char *u, LnFs **fs)
{
	const LnOps *o;
	return ln_vfs_mount_url(u, NULL, &o, fs);
}

static long put_file(LnFs *fs, const char *path, const u8 *data, long n, long chunk)
{
	LnFile *f;
	long off = 0;
	int r = ops->open(fs, path, LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC, &f);
	if (r) return r;
	while (off < n) {
		long w = ops->write(f, (u64)off, data + off, LN_MIN(chunk, n - off));
		if (w <= 0) { ops->close(f); return w ? w : LN_EIO; }
		off += w;
	}
	r = ops->close(f);
	return r ? r : off;
}

static int get_cmp(LnFs *fs, const char *path, const u8 *data, long n, long chunk)
{
	LnFile *f;
	u8 *b = malloc((size_t)chunk);
	long off = 0, r;
	int ok = 1;
	if (ops->open(fs, path, LN_O_READ, &f)) { free(b); return 0; }
	while ((r = ops->read(f, (u64)off, b, chunk)) > 0) {
		if (off + r > n || memcmp(b, data + off, (size_t)r)) { ok = 0; break; }
		off += r;
	}
	ops->close(f);
	free(b);
	return ok && r == 0 && off == n;
}

static int found;
static void share_cb(void *ud, const char *name, const char *comment)
{
	(void)ud; (void)comment;
	if (strstr(name, "/export") || strstr(name, "/ro")) found++;
}

int main(void)
{
	LnFs *fs, *fs2;
	LnFile *f, *g;
	LnDir *d;
	LnStat st;
	LnStatFs sf;
	char name[300], p[1100];
	u8 *big, *back;
	long BIG = 1572864 + 123, i, n;
	int r, count, sawdir, sawfile, sawlink;
	const char *tmp = getenv("TMPDIR");

	ln_net_init();
	ops = ln_vfs_find("nfs");
	if (getuid() != 0) T_SKIP("t_nfs_server", "needs root for ganesha");
	snprintf(dir, sizeof(dir), "%s/lagoon-nfs.XXXXXX", tmp && *tmp ? tmp : "/tmp");
	if (!mkdtemp(dir)) T_SKIP("t_nfs_server", "mkdtemp");
	if (server("start") != 0) T_SKIP("t_nfs_server", "nfs-ganesha could not start");
	chmod(dir, 0755);
	{
		char e[1024], ro[1024];
		snprintf(e, sizeof(e), "%s/export", dir);
		snprintf(ro, sizeof(ro), "%s/ro", dir);
		chmod(e, 0755);
		chmod(ro, 0755);
		snprintf(ro, sizeof(ro), "%s/ro/readme.txt", dir);
		{ FILE *x = fopen(ro, "w"); if (x) { fputs("read only\n", x); fclose(x); } }
	}

	/* ---- mount: via the portmapper; then with explicit ports and no portmapper */
	snprintf(url, sizeof(url), "nfs://127.0.0.1%s/export?uid=0&gid=0", dir);
	r = mnt(url, &fs);
	CHECK_INT(r, LN_OK);
	if (r) { server("stop"); T_DONE("t_nfs_server"); }
	snprintf(p, sizeof(p), "nfs://127.0.0.1:%d%s/export?uid=0&gid=0&mountport=%d&pmapport=1", PORT, dir, PORT + 1);
	r = mnt(p, &fs2);
	CHECK_INT(r, LN_OK);
	if (!r) ops->unmount(fs2);
	snprintf(p, sizeof(p), "nfs://127.0.0.1%s/nonexistent", dir);
	CHECK_INT(mnt(p, &fs2), LN_ENOSHARE);
	CHECK(ops->max_io(fs) >= 4096 && ops->max_io(fs) <= 32768);
	CHECK_INT(ops->ping(fs), LN_OK);

	/* ---- statfs, root */
	CHECK_INT(ops->statfs(fs, &sf), LN_OK);
	CHECK(sf.total_bytes > 0 && sf.free_bytes > 0 && sf.free_bytes <= sf.total_bytes);
	CHECK_STR(sf.volume, "export");
	CHECK_INT(ops->stat(fs, "", &st), LN_OK);
	CHECK_INT(st.type, LN_T_DIR);
	CHECK(st.prot & LN_P_WRITE);

	/* ---- mkdir / errors */
	CHECK_INT(ops->mkdir(fs, "d1"), LN_OK);
	CHECK_INT(ops->mkdir(fs, "d1"), LN_EEXIST);
	CHECK_INT(ops->mkdir(fs, "nope/d2"), LN_ENOENT);
	CHECK_INT(ops->stat(fs, "d1", &st), LN_OK);
	CHECK_INT(st.type, LN_T_DIR);
	CHECK_INT(st.mode, 0755);
	CHECK_INT(ops->stat(fs, "missing", &st), LN_ENOENT);

	/* ---- 1.5 MB write + read, byte compared here and on the server's disk */
	big = malloc((size_t)BIG);
	back = malloc((size_t)BIG);
	for (i = 0; i < BIG; i++) big[i] = (u8)((i * 7919) ^ (i >> 9));
	CHECK_INT(put_file(fs, "d1/big.bin", big, BIG, ops->max_io(fs)), BIG);
	CHECK_INT(hsize("d1/big.bin"), BIG);
	CHECK(hcompare("d1/big.bin", big, BIG));
	CHECK(get_cmp(fs, "d1/big.bin", big, BIG, ops->max_io(fs)));
	CHECK(get_cmp(fs, "d1/big.bin", big, BIG, 100000));       /* > max_io: split by the backend */
	CHECK(get_cmp(fs, "d1/big.bin", big, BIG, 777));
	/* odd-sized unaligned writes through one handle */
	CHECK_INT(put_file(fs, "d1/odd.bin", big, 300001, 4099), 300001);
	CHECK(hcompare("d1/odd.bin", big, 300001));
	CHECK_INT(ops->stat(fs, "d1/big.bin", &st), LN_OK);
	CHECK(st.size == (u64)BIG);
	CHECK_INT(st.type, LN_T_FILE);
	CHECK_INT(st.mode, 0644);
	CHECK(st.fileid != 0);
	CHECK_INT(st.prot & (LN_P_READ | LN_P_WRITE), LN_P_READ | LN_P_WRITE);

	/* ---- open flags, fstat, truncate, flush, positional I/O */
	CHECK_INT(ops->open(fs, "d1/big.bin", LN_O_WRITE | LN_O_CREATE | LN_O_EXCL, &f), LN_EEXIST);
	CHECK_INT(ops->open(fs, "d1", LN_O_READ, &f), LN_EISDIR);
	CHECK_INT(ops->open(fs, "d1/none", LN_O_READ, &f), LN_ENOENT);
	CHECK_INT(ops->open(fs, "d1/big.bin/x", LN_O_READ, &f), LN_ENOTDIR);
	r = ops->open(fs, "d1/excl.txt", LN_O_WRITE | LN_O_CREATE | LN_O_EXCL, &f);
	CHECK_INT(r, LN_OK);
	if (!r) {
		CHECK_INT(ops->write(f, 0, "hello world", 11), 11);
		CHECK_INT(ops->write(f, 20, "tail", 4), 4);              /* sparse gap */
		CHECK_INT(ops->flush(f), LN_OK);
		CHECK_INT(hsize("d1/excl.txt"), 24);
		CHECK_INT(ops->fstat(f, &st), LN_OK);
		CHECK(st.size == 24);
		CHECK_INT(st.mode, 0644);                                /* EXCLUSIVE create + SETATTR */
		CHECK_INT(ops->truncate(f, 5), LN_OK);
		CHECK_INT(ops->fstat(f, &st), LN_OK);
		CHECK(st.size == 5);
		n = ops->read(f, 1, name, 100);
		CHECK_INT(n, 4);
		CHECK(!memcmp(name, "ello", 4));
		CHECK_INT(ops->read(f, 5, name, 10), 0);                 /* EOF */
		CHECK_INT(ops->close(f), LN_OK);
	}
	r = ops->open(fs, "d1/excl.txt", LN_O_WRITE | LN_O_TRUNC, &f);
	CHECK_INT(r, LN_OK);
	if (!r) ops->close(f);
	CHECK_INT(hsize("d1/excl.txt"), 0);
	r = ops->open(fs, "d1/excl.txt", LN_O_WRITE | LN_O_CREATE, &f);   /* exists: opened */
	CHECK_INT(r, LN_OK);
	if (!r) { CHECK_INT(ops->write(f, 0, "abc", 3), 3); ops->close(f); }
	CHECK(hcompare("d1/excl.txt", (const u8 *)"abc", 3));

	/* ---- readdir with several batches + Unicode names */
	CHECK_INT(ops->mkdir(fs, "many"), LN_OK);
	for (i = 0; i < 300; i++) {
		snprintf(p, sizeof(p), "many/file-with-a-fairly-long-name-%04ld.txt", i);
		r = ops->open(fs, p, LN_O_WRITE | LN_O_CREATE, &f);
		if (r) break;
		ops->close(f);
	}
	CHECK_INT(i, 300);
	CHECK_INT(ops->opendir(fs, "many", &d), LN_OK);
	count = 0;
	while ((r = ops->readdir(d, name, sizeof(name), &st)) > 0)
		if (st.type == LN_T_FILE && !strncmp(name, "file-with", 9)) count++;
	CHECK_INT(r, 0);
	CHECK_INT(count, 300);
	ops->closedir(d);
	CHECK_INT(ops->opendir(fs, "d1/big.bin", &d), LN_ENOTDIR);
	CHECK_INT(put_file(fs, "Gr\xc3\xbc\xc3\x9f" "e \xe2\x9c\x93.txt", (const u8 *)"u", 1, 10), 1);
	CHECK_INT(hsize("Gr\xc3\xbc\xc3\x9f" "e \xe2\x9c\x93.txt"), 1);

	/* ---- symlinks (made on the server's disk) */
	{
		char t[1024], l[1024];
		hpath(l, sizeof(l), "link-d1"); CHECK(symlink("d1", l) == 0);
		hpath(l, sizeof(l), "link-excl"); CHECK(symlink("d1/excl.txt", l) == 0);
		hpath(t, sizeof(t), "d1/excl.txt");
		hpath(l, sizeof(l), "abs-link"); CHECK(symlink(t, l) == 0);
		hpath(l, sizeof(l), "d1/up"); CHECK(symlink("../many", l) == 0);
		hpath(l, sizeof(l), "outside"); CHECK(symlink("/etc/passwd", l) == 0);
	}
	CHECK_INT(ops->opendir(fs, "", &d), LN_OK);
	sawdir = sawfile = sawlink = 0;
	while ((r = ops->readdir(d, name, sizeof(name), &st)) > 0) {
		if (!strcmp(name, "d1") && st.type == LN_T_DIR) sawdir = 1;
		if (!strcmp(name, "Gr\xc3\xbc\xc3\x9f" "e \xe2\x9c\x93.txt") && st.type == LN_T_FILE && st.size == 1) sawfile = 1;
		if (!strcmp(name, "link-d1") && st.type == LN_T_LINK) sawlink = 1;
		CHECK(strcmp(name, ".") && strcmp(name, ".."));
	}
	ops->closedir(d);
	CHECK(sawdir); CHECK(sawfile); CHECK(sawlink);
	CHECK_INT(ops->stat(fs, "link-excl", &st), LN_OK);
	CHECK_INT(st.type, LN_T_LINK);
	CHECK(get_cmp(fs, "link-excl", (const u8 *)"abc", 3, 100));          /* open follows */
	CHECK(get_cmp(fs, "link-d1/excl.txt", (const u8 *)"abc", 3, 100));   /* link in the middle */
	CHECK(get_cmp(fs, "abs-link", (const u8 *)"abc", 3, 100));           /* absolute, inside the export */
	CHECK_INT(ops->stat(fs, "d1/up/file-with-a-fairly-long-name-0007.txt", &st), LN_OK);
	CHECK_INT(ops->open(fs, "outside", LN_O_READ, &f), LN_ENOENT);
	r = ops->opendir(fs, "link-d1", &d);
	CHECK_INT(r, LN_OK);
	if (!r) ops->closedir(d);

	/* ---- rename */
	CHECK_INT(ops->rename(fs, "d1/excl.txt", "d1/big.bin"), LN_EEXIST);
	CHECK_INT(ops->rename(fs, "d1/excl.txt", "d1/renamed.txt"), LN_OK);
	CHECK_INT(ops->stat(fs, "d1/excl.txt", &st), LN_ENOENT);
	CHECK_INT(ops->stat(fs, "d1/renamed.txt", &st), LN_OK);
	CHECK_INT(ops->rename(fs, "d1/renamed.txt", "renamed-top.txt"), LN_OK);   /* across dirs */
	CHECK_INT(hsize("renamed-top.txt"), 3);
	CHECK_INT(ops->rename(fs, "nothere", "x"), LN_ENOENT);
	CHECK_INT(ops->rename(fs, "many", "many2"), LN_OK);                       /* cached dir moves */
	CHECK_INT(ops->stat(fs, "many/file-with-a-fairly-long-name-0001.txt", &st), LN_ENOENT);
	CHECK_INT(ops->stat(fs, "many2/file-with-a-fairly-long-name-0001.txt", &st), LN_OK);

	/* ---- setattr */
	memset(&st, 0, sizeof(st));
	st.mtime = 1000000000;
	CHECK_INT(ops->setattr(fs, "renamed-top.txt", &st, LN_SET_MTIME), LN_OK);
	st.mode = 0600;
	CHECK_INT(ops->setattr(fs, "renamed-top.txt", &st, LN_SET_MODE), LN_OK);
	CHECK_INT(ops->stat(fs, "renamed-top.txt", &st), LN_OK);
	CHECK_INT(st.mtime, 1000000000);
	CHECK_INT(st.mode, 0600);
	st.prot = LN_P_READ | LN_P_EXEC;
	CHECK_INT(ops->setattr(fs, "renamed-top.txt", &st, LN_SET_PROT), LN_OK);
	CHECK_INT(ops->stat(fs, "renamed-top.txt", &st), LN_OK);
	CHECK_INT(st.mode, 0500);
	st.size = 2;
	CHECK_INT(ops->setattr(fs, "renamed-top.txt", &st, LN_SET_SIZE), LN_OK);
	CHECK_INT(hsize("renamed-top.txt"), 2);
	CHECK_INT(ops->setattr(fs, "renamed-top.txt", &st, LN_SET_COMMENT), LN_ENOTSUP);
	CHECK_INT(ops->setattr(fs, "gone.txt", &st, LN_SET_MTIME), LN_ENOENT);

	/* ---- remove */
	CHECK_INT(ops->remove(fs, "d1"), LN_ENOTEMPTY);
	CHECK_INT(ops->remove(fs, "d1/odd.bin"), LN_OK);
	CHECK_INT(hsize("d1/odd.bin"), -1);
	CHECK_INT(ops->remove(fs, "d1/odd.bin"), LN_ENOENT);
	CHECK_INT(ops->mkdir(fs, "empty"), LN_OK);
	CHECK_INT(ops->remove(fs, "empty"), LN_OK);
	CHECK_INT(ops->stat(fs, "empty", &st), LN_ENOENT);
	CHECK_INT(ops->remove(fs, ""), LN_EINVAL);

	/* ---- for the stale handle check after the server restart below */
	CHECK_INT(ops->mkdir(fs, "st"), LN_OK);
	CHECK_INT(put_file(fs, "st/x.txt", (const u8 *)"one", 3, 10), 3);
	CHECK_INT(ops->stat(fs, "st/x.txt", &st), LN_OK);   /* caches the handle of "st" */

	/* ---- permissions: nobody cannot write into root-owned 0755 dirs */
	snprintf(p, sizeof(p), "nfs://127.0.0.1%s/export", dir);
	r = mnt(p, &fs2);
	CHECK_INT(r, LN_OK);
	if (!r) {
		CHECK_INT(ops->stat(fs2, "d1", &st), LN_OK);
		CHECK(!(st.prot & LN_P_WRITE));
		CHECK(st.prot & LN_P_READ);
		CHECK_INT(ops->open(fs2, "d1/nobody.txt", LN_O_WRITE | LN_O_CREATE, &f), LN_EACCES);
		CHECK_INT(ops->mkdir(fs2, "d1/x"), LN_EACCES);
		CHECK_INT(ops->remove(fs2, "d1/big.bin"), LN_EACCES);
		CHECK(get_cmp(fs2, "d1/big.bin", big, BIG, 32768));
		ops->unmount(fs2);
	}
	/* sub-directory URL: the share root is d1 */
	snprintf(p, sizeof(p), "nfs://127.0.0.1%s/export/d1?uid=0&gid=0", dir);
	r = mnt(p, &fs2);
	CHECK_INT(r, LN_OK);
	if (!r) {
		CHECK_INT(ops->stat(fs2, "big.bin", &st), LN_OK);
		CHECK(st.size == (u64)BIG);
		CHECK_INT(ops->statfs(fs2, &sf), LN_OK);
		CHECK_STR(sf.volume, "d1");
		ops->unmount(fs2);
	}
	/* read-only export (root squashed) */
	snprintf(p, sizeof(p), "nfs://127.0.0.1%s/ro?uid=0&gid=0", dir);
	r = mnt(p, &fs2);
	CHECK_INT(r, LN_OK);
	if (!r) {
		CHECK(get_cmp(fs2, "readme.txt", (const u8 *)"read only\n", 10, 100));
		r = ops->open(fs2, "new.txt", LN_O_WRITE | LN_O_CREATE, &f);
		CHECK(r == LN_EROFS || r == LN_EACCES);
		CHECK_INT(ops->mkdir(fs2, "x"), r);
		ops->unmount(fs2);
	}
	snprintf(p, sizeof(p), "nfs://127.0.0.1%s/ro?ro", dir);
	r = mnt(p, &fs2);
	CHECK_INT(r, LN_OK);
	if (!r) {
		CHECK_INT(ops->statfs(fs2, &sf), LN_OK);
		CHECK(sf.readonly);
		CHECK_INT(ops->remove(fs2, "readme.txt"), LN_EROFS);
		ops->unmount(fs2);
	}

	/* ---- list_shares (MOUNT EXPORT) */
	{
		LnUrl u;
		LnCreds c;
		memset(&c, 0, sizeof(c));
		ln_url_parse("nfs://127.0.0.1/", &u);
		found = 0;
		CHECK_INT(ops->list_shares(&u, &c, share_cb, NULL), LN_OK);
		CHECK_INT(found, 2);
	}

	/* ---- reconnect keeps open files */
	CHECK_INT(ops->open(fs, "d1/big.bin", LN_O_READ, &f), LN_OK);
	CHECK_INT(ops->read(f, 0, back, 1000), 1000);
	CHECK_INT(ops->reconnect(fs), LN_OK);
	CHECK_INT(ops->read(f, 1000, back + 1000, 5000), 5000);
	CHECK(!memcmp(back, big, 6000));

	/* ---- server restart with uncommitted (UNSTABLE) writes: the handle
	 * survives, the new write verifier makes us resend */
	CHECK_INT(ops->open(fs, "restart.bin", LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC, &g), LN_OK);
	n = ops->max_io(fs);
	CHECK_INT(ops->write(g, 0, big, n), n);
	ln_log_level = 1;
	CHECK_INT(server("stop"), 0);
	{
		/* replace the cached directory "st" while the server is down: its
		 * old handle is stale afterwards (ganesha hides deleted directories
		 * it still holds open, so this is done across the restart) */
		char a[1024], b[1024];
		hpath(a, sizeof(a), "st"); hpath(b, sizeof(b), "st-old");
		rename(a, b);
		mkdir(a, 0755);
		hwrite("st/x.txt", "fresh");
		hpath(b, sizeof(b), "st-old/x.txt"); unlink(b);
		hpath(b, sizeof(b), "st-old"); rmdir(b);
	}
	CHECK_INT(server("start"), 0);
	r = (int)ops->write(g, (u64)n, big + n, n);
	for (i = 0; r == LN_ECONNRESET && i < 10; i++) {          /* what the handler does */
		ops->reconnect(fs);
		r = (int)ops->write(g, (u64)n, big + n, n);
	}
	CHECK_INT(r, n);
	CHECK_INT(ops->close(g), LN_OK);
	CHECK(hcompare("restart.bin", big, 2 * n));
	n = ops->read(f, 6000, back + 6000, 4000);                /* the old read handle too */
	CHECK_INT(n, 4000);
	CHECK(!memcmp(back, big, 10000));
	ops->close(f);
	CHECK_INT(ops->ping(fs), LN_OK);
	ln_log_level = 1;
	CHECK_INT(ops->stat(fs, "st/x.txt", &st), LN_OK);      /* NFS3ERR_STALE -> looked up again */
	CHECK(st.size == 5);
	ln_log_level = 0;

	ops->unmount(fs);
	free(big);
	free(back);
	server("stop");
	T_DONE("t_nfs_server");
}
