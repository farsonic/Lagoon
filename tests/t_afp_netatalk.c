/*
 * Lagoon - AFP backend against a real Netatalk 3 server: starts afpd from
 * tests/servers/afp/ on 127.0.0.1:5481 with volumes in a fresh /tmp
 * directory and exercises every LnOps call (guest / DHX2 / clear text
 * logins, volume passwords, big byte-compared transfers, decomposed
 * Unicode names, errors, statfs, list_shares, Finder comments, attributes,
 * paged listings, tickles and reconnect). Needs root and netatalk;
 * exits 77 (skipped) otherwise.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define _DEFAULT_SOURCE
#include "testutil.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "ln_vfs.h"
#include "ln_sys.h"
#include "ln_net.h"

#define PORT "5481"
static char dir[64];
static const LnOps *ops;

static void sh(const char *fmt, const char *a)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), fmt, a, a);
	if (system(cmd) != 0)
		fprintf(stderr, "command failed: %s\n", cmd);
}

static LnFs *mnt(const char *userpass, const char *vol, const char *opts, int *err)
{
	char url[256];
	LnFs *fs = NULL;
	const LnOps *o;
	int r;
	snprintf(url, sizeof(url), "afp://%s127.0.0.1:" PORT "/%s%s%s", userpass, vol, opts[0] ? "?" : "", opts);
	r = ln_vfs_mount_url(url, NULL, &o, &fs);
	if (err)
		*err = r;
	if (r) {
		if (!err)
			fprintf(stderr, "mount %s: %s\n", url, ln_strerror(r));
		return NULL;
	}
	return fs;
}

#define USER "lagoon:lagoon-test-pw@"

static int put(LnFs *fs, const char *path, const void *data, long n, int flags)
{
	LnFile *f;
	int r = ops->open(fs, path, flags ? flags : LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC, &f);
	long w;
	if (r)
		return r;
	w = n ? ops->write(f, 0, data, n) : 0;
	r = ops->close(f);
	return w < 0 ? (int)w : w != n ? LN_EIO : r;
}

static long get(LnFs *fs, const char *path, void *buf, long max)
{
	LnFile *f;
	long n;
	int r = ops->open(fs, path, LN_O_READ, &f);
	if (r)
		return r;
	n = ops->read(f, 0, buf, max);
	ops->close(f);
	return n;
}

static int host_read(const char *rel, u8 *buf, long max, long *n)
{
	char p[512];
	FILE *f;
	snprintf(p, sizeof(p), "%s/vol/%s", dir, rel);
	if (!(f = fopen(p, "rb")))
		return -1;
	*n = (long)fread(buf, 1, (size_t)max, f);
	fclose(f);
	return 0;
}

static int host_stat(const char *rel, struct stat *st)
{
	char p[512];
	snprintf(p, sizeof(p), "%s/vol/%s", dir, rel);
	return stat(p, st);
}

static int count_dir(LnFs *fs, const char *path, const char *want, int *found)
{
	LnDir *d;
	char name[256];
	LnStat st;
	int n = 0, r;
	if (found)
		*found = 0;
	if ((r = ops->opendir(fs, path, &d)) != 0)
		return r;
	while ((r = ops->readdir(d, name, sizeof(name), &st)) > 0) {
		n++;
		if (want && found && !strcmp(name, want))
			*found = 1;
	}
	ops->closedir(d);
	return r < 0 ? r : n;
}

static void share_cb(void *ud, const char *name, const char *comment)
{
	int *seen = ud;
	(void)comment;
	if (!strcmp(name, "lagoon")) seen[0] = 1;
	if (!strcmp(name, "readonly")) seen[1] = 1;
	if (!strcmp(name, "secret")) seen[2] = 1;
}

static void t_shares_and_logins(void)
{
	LnUrl u;
	LnCreds c;
	int seen[3] = { 0, 0, 0 }, r;
	LnFs *fs;
	LnStatFs sf;
	char buf[64];
	memset(&c, 0, sizeof(c));
	ln_url_parse("afp://127.0.0.1:" PORT "/", &u);
	CHECK_INT(ops->list_shares(&u, &c, share_cb, seen), LN_OK);
	CHECK(seen[0] && seen[1] && seen[2]);
	/* DHX2 user listing too */
	strcpy(c.user, "lagoon");
	strcpy(c.password, "lagoon-test-pw");
	seen[0] = 0;
	CHECK_INT(ops->list_shares(&u, &c, share_cb, seen), LN_OK);
	CHECK(seen[0]);

	/* wrong password, unknown volume, guest on the volume */
	CHECK(!mnt("lagoon:wrong@", "lagoon", "", &r));
	CHECK_INT(r, LN_EAUTH);
	CHECK(!mnt(USER, "nosuch", "", &r));
	CHECK_INT(r, LN_ENOSHARE);
	fs = mnt("", "lagoon", "", NULL);
	CHECK(fs != NULL);
	if (fs) {
		CHECK_INT(ops->statfs(fs, &sf), LN_OK);
		CHECK(sf.total_bytes > 0 && sf.free_bytes > 0 && sf.free_bytes <= sf.total_bytes);
		CHECK_INT(sf.readonly, 0);
		CHECK_STR(sf.volume, "lagoon");
		CHECK(ops->max_io(fs) >= 4096);
		ops->unmount(fs);
	}
	/* clear text: refused unless allowed; 8-byte passwords only */
	CHECK(!mnt("lagoon8:lagoon-t@", "lagoon", "uam=cleartext", &r));
	CHECK_INT(r, LN_EAUTH);
	fs = mnt("lagoon8:lagoon-t@", "lagoon", "uam=cleartext&cleartext=yes", NULL);
	CHECK(fs != NULL);
	if (fs) ops->unmount(fs);
	/* forcing DHX2 explicitly; DHCAST128 is not offered by this server */
	fs = mnt(USER, "lagoon", "uam=dhx2", NULL);
	CHECK(fs != NULL);
	if (fs) ops->unmount(fs);
	CHECK(!mnt(USER, "lagoon", "uam=dhcast128", &r));
	CHECK_INT(r, LN_EAUTH);

	/* volume password */
	CHECK(!mnt(USER, "secret", "", &r));
	CHECK(r == LN_EACCES || r == LN_EAUTH);
	CHECK(!mnt(USER, "secret", "volpass=nope", &r));
	CHECK_INT(r, LN_EAUTH);
	fs = mnt(USER, "secret", "volpass=lagoonpw", NULL);
	CHECK(fs != NULL);
	if (fs) {
		CHECK_INT(put(fs, "in-secret.txt", "s", 1, 0), LN_OK);
		ops->unmount(fs);
	}

	/* read-only volume */
	fs = mnt(USER, "readonly", "", NULL);
	CHECK(fs != NULL);
	if (fs) {
		CHECK_INT(ops->statfs(fs, &sf), LN_OK);
		CHECK_INT(sf.readonly, 1);
		CHECK_INT(get(fs, "readme.txt", buf, sizeof(buf)), 17);
		CHECK(!memcmp(buf, "read-only volume\n", 17));
		CHECK_INT(ops->mkdir(fs, "x"), LN_EROFS);
		CHECK_INT(put(fs, "new.txt", "x", 1, 0), LN_EROFS);
		ops->unmount(fs);
	}
}

static void t_files(LnFs *fs)
{
	const long big = 3 * 1024 * 1024 + 12345;
	u8 *a = malloc((size_t)big), *b = malloc((size_t)big);
	LnFile *f;
	LnStat st;
	long i, n, off, chunk;
	int r;
	struct stat hs;

	CHECK_INT(ops->mkdir(fs, "t"), LN_OK);
	CHECK_INT(ops->mkdir(fs, "t"), LN_EEXIST);
	CHECK_INT(ops->stat(fs, "t", &st), LN_OK);
	CHECK_INT(st.type, LN_T_DIR);
	CHECK(st.fileid != 0);

	/* big transfer, written in odd-sized pieces, read in others */
	for (i = 0; i < big; i++)
		a[i] = (u8)((i * 2654435761u) >> 13);
	CHECK_INT(ops->open(fs, "t/big.bin", LN_O_WRITE | LN_O_CREATE | LN_O_EXCL, &f), LN_OK);
	for (off = 0, chunk = 1; off < big; off += n, chunk = chunk * 7 % 300001 + 1) {
		n = LN_MIN(chunk, big - off);
		CHECK_INT(ops->write(f, (u64)off, a + off, n), n);
	}
	CHECK_INT(ops->flush(f), LN_OK);
	CHECK_INT(ops->fstat(f, &st), LN_OK);
	CHECK_INT(st.size, big);
	CHECK_INT(ops->close(f), LN_OK);
	memset(b, 0, (size_t)big);
	CHECK_INT(host_read("t/big.bin", b, big, &n), 0);
	CHECK_INT(n, big);
	CHECK(!memcmp(a, b, (size_t)big));
	memset(b, 0, (size_t)big);
	CHECK_INT(ops->open(fs, "t/big.bin", LN_O_READ, &f), LN_OK);
	for (off = 0, chunk = 1000; off < big; off += n) {
		n = ops->read(f, (u64)off, b + off, LN_MIN(chunk, big - off));
		CHECK(n > 0);
		if (n <= 0) break;
		chunk = chunk * 3 % 400000 + 517;
	}
	CHECK(!memcmp(a, b, (size_t)big));
	CHECK_INT(ops->read(f, (u64)big, b, 100), 0);        /* at EOF */
	CHECK_INT(ops->read(f, (u64)big - 10, b, 100), 10);  /* across EOF */
	CHECK(!memcmp(b, a + big - 10, 10));
	CHECK_INT(ops->fstat(f, &st), LN_OK);
	CHECK_INT(st.size, big);
	CHECK_INT(ops->close(f), LN_OK);
	/* one big read in a single call */
	memset(b, 0, (size_t)big);
	CHECK_INT(get(fs, "t/big.bin", b, big), big);
	CHECK(!memcmp(a, b, (size_t)big));

	/* create flags */
	CHECK_INT(ops->open(fs, "t/big.bin", LN_O_WRITE | LN_O_CREATE | LN_O_EXCL, &f), LN_EEXIST);
	CHECK_INT(put(fs, "t/small.txt", "hello world", 11, 0), LN_OK);
	CHECK_INT(put(fs, "t/small.txt", "bye", 3, 0), LN_OK);    /* CREATE|TRUNC on an existing file */
	CHECK_INT(get(fs, "t/small.txt", b, 100), 3);
	CHECK(!memcmp(b, "bye", 3));
	/* read+write handle: write in the middle, read back */
	CHECK_INT(ops->open(fs, "t/small.txt", LN_O_READ | LN_O_WRITE, &f), LN_OK);
	CHECK_INT(ops->write(f, 5, "xy", 2), 2);             /* leaves a hole of zeros */
	CHECK_INT(ops->read(f, 0, b, 100), 7);
	CHECK(!memcmp(b, "bye\0\0xy", 7));
	CHECK_INT(ops->truncate(f, 2), LN_OK);
	CHECK_INT(ops->fstat(f, &st), LN_OK);
	CHECK_INT(st.size, 2);
	CHECK_INT(ops->truncate(f, 100000), LN_OK);
	CHECK_INT(ops->close(f), LN_OK);
	CHECK_INT(host_stat("t/small.txt", &hs), 0);
	CHECK_INT(hs.st_size, 100000);
	memset(&st, 0, sizeof(st));
	st.size = 5;
	CHECK_INT(ops->setattr(fs, "t/small.txt", &st, LN_SET_SIZE), LN_OK);
	CHECK_INT(ops->stat(fs, "t/small.txt", &st), LN_OK);
	CHECK_INT(st.size, 5);
	CHECK_INT(st.type, LN_T_FILE);

	/* errors */
	CHECK_INT(ops->open(fs, "t/nothere", LN_O_READ, &f), LN_ENOENT);
	CHECK_INT(ops->open(fs, "nodir/x", LN_O_WRITE | LN_O_CREATE, &f), LN_ENOENT);
	CHECK_INT(ops->open(fs, "t", LN_O_READ, &f), LN_EISDIR);
	CHECK_INT(ops->stat(fs, "t/nothere", &st), LN_ENOENT);
	CHECK_INT(ops->stat(fs, "t/small.txt/x", &st), LN_ENOENT);
	{
		LnDir *d;
		CHECK_INT(ops->opendir(fs, "t/small.txt", &d), LN_ENOTDIR);
		CHECK_INT(ops->opendir(fs, "t/none", &d), LN_ENOENT);
	}
	CHECK_INT(ops->remove(fs, "t"), LN_ENOTEMPTY);
	CHECK_INT(ops->remove(fs, "t/nothere"), LN_ENOENT);
	CHECK_INT(ops->mkdir(fs, "t/small.txt"), LN_EEXIST);
	r = ops->remove(fs, "");
	CHECK(r < 0);
	free(a);
	free(b);
}

static void t_names(LnFs *fs)
{
	/* NFC in Lagoon, NFD on the wire, NFC on the Linux disk (netatalk) */
	static const char *names[] = {
		"Caf\xc3\xa9 \xc3\xbc.txt",                          /* Café ü.txt */
		"\xc3\x85ngstr\xc3\xb6m \xe2\x9c\x93 \xe6\x97\xa5\xe6\x9c\xac.txt", /* Ångström ✓ 日本 */
		"spaces and (parens) & more.txt"
	};
	int i, found, r;
	LnStat st;
	char p[256];
	struct stat hs;
	CHECK_INT(ops->mkdir(fs, "u"), LN_OK);
	CHECK_INT(ops->mkdir(fs, "u/D\xc3\xbcr"), LN_OK);              /* Dür */
	for (i = 0; i < 3; i++) {
		snprintf(p, sizeof(p), "u/D\xc3\xbcr/%s", names[i]);
		CHECK_INT(put(fs, p, names[i], (long)strlen(names[i]), 0), LN_OK);
		CHECK_INT(ops->stat(fs, p, &st), LN_OK);
		CHECK_INT(st.size, strlen(names[i]));
		CHECK_INT(host_stat(p, &hs), 0);
		CHECK_INT(count_dir(fs, "u/D\xc3\xbcr", names[i], &found), i + 1);
		CHECK(found);
	}
	/* a name that came from the Linux side in NFD reads back as NFC */
	{
		char hp[512];
		FILE *f;
		snprintf(hp, sizeof(hp), "%s/vol/u/Re\xcc\x81sume\xcc\x81.txt", dir);
		f = fopen(hp, "w");
		if (f) { fputs("nfd", f); fclose(f); }
		r = count_dir(fs, "u", "R\xc3\xa9sum\xc3\xa9.txt", &found);
		CHECK_INT(r, 2);
		CHECK(found);
	}
	/* rename: never over an existing name, across directories, case only */
	snprintf(p, sizeof(p), "u/D\xc3\xbcr/%s", names[0]);
	{
		char q[256];
		snprintf(q, sizeof(q), "u/D\xc3\xbcr/%s", names[1]);
		CHECK_INT(ops->rename(fs, p, q), LN_EEXIST);
		CHECK_INT(ops->stat(fs, p, &st), LN_OK);
		CHECK_INT(ops->rename(fs, p, "u/moved \xc3\xa9.txt"), LN_OK);
		CHECK_INT(ops->stat(fs, p, &st), LN_ENOENT);
		CHECK_INT(ops->stat(fs, "u/moved \xc3\xa9.txt", &st), LN_OK);
		CHECK_INT(ops->rename(fs, "u/moved \xc3\xa9.txt", "u/MOVED \xc3\x89.txt"), LN_OK);
		CHECK_INT(host_stat("u/MOVED \xc3\x89.txt", &hs), 0);
		CHECK_INT(ops->rename(fs, "u/D\xc3\xbcr", "u/Dir2"), LN_OK);
		CHECK_INT(count_dir(fs, "u/Dir2", NULL, NULL), 2);
		CHECK_INT(ops->rename(fs, "u/nothere", "u/x"), LN_ENOENT);
		CHECK_INT(ops->rename(fs, "u/Dir2", "u/Dir2/sub"), LN_EINVAL);
	}
}

static void t_attrs(LnFs *fs)
{
	LnStat st;
	struct stat hs;
	LnFile *f;
	CHECK_INT(put(fs, "a.txt", "attr", 4, 0), LN_OK);
	/* modification time */
	memset(&st, 0, sizeof(st));
	st.mtime = 1234567890;
	CHECK_INT(ops->setattr(fs, "a.txt", &st, LN_SET_MTIME), LN_OK);
	CHECK_INT(ops->stat(fs, "a.txt", &st), LN_OK);
	CHECK_INT(st.mtime, 1234567890);
	CHECK_INT(host_stat("a.txt", &hs), 0);
	CHECK_INT(hs.st_mtime, 1234567890);
	st.mtime = 1700000000;
	CHECK_INT(ops->setattr(fs, "t", &st, LN_SET_MTIME), LN_OK);
	CHECK_INT(ops->stat(fs, "t", &st), LN_OK);
	CHECK_INT(st.mtime, 1700000000);
	/* UNIX mode */
	CHECK_INT(ops->stat(fs, "a.txt", &st), LN_OK);
	CHECK(st.mode != 0);
	CHECK_INT(st.uid, hs.st_uid);
	st.mode = 0640;
	CHECK_INT(ops->setattr(fs, "a.txt", &st, LN_SET_MODE), LN_OK);
	CHECK_INT(host_stat("a.txt", &hs), 0);
	CHECK_INT(hs.st_mode & 07777, 0640);
	CHECK_INT(ops->stat(fs, "a.txt", &st), LN_OK);
	CHECK_INT(st.mode & 07777, 0640);
	CHECK(st.prot & LN_P_READ);
	CHECK(st.prot & LN_P_WRITE);
	CHECK(!(st.prot & LN_P_EXEC));
	st.mode = 0755;
	CHECK_INT(ops->setattr(fs, "a.txt", &st, LN_SET_MODE), LN_OK);
	CHECK_INT(ops->stat(fs, "a.txt", &st), LN_OK);
	CHECK(st.prot & LN_P_EXEC);
	/* hidden <-> Invisible */
	st.prot = LN_P_READ | LN_P_WRITE | LN_P_DELETE | LN_P_HIDDEN;
	CHECK_INT(ops->setattr(fs, "a.txt", &st, LN_SET_PROT), LN_OK);
	CHECK_INT(ops->stat(fs, "a.txt", &st), LN_OK);
	CHECK(st.prot & LN_P_HIDDEN);
	CHECK(st.prot & LN_P_DELETE);
	/* delete protection <-> DeleteInhibit/RenameInhibit */
	st.prot = LN_P_READ | LN_P_WRITE;
	CHECK_INT(ops->setattr(fs, "a.txt", &st, LN_SET_PROT), LN_OK);
	CHECK_INT(ops->stat(fs, "a.txt", &st), LN_OK);
	CHECK(!(st.prot & LN_P_DELETE));
	CHECK(!(st.prot & LN_P_HIDDEN));
	CHECK_INT(ops->remove(fs, "a.txt"), LN_EACCES);
	CHECK_INT(ops->rename(fs, "a.txt", "b.txt"), LN_EACCES);
	/* write protection <-> WriteInhibit */
	st.prot = LN_P_READ | LN_P_DELETE;
	CHECK_INT(ops->setattr(fs, "a.txt", &st, LN_SET_PROT), LN_OK);
	CHECK_INT(ops->stat(fs, "a.txt", &st), LN_OK);
	CHECK(!(st.prot & LN_P_WRITE));
	CHECK(st.prot & LN_P_DELETE);
	CHECK_INT(ops->open(fs, "a.txt", LN_O_WRITE, &f), LN_EACCES);
	st.prot = LN_P_READ | LN_P_WRITE | LN_P_DELETE;
	CHECK_INT(ops->setattr(fs, "a.txt", &st, LN_SET_PROT), LN_OK);
	CHECK_INT(ops->stat(fs, "a.txt", &st), LN_OK);
	CHECK(st.prot & LN_P_WRITE);
	CHECK_INT(put(fs, "a.txt", "writable", 8, 0), LN_OK);
	/* Finder comments (Amiga file notes) */
	strcpy(st.comment, "An Amiga file note \xe2\x9c\x93");
	CHECK_INT(ops->setattr(fs, "a.txt", &st, LN_SET_COMMENT), LN_OK);
	memset(&st, 0, sizeof(st));
	CHECK_INT(ops->stat(fs, "a.txt", &st), LN_OK);
	CHECK_STR(st.comment, "An Amiga file note \xe2\x9c\x93");
	CHECK_INT(ops->open(fs, "a.txt", LN_O_READ, &f), LN_OK);
	memset(&st, 0, sizeof(st));
	CHECK_INT(ops->fstat(f, &st), LN_OK);
	CHECK_STR(st.comment, "An Amiga file note \xe2\x9c\x93");
	CHECK_INT(st.size, 8);
	ops->close(f);
	st.comment[0] = 0;
	CHECK_INT(ops->setattr(fs, "a.txt", &st, LN_SET_COMMENT), LN_OK);
	CHECK_INT(ops->stat(fs, "a.txt", &st), LN_OK);
	CHECK_STR(st.comment, "");
	strcpy(st.comment, "dir note");
	CHECK_INT(ops->setattr(fs, "t", &st, LN_SET_COMMENT), LN_OK);
	CHECK_INT(ops->stat(fs, "t", &st), LN_OK);
	CHECK_STR(st.comment, "dir note");
	CHECK_INT(ops->remove(fs, "a.txt"), LN_OK);
}

static void t_bigdir(LnFs *fs)
{
	char p[512];
	int i, n, found;
	snprintf(p, sizeof(p), "%s/vol/many", dir);
	mkdir(p, 0777);
	for (i = 0; i < 700; i++) {
		FILE *f;
		snprintf(p, sizeof(p), "%s/vol/many/file-%04d-with-a-longish-name.dat", dir, i);
		if ((f = fopen(p, "w"))) fclose(f);
	}
	snprintf(p, sizeof(p), "%s/vol/many/.AppleDouble", dir);
	mkdir(p, 0777);
	n = count_dir(fs, "many", "file-0699-with-a-longish-name.dat", &found);
	CHECK_INT(n, 700);
	CHECK(found);
	CHECK_INT(count_dir(fs, "many", ".AppleDouble", &found), 700);
	CHECK(!found);
}

static void t_reconnect(void)
{
	LnFs *fs = mnt(USER, "lagoon", "", NULL), *idle;
	LnFile *f;
	LnStat st;
	u8 buf[32];
	int r, i;
	char cmd[256];
	if (!fs)
		return;
	CHECK_INT(ops->ping(fs), LN_OK);
	CHECK_INT(ops->open(fs, "re.txt", LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC, &f), LN_OK);
	CHECK_INT(ops->write(f, 0, "before", 6), 6);
	/* kill every session process of the server: the connection drops */
	snprintf(cmd, sizeof(cmd), "pkill -9 -P $(cat %s/netatalk.pid)", dir);
	CHECK_INT(system(cmd), 0);
	usleep(300000);
	r = ops->stat(fs, "re.txt", &st);
	CHECK_INT(r, LN_ECONNRESET);
	CHECK_INT(ops->write(f, 6, "x", 1), LN_ECONNRESET);
	CHECK_INT(ops->reconnect(fs), LN_OK);
	/* the open file was reopened by path */
	CHECK_INT(ops->write(f, 6, "-after", 6), 6);
	CHECK_INT(ops->read(f, 0, buf, sizeof(buf)), 12);
	CHECK(!memcmp(buf, "before-after", 12));
	CHECK_INT(ops->close(f), LN_OK);
	CHECK_INT(ops->stat(fs, "re.txt", &st), LN_OK);
	CHECK_INT(st.size, 12);

	/* tickles: the server (tickleval 2, timeout 3) drops clients that
	 * stay quiet for 6 s; ping() every 2 s keeps fs alive, idle dies */
	idle = mnt(USER, "lagoon", "", NULL);
	CHECK(idle != NULL);
	for (i = 0; i < 5; i++) {
		sleep(2);
		CHECK_INT(ops->ping(fs), LN_OK);
	}
	if (idle) {
		r = ops->stat(idle, "re.txt", &st);
		CHECK_INT(r, LN_ECONNRESET);
		CHECK_INT(ops->reconnect(idle), LN_OK);
		CHECK_INT(ops->stat(idle, "re.txt", &st), LN_OK);
		ops->unmount(idle);
	}
	CHECK_INT(ops->stat(fs, "re.txt", &st), LN_OK);
	CHECK_INT(ops->remove(fs, "re.txt"), LN_OK);
	/* SIGUSR1 makes afpd announce a shutdown in 5 minutes with a
	 * DSIAttention: it is acknowledged and the session goes on */
	snprintf(cmd, sizeof(cmd), "pkill -USR1 -P $(cat %s/netatalk.pid)", dir);
	CHECK_INT(system(cmd), 0);
	usleep(300000);
	CHECK_INT(ops->ping(fs), LN_OK);
	CHECK_INT(ops->stat(fs, "", &st), LN_OK);
	CHECK_INT(ops->ping(fs), LN_OK);
	ops->unmount(fs);
}

static void cleanup_tree(LnFs *fs)
{
	char p[512];
	int i;
	for (i = 0; i < 700; i++) {
		snprintf(p, sizeof(p), "many/file-%04d-with-a-longish-name.dat", i);
		ops->remove(fs, p);
	}
}

int main(void)
{
	LnFs *fs;
	char cmd[512];
	const char *s = getenv("S");
	int r;
	if (geteuid() != 0)
		T_SKIP("t_afp_netatalk", "needs root to run afpd");
	if (system("command -v afpd >/dev/null 2>&1") != 0)
		T_SKIP("t_afp_netatalk", "netatalk (afpd) not installed");
	strcpy(dir, "/tmp/lagoon-afp.XXXXXX");
	if (!mkdtemp(dir))
		T_SKIP("t_afp_netatalk", "mkdtemp");
	chmod(dir, 0755);
	snprintf(cmd, sizeof(cmd), "AFP_TICKLE=2 tests/servers/afp/netatalk.sh start %s " PORT " >/dev/null", dir);
	r = system(cmd);
	if (r != 0) {
		sh("tests/servers/afp/netatalk.sh stop %s", dir);
		T_SKIP("t_afp_netatalk", "could not start netatalk");
	}
	ln_net_init();
	ops = ln_vfs_find("afp");
	CHECK(ops != NULL);

	t_shares_and_logins();
	fs = mnt(USER, "lagoon", "", NULL);
	CHECK(fs != NULL);
	if (fs) {
		t_files(fs);
		t_names(fs);
		t_attrs(fs);
		t_bigdir(fs);
		cleanup_tree(fs);
		ops->unmount(fs);
	}
	t_reconnect();
	/* a mount below a subdirectory of the volume */
	fs = mnt(USER, "lagoon/t", "", NULL);
	CHECK(fs != NULL);
	if (fs) {
		LnStat st;
		CHECK_INT(ops->stat(fs, "small.txt", &st), LN_OK);
		CHECK_INT(st.size, 5);
		ops->unmount(fs);
	}

	sh("tests/servers/afp/netatalk.sh stop %s", dir);
	/* keep the tree for inspection: move it aside, never delete */
	snprintf(cmd, sizeof(cmd), "mkdir -p '%s/trash' && mv %s '%s/trash/'", s && *s ? s : "/tmp/lagoon",
	         dir, s && *s ? s : "/tmp/lagoon");
	if (system(cmd) != 0)
		fprintf(stderr, "left %s\n", dir);
	ln_net_exit();
	T_DONE("t_afp_netatalk");
}
