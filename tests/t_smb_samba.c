/* Lagoon - SMB backend against a real Samba (tests/servers/smb): every
 * LnOps call over each dialect / signing / encryption variant, big files
 * with byte compares (also on the host file system), unicode and NFD
 * names (vfs_fruit share), error mapping, read-only, encrypted and guest
 * shares, list_shares, statfs, large directories, reconnect after the
 * server drops the connection. Exit 77 if smbd cannot run (needs root).
 * SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "testutil.h"
#include "ln_vfs.h"
#include "ln_sys.h"
#include "ln_net.h"
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static char dir[64];
static int port, port2;
static const LnOps *ops;

static int port_free(int p)
{
	struct sockaddr_in sa;
	int fd = socket(AF_INET, SOCK_STREAM, 0), ok;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((u16)p);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ok = bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
	close(fd);
	return ok;
}

static void stop_servers(void)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "tests/servers/smb/stop.sh %s; tests/servers/smb/stop.sh %s/sig", dir, dir);
	if (system(cmd)) { /* ignore */ }
}

static int start_server(const char *d, int p, const char *signing)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "tests/servers/smb/start.sh %s %d 127.0.0.1 %s >/dev/null 2>&1", d, p, signing);
	return system(cmd);
}

/* kill the per-connection smbd children: the client sees the connection drop */
static void drop_connections(void)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "pkill -P $(cat %s/run/smbd.pid) -f \"^smbd: client\"", dir);
	if (system(cmd)) { /* ignore */ }
	{ struct timespec ts = { 0, 300000000 }; nanosleep(&ts, NULL); }
}

static LnFs *mnt(const char *share, const char *opts, const char *user, int *err)
{
	char url[300];
	LnFs *fs = NULL;
	int r;
	snprintf(url, sizeof(url), "smb://%s127.0.0.1:%d/%s%s", user ? user : "lagoon:lagoon-test-pw@", port, share,
	         opts ? opts : "");
	r = ln_vfs_mount_url(url, NULL, &ops, &fs);
	if (err)
		*err = r;
	else if (r)
		fprintf(stderr, "mount %s: %s\n", url, ln_strerror(r));
	return r ? NULL : fs;
}

static void fill(u8 *b, size_t n, u32 seed)
{
	size_t i;
	for (i = 0; i < n; i++) {
		seed = seed * 1103515245u + 12345u;
		b[i] = (u8)(seed >> 16);
	}
}

static int host_cmp(const char *rel, const u8 *data, size_t n)
{
	char p[512];
	FILE *f;
	u8 *b;
	size_t got;
	int ok;
	snprintf(p, sizeof(p), "%s/%s", dir, rel);
	f = fopen(p, "rb");
	if (!f) return 0;
	b = malloc(n + 1);
	got = fread(b, 1, n + 1, f);
	fclose(f);
	ok = got == n && !memcmp(b, data, n);
	free(b);
	return ok;
}

static int write_all(LnFs *fs, const char *path, int flags, const u8 *d, size_t n)
{
	LnFile *f;
	size_t off = 0;
	long chunk = ops->max_io(fs);
	int r = ops->open(fs, path, flags, &f);
	if (r) return r;
	while (off < n) {
		long w = ops->write(f, off, d + off, (long)LN_MIN((size_t)chunk, n - off));
		if (w <= 0) { ops->close(f); return w < 0 ? (int)w : LN_EIO; }
		off += (size_t)w;
	}
	return ops->close(f);
}

static int read_cmp(LnFs *fs, const char *path, const u8 *d, size_t n)
{
	LnFile *f;
	u8 *b = malloc(n + 100);
	long got, total = 0;
	int r = ops->open(fs, path, LN_O_READ, &f), ok;
	if (r) { free(b); return 0; }
	/* odd chunk size to exercise splitting */
	while ((got = ops->read(f, (u64)total, b + total, 100000)) > 0 && total < (long)n + 100)
		total += got;
	ops->close(f);
	ok = got == 0 && total == (long)n && !memcmp(b, d, n);
	free(b);
	return ok;
}

static int count_dir(LnFs *fs, const char *path, const char *want, LnStat *wst)
{
	LnDir *d;
	char name[256];
	LnStat st;
	int n = 0, r;
	if (ops->opendir(fs, path, &d)) return -1;
	while ((r = ops->readdir(d, name, sizeof(name), &st)) > 0) {
		n++;
		if (want && !strcmp(name, want) && wst) *wst = st;
		CHECK(strcmp(name, ".") && strcmp(name, ".."));
	}
	ops->closedir(d);
	return r < 0 ? r : n;
}

/* the full LnOps workout in directory "base" */
static void file_ops(LnFs *fs, const char *base, const char *hostbase)
{
	static u8 big[1536 * 1024 + 123];
	char p[256], q[256], h[256];
	LnStat st;
	LnStatFs sf;
	LnFile *f;
	u8 buf[256];
	int r;

	fill(big, sizeof(big), (u32)strlen(base));
	CHECK_INT(ops->ping(fs), 0);
	CHECK_INT(ops->mkdir(fs, base), 0);
	CHECK_INT(ops->mkdir(fs, base), LN_EEXIST);
	CHECK_INT(ops->stat(fs, base, &st), 0);
	CHECK_INT(st.type, LN_T_DIR);

	/* big file */
	snprintf(p, sizeof(p), "%s/big.bin", base);
	CHECK_INT(write_all(fs, p, LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC, big, sizeof(big)), 0);
	CHECK(read_cmp(fs, p, big, sizeof(big)));
	snprintf(h, sizeof(h), "%s/big.bin", hostbase);
	if (hostbase[0]) CHECK(host_cmp(h, big, sizeof(big)));
	CHECK_INT(ops->stat(fs, p, &st), 0);
	CHECK_INT(st.type, LN_T_FILE);
	CHECK_INT(st.size, sizeof(big));
	CHECK(st.mtime > 1600000000u);
	CHECK(st.prot & LN_P_WRITE);

	/* positional I/O, fstat, truncate, flush, read past EOF */
	CHECK_INT(ops->open(fs, p, LN_O_READ | LN_O_WRITE, &f), 0);
	if (f) {
		CHECK_INT(ops->read(f, 1000000, buf, 200), 200);
		CHECK(!memcmp(buf, big + 1000000, 200));
		CHECK_INT(ops->write(f, 5, "HELLO", 5), 5);
		CHECK_INT(ops->read(f, 3, buf, 9), 9);
		CHECK(!memcmp(buf + 2, "HELLO", 5));
		CHECK_INT(ops->truncate(f, 70000), 0);
		CHECK_INT(ops->fstat(f, &st), 0);
		CHECK_INT(st.size, 70000);
		CHECK_INT(ops->read(f, 69990, buf, 100), 10);
		CHECK_INT(ops->read(f, 80000, buf, 100), 0);
		CHECK_INT(ops->flush(f), 0);
		CHECK_INT(ops->close(f), 0);
	}
	CHECK_INT(ops->open(fs, p, LN_O_WRITE | LN_O_CREATE | LN_O_EXCL, &f), LN_EEXIST);
	CHECK_INT(ops->open(fs, base, LN_O_READ, &f), LN_EISDIR);
	snprintf(q, sizeof(q), "%s/nothere", base);
	CHECK_INT(ops->open(fs, q, LN_O_READ, &f), LN_ENOENT);
	CHECK_INT(ops->stat(fs, q, &st), LN_ENOENT);
	snprintf(q, sizeof(q), "%s/nothere/deeper", base);
	CHECK_INT(ops->stat(fs, q, &st), LN_ENOENT);
	{
		LnDir *d;
		CHECK_INT(ops->opendir(fs, p, &d), LN_ENOTDIR);
	}

	/* unicode names: Latin-1, beyond Latin-1, CJK */
	snprintf(q, sizeof(q), "%s/Gr\xc3\xbc\xc3\x9f" "e \xe2\x82\xac \xe6\x97\xa5\xe6\x9c\xac.txt", base);
	CHECK_INT(write_all(fs, q, LN_O_WRITE | LN_O_CREATE, (const u8 *)"unicode", 7), 0);
	CHECK(read_cmp(fs, q, (const u8 *)"unicode", 7));
	CHECK_INT(count_dir(fs, base, "Gr\xc3\xbc\xc3\x9f" "e \xe2\x82\xac \xe6\x97\xa5\xe6\x9c\xac.txt", &st), 2);
	CHECK_INT(st.size, 7);

	/* rename: ok, onto existing (must not overwrite), missing source, into subdir */
	snprintf(h, sizeof(h), "%s/renamed.bin", base);
	CHECK_INT(ops->rename(fs, p, h), 0);
	CHECK_INT(ops->stat(fs, p, &st), LN_ENOENT);
	CHECK_INT(ops->rename(fs, h, q), LN_EEXIST);
	CHECK_INT(ops->stat(fs, q, &st), 0);
	CHECK_INT(st.size, 7);
	CHECK_INT(ops->rename(fs, p, h), LN_ENOENT);
	snprintf(p, sizeof(p), "%s/sub", base);
	CHECK_INT(ops->mkdir(fs, p), 0);
	snprintf(p, sizeof(p), "%s/sub/moved.bin", base);
	CHECK_INT(ops->rename(fs, h, p), 0);
	CHECK_INT(ops->stat(fs, p, &st), 0);
	CHECK_INT(st.size, 70000);

	/* setattr: mtime, read-only (delete protected), hidden, archive */
	memset(&st, 0, sizeof(st));
	st.mtime = 1234567890u;
	CHECK_INT(ops->setattr(fs, p, &st, LN_SET_MTIME), 0);
	CHECK_INT(ops->stat(fs, p, &st), 0);
	CHECK_INT(st.mtime, 1234567890u);
	st.prot = LN_P_READ | LN_P_EXEC | LN_P_HIDDEN;   /* -w -d, hidden, not archived */
	CHECK_INT(ops->setattr(fs, p, &st, LN_SET_PROT), 0);
	CHECK_INT(ops->stat(fs, p, &st), 0);
	CHECK(!(st.prot & LN_P_WRITE));
	CHECK(!(st.prot & LN_P_DELETE));
	CHECK(st.prot & LN_P_HIDDEN);
	CHECK(!(st.prot & LN_P_ARCHIVE));
	CHECK_INT(st.mtime, 1234567890u);
	CHECK_INT(ops->remove(fs, p), LN_EACCES);
	CHECK_INT(ops->open(fs, p, LN_O_WRITE, &f), LN_EACCES);
	st.prot = LN_P_READ | LN_P_WRITE | LN_P_EXEC | LN_P_DELETE | LN_P_ARCHIVE;
	CHECK_INT(ops->setattr(fs, p, &st, LN_SET_PROT), 0);
	CHECK_INT(ops->stat(fs, p, &st), 0);
	CHECK(st.prot & LN_P_WRITE);
	CHECK(!(st.prot & LN_P_HIDDEN));
	CHECK(st.prot & LN_P_ARCHIVE);
	st.size = 10;
	CHECK_INT(ops->setattr(fs, p, &st, LN_SET_SIZE), 0);
	CHECK_INT(ops->stat(fs, p, &st), 0);
	CHECK_INT(st.size, 10);
	CHECK_INT(ops->setattr(fs, p, &st, LN_SET_COMMENT), LN_ENOTSUP);

	/* remove: non-empty dir, missing, then everything */
	snprintf(q, sizeof(q), "%s/sub", base);
	CHECK_INT(ops->remove(fs, q), LN_ENOTEMPTY);
	snprintf(h, sizeof(h), "%s/gone", base);
	CHECK_INT(ops->remove(fs, h), LN_ENOENT);
	CHECK_INT(ops->remove(fs, p), 0);
	CHECK_INT(ops->remove(fs, q), 0);
	snprintf(q, sizeof(q), "%s/Gr\xc3\xbc\xc3\x9f" "e \xe2\x82\xac \xe6\x97\xa5\xe6\x9c\xac.txt", base);
	CHECK_INT(ops->remove(fs, q), 0);
	CHECK_INT(count_dir(fs, base, NULL, NULL), 0);
	CHECK_INT(ops->remove(fs, base), 0);

	r = ops->statfs(fs, &sf);
	CHECK_INT(r, 0);
	CHECK(sf.total_bytes > 0 && sf.free_bytes > 0 && sf.free_bytes <= sf.total_bytes);
	CHECK(sf.block_size > 0);
	CHECK(!sf.readonly);
	CHECK(ops->max_io(fs) >= 4096);
}

static void variants(void)
{
	static const char *const v[] = {
		"", "?dialect=3.0.2", "?dialect=3.0", "?dialect=2.1", "?dialect=2.0.2",
		"?dialect=2.1&sign=required", "?dialect=3.0&sign=required", "?gmac=no",
		"?encrypt=yes", "?encrypt=yes&cipher=ccm", "?encrypt=yes&cipher=gcm256", "?dialect=3.0&encrypt=yes",
		"?io=4096"
	};
	int i;
	for (i = 0; i < (int)LN_ARRAY_SIZE(v); i++) {
		LnFs *fs = mnt("plain", v[i], NULL, NULL);
		char base[32], hb[64];
		int f0 = t_fail;
		CHECK(fs != NULL);
		if (!fs) continue;
		snprintf(base, sizeof(base), "v%d", i);
		snprintf(hb, sizeof(hb), "plain/v%d", i);
		file_ops(fs, base, hb);
		ops->unmount(fs);
		printf("t_smb_samba: variant \"%s\" %s\n", v[i], t_fail == f0 ? "ok" : "FAILED");
	}
}

static void subdir_url(void)
{
	/* smb://host/share/sub: paths are relative to the subdirectory */
	LnFs *fs = mnt("plain", NULL, NULL, NULL);
	LnStat st;
	if (!fs) { CHECK(0); return; }
	CHECK_INT(ops->mkdir(fs, "top"), 0);
	CHECK_INT(write_all(fs, "top/in.txt", LN_O_WRITE | LN_O_CREATE, (const u8 *)"x", 1), 0);
	ops->unmount(fs);
	fs = mnt("plain/top", NULL, NULL, NULL);
	if (!fs) { CHECK(0); return; }
	CHECK_INT(ops->stat(fs, "in.txt", &st), 0);
	CHECK_INT(count_dir(fs, "", NULL, NULL), 1);
	CHECK_INT(ops->remove(fs, "in.txt"), 0);
	ops->unmount(fs);
	fs = mnt("plain", NULL, NULL, NULL);
	if (!fs) { CHECK(0); return; }
	CHECK_INT(ops->remove(fs, "top"), 0);
	ops->unmount(fs);
}

static void big_dir(void)
{
	LnFs *fs = mnt("plain", NULL, NULL, NULL);
	char p[64];
	int i, n = 1200;
	LnStat st;
	if (!fs) { CHECK(0); return; }
	CHECK_INT(ops->mkdir(fs, "many"), 0);
	for (i = 0; i < n; i++) {
		snprintf(p, sizeof(p), "many/file-with-a-longish-name-%05d.txt", i);
		if (write_all(fs, p, LN_O_WRITE | LN_O_CREATE, (const u8 *)p, (size_t)i % 50)) { CHECK(0); break; }
	}
	CHECK_INT(count_dir(fs, "many", "file-with-a-longish-name-00049.txt", &st), n);
	CHECK_INT(st.size, 49);
	for (i = 0; i < n; i++) {
		snprintf(p, sizeof(p), "many/file-with-a-longish-name-%05d.txt", i);
		if (ops->remove(fs, p)) { CHECK(0); break; }
	}
	CHECK_INT(ops->remove(fs, "many"), 0);
	ops->unmount(fs);
}

static void other_shares(void)
{
	LnFs *fs;
	LnFile *f;
	LnStat st;
	LnStatFs sf;
	int err;
	u8 b[64];

	/* read-only share */
	fs = mnt("readonly", NULL, NULL, NULL);
	CHECK(fs != NULL);
	if (fs) {
		CHECK_INT(ops->stat(fs, "hello.txt", &st), 0);
		CHECK(read_cmp(fs, "hello.txt", (const u8 *)"read only file\n", 15));
		CHECK(ops->open(fs, "hello.txt", LN_O_WRITE, &f) < 0);
		CHECK(ops->mkdir(fs, "x") < 0);
		CHECK(ops->remove(fs, "hello.txt") < 0);
		CHECK_INT(ops->statfs(fs, &sf), 0);
		CHECK_INT(sf.readonly, 1);
		ops->unmount(fs);
	}
	/* share-level encryption is picked up automatically */
	fs = mnt("encrypted", NULL, NULL, NULL);
	CHECK(fs != NULL);
	if (fs) {
		file_ops(fs, "enc", "encrypted/enc");
		ops->unmount(fs);
	}
	fs = mnt("encrypted", "?dialect=2.1", NULL, &err);
	CHECK(fs == NULL);
	if (fs) ops->unmount(fs);
	/* macOS emulation (vfs_fruit): AAPL context, NFD names from the server come back NFC */
	fs = mnt("fruit", NULL, NULL, NULL);
	CHECK(fs != NULL);
	if (fs) {
		char p[512];
		FILE *hf;
		LnDir *d;
		char name[256];
		int found = 0;
		file_ops(fs, "mac", "fruit/mac");
		snprintf(p, sizeof(p), "%s/fruit/Cafe\xcc\x81.txt", dir);      /* NFD "Café.txt" */
		hf = fopen(p, "w");
		if (hf) { fputs("nfd", hf); fclose(hf); }
		CHECK_INT(ops->opendir(fs, "", &d), 0);
		while (ops->readdir(d, name, sizeof(name), &st) > 0)
			if (!strcmp(name, "Caf\xc3\xa9.txt")) found = 1;
		ops->closedir(d);
		CHECK(found);
		ops->unmount(fs);
		unlink(p);
	}
	/* guest / anonymous */
	fs = mnt("guest", NULL, "", NULL);
	CHECK(fs != NULL);
	if (fs) {
		CHECK_INT(write_all(fs, "g.txt", LN_O_WRITE | LN_O_CREATE, (const u8 *)"guest", 5), 0);
		CHECK(read_cmp(fs, "g.txt", (const u8 *)"guest", 5));
		CHECK_INT(ops->remove(fs, "g.txt"), 0);
		ops->unmount(fs);
	}
	fs = mnt("guest", "?sign=required", "", &err);
	CHECK_INT(err, LN_EAUTH);
	if (fs) ops->unmount(fs);
	fs = mnt("plain", NULL, "", &err);
	CHECK(fs == NULL && (err == LN_EACCES || err == LN_EAUTH));
	if (fs) ops->unmount(fs);
	/* bad password, missing share */
	fs = mnt("plain", NULL, "lagoon:wrong@", &err);
	CHECK_INT(err, LN_EAUTH);
	if (fs) ops->unmount(fs);
	fs = mnt("nosuchshare", NULL, NULL, &err);
	CHECK_INT(err, LN_ENOSHARE);
	if (fs) ops->unmount(fs);
	/* domain in the URL (WORKGROUP;user) is accepted by a standalone server */
	fs = mnt("plain", NULL, "LAGOON;lagoon:lagoon-test-pw@", NULL);
	CHECK(fs != NULL);
	if (fs) ops->unmount(fs);
	(void)b;
}

typedef struct { int n, plain, hidden, ipc; } ShareSeen;
static void share_cb(void *ud, const char *name, const char *comment)
{
	ShareSeen *s = ud;
	s->n++;
	if (!strcmp(name, "plain")) { s->plain = 1; CHECK_STR(comment, "Plain share"); }
	if (!strcmp(name, "hidden$")) s->hidden = 1;
	if (!strcmp(name, "IPC$")) s->ipc = 1;
}

static void shares(void)
{
	LnUrl u;
	LnCreds c;
	ShareSeen s;
	char url[128];
	memset(&c, 0, sizeof(c));
	strcpy(c.user, "lagoon");
	strcpy(c.password, "lagoon-test-pw");
	snprintf(url, sizeof(url), "smb://127.0.0.1:%d/", port);
	CHECK_INT(ln_url_parse(url, &u), 0);
	memset(&s, 0, sizeof(s));
	CHECK_INT(ops->list_shares(&u, &c, share_cb, &s), 0);
	CHECK_INT(s.n, 5);
	CHECK(s.plain && !s.hidden && !s.ipc);
	snprintf(url, sizeof(url), "smb://127.0.0.1:%d/?hidden=yes&dialect=3.0", port);
	CHECK_INT(ln_url_parse(url, &u), 0);
	memset(&s, 0, sizeof(s));
	CHECK_INT(ops->list_shares(&u, &c, share_cb, &s), 0);
	CHECK(s.plain && s.hidden && s.ipc);
	/* anonymous enumeration */
	memset(&c, 0, sizeof(c));
	snprintf(url, sizeof(url), "smb://127.0.0.1:%d/", port);
	CHECK_INT(ln_url_parse(url, &u), 0);
	memset(&s, 0, sizeof(s));
	CHECK_INT(ops->list_shares(&u, &c, share_cb, &s), 0);
	CHECK(s.plain);
}

static void reconnect(const char *opts)
{
	static u8 data[300000];
	LnFs *fs = mnt("plain", opts, NULL, NULL);
	LnFile *f = NULL;
	LnDir *d = NULL;
	LnStat st;
	char name[256];
	long w;
	int r, n = 0;
	if (!fs) { CHECK(0); return; }
	fill(data, sizeof(data), 7);
	CHECK_INT(ops->mkdir(fs, "rc"), 0);
	CHECK_INT(write_all(fs, "rc/a", LN_O_WRITE | LN_O_CREATE, data, 10), 0);
	CHECK_INT(write_all(fs, "rc/b", LN_O_WRITE | LN_O_CREATE, data, 10), 0);
	CHECK_INT(ops->open(fs, "rc/file.bin", LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC, &f), 0);
	CHECK_INT(ops->write(f, 0, data, 150000), 150000);
	CHECK_INT(ops->opendir(fs, "rc", &d), 0);
	CHECK_INT(ops->readdir(d, name, sizeof(name), &st), 1);
	drop_connections();
	w = ops->write(f, 150000, data + 150000, 150000);
	CHECK_INT(w, LN_ECONNRESET);
	CHECK_INT(ops->ping(fs), LN_ECONNRESET);
	CHECK_INT(ops->reconnect(fs), 0);
	/* the handler retries: same LnFile, reopened by path, without truncation */
	CHECK_INT(ops->write(f, 150000, data + 150000, 150000), 150000);
	CHECK_INT(ops->close(f), 0);
	CHECK(read_cmp(fs, "rc/file.bin", data, sizeof(data)));
	/* the directory listing continues where it was */
	while ((r = ops->readdir(d, name, sizeof(name), &st)) > 0) n++;
	CHECK_INT(r, 0);
	CHECK_INT(n, 2);
	ops->closedir(d);
	CHECK_INT(ops->remove(fs, "rc/file.bin"), 0);
	CHECK_INT(ops->remove(fs, "rc/a"), 0);
	CHECK_INT(ops->remove(fs, "rc/b"), 0);
	CHECK_INT(ops->remove(fs, "rc"), 0);
	ops->unmount(fs);
}

static void signing_server(void)
{
	static const char *const v[] = { "?dialect=2.0.2", "?dialect=2.1", "?dialect=3.0", "", "?gmac=no" };
	int i, save = port;
	char d2[128];
	snprintf(d2, sizeof(d2), "%s/sig", dir);
	if (start_server(d2, port2, "mandatory")) {
		CHECK(0);
		return;
	}
	port = port2;
	for (i = 0; i < (int)LN_ARRAY_SIZE(v); i++) {
		LnFs *fs = mnt("plain", v[i], NULL, NULL);
		int f0 = t_fail;
		CHECK(fs != NULL);
		if (!fs) continue;
		file_ops(fs, "s", "");
		ops->unmount(fs);
		printf("t_smb_samba: mandatory signing \"%s\" %s\n", v[i], t_fail == f0 ? "ok" : "FAILED");
	}
	port = save;
}

int main(void)
{
	int p;
	if (getuid() != 0) T_SKIP("t_smb_samba", "needs root for smbd");
	if (system("command -v smbd >/dev/null 2>&1")) T_SKIP("t_smb_samba", "no smbd");
	for (port = 0, p = 4450; p <= 4459; p++)
		if (port_free(p)) { if (!port) port = p; else { port2 = p; break; } }
	if (!port || !port2) T_SKIP("t_smb_samba", "no free port in 4450-4459");
	strcpy(dir, "/tmp/lagoon-smb.XXXXXX");
	if (!mkdtemp(dir)) T_SKIP("t_smb_samba", "mkdtemp");
	if (start_server(dir, port, "auto")) T_SKIP("t_smb_samba", "smbd did not start");
	ln_net_init();
	ops = ln_vfs_find("smb");

	variants();
	subdir_url();
	big_dir();
	other_shares();
	shares();
	reconnect("");
	reconnect("?encrypt=yes");
	reconnect("?dialect=2.1");
	signing_server();

	stop_servers();
	T_DONE("t_smb_samba");
}
