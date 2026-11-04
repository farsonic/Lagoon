/*
 * Lagoon - native tests for lagoon-handler's portable core
 * (src/amiga/handler/hcore.c) and the mem backend (src/core/mem): Amiga
 * path parsing, case-insensitive names, long/escaped names, DOS lock
 * semantics, buffered I/O (1 MB, random chunk sizes, compared with a
 * model), namespace errors, read-only, disk full and reconnects.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "testutil.h"
#include <stdlib.h>
#include "../src/amiga/handler/hcore.c"

static void no_sleep(u32 ms) { (void)ms; }

static HC *mount(const char *url, int ro)
{
	static HC hc;
	const LnOps *ops;
	LnFs *fs;
	int r = ln_vfs_mount_url(url, NULL, &ops, &fs);
	CHECK_INT(r, 0);
	if (r)
		exit(1);
	hc_init(&hc, ops, fs, ro);
	hc.sleep_ms = no_sleep;
	return &hc;
}

static void umount(HC *h)
{
	CHECK_INT(h->nlocks, 0);
	CHECK_INT(h->nfiles, 0);
	hc_free(h);
	h->ops->unmount(h->fs);
}

static int count_dir(HC *h, const char *apath, int *longnames)
{
	HLock *l;
	u32 idx = 0;
	const HEnt *e;
	int n = 0, r;
	if (hc_lock(h, NULL, apath, 0, &l))
		return -1;
	while ((r = hc_next(h, l, &idx, &e)) > 0) {
		n++;
		CHECK(strlen(e->aname) <= HC_NAMEMAX);
		if (longnames && strlen(e->aname) == HC_NAMEMAX - 5 + 5 && strchr(e->aname, '~'))
			(*longnames)++;
	}
	CHECK_INT(r, 0);
	hc_unlock(h, l);
	return n;
}

static void names(void)
{
	HC *h = mount("mem://t/names?seed=1&many=300", 0);
	HLock *a, *b, *c, *d;
	LnStat st;
	char nm[HC_NAMEMAX + 1];
	int longn = 0;

	/* case-insensitive on a case-sensitive server */
	CHECK_INT(hc_lock(h, NULL, "ReadMe.txt", 0, &a), 0);
	CHECK_INT(hc_lock(h, NULL, "README.TXT", 0, &b), 0);
	CHECK_STR(b->rpath, "ReadMe.txt");
	CHECK(hc_same_lock(a, b));
	/* exclusive vs shared */
	CHECK_INT(hc_lock(h, NULL, "readme.txt", 1, &c), LN_EINUSE);
	CHECK_INT(hc_change_lock(h, a, 1), LN_EINUSE);
	hc_unlock(h, b);
	CHECK_INT(hc_change_lock(h, a, 1), 0);
	CHECK_INT(hc_lock(h, NULL, "ReadMe.txt", 0, &c), LN_EINUSE);
	CHECK_INT(hc_duplock(h, a, &c), LN_EINUSE);
	CHECK_INT(hc_delete(h, NULL, "readme.txt"), LN_EINUSE);
	hc_unlock(h, a);

	/* device/volume prefix, parent slashes */
	CHECK_INT(hc_lock(h, NULL, "Dir1/Sub", 0, &a), 0);
	CHECK_STR(a->rpath, "Dir1/sub");
	CHECK_INT(hc_lock(h, a, "/", 0, &b), 0);
	CHECK_STR(b->rpath, "Dir1");
	CHECK_INT(hc_lock(h, a, "//readme.txt", 0, &c), 0);
	CHECK_STR(c->rpath, "ReadMe.txt");
	CHECK_INT(hc_lock(h, a, "LGN0:dir1//mixedcase.txt", 0, &d), 0);
	CHECK_STR(d->rpath, "MixedCase.TXT");
	hc_unlock(h, d);
	CHECK_INT(hc_lock(h, a, "deep.txt/x", 0, &d), LN_ENOTDIR);
	CHECK_INT(hc_lock(h, a, "///", 0, &d), LN_ENOENT);
	CHECK_INT(hc_lock(h, a, "x:y:z", 0, &d), LN_EINVAL);
	CHECK_INT(hc_lock(h, NULL, "Dir1/", 0, &d), 0);
	CHECK_STR(d->rpath, "Dir1");
	hc_unlock(h, d);
	hc_unlock(h, c);
	CHECK_INT(hc_parent(h, b, &c), 0);
	CHECK(c != NULL && c->rpath[0] == 0);
	CHECK_INT(hc_parent(h, c, &d), 0);
	CHECK(d == NULL);
	hc_unlock(h, c);
	hc_unlock(h, b);
	hc_unlock(h, a);

	/* escaped names: ':' -> %3A, U+017F (not Latin-1) -> %C5%BF */
	CHECK_INT(hc_lock(h, NULL, "a%3Ab.txt", 0, &a), 0);
	CHECK_STR(a->rpath, "a:b.txt");
	hc_unlock(h, a);
	CHECK_INT(hc_lock(h, NULL, "\xdcn\xef-%C5%BF.txt", 0, &a), 0);
	CHECK_STR(a->rpath, "\xc3\x9cn\xc3\xaf-\xc5\xbf.txt");
	hc_unlock(h, a);
	CHECK_INT(hc_lock(h, NULL, "\xfcN\xcf-%c5%bf.TXT", 0, &a), 0);    /* Latin-1 case folding */
	hc_unlock(h, a);

	/* long names: cut to 107 with a unique suffix, and found again */
	{
		char rn[200];
		int i;
		for (i = 0; i < 130; i++)
			rn[i] = (char)('a' + i % 26);
		strcpy(rn + 130, ".txt");
		hc_amiga_name(rn, nm);
		CHECK_INT(strlen(nm), HC_NAMEMAX);
		CHECK(nm[HC_NAMEMAX - 5] == '~');
		CHECK_INT(hc_lock(h, NULL, nm, 0, &a), 0);
		CHECK_STR(a->rpath, rn);
		CHECK_INT(hc_stat_lock(h, a, &st), 0);
		CHECK_INT(st.size, 10);
		hc_unlock(h, a);
	}
	CHECK_INT(count_dir(h, ":", &longn), 8);
	CHECK_INT(longn, 1);
	CHECK_INT(count_dir(h, "Many", NULL), 300);
	CHECK_INT(count_dir(h, "ReadMe.txt", NULL), 0);   /* ExNext on a file: nothing */

	/* names that are one name to the Amiga: the later one gets a suffix */
	CHECK_INT(h->ops->mkdir(h->fs, "case"), 0);
	CHECK_INT(h->ops->mkdir(h->fs, "case/foo"), 0);
	CHECK_INT(h->ops->mkdir(h->fs, "case/FOO"), 0);
	hc_cache_clear(h);      /* changed behind the handler's back */
	{
		HLock *l;
		u32 idx = 0;
		const HEnt *e;
		CHECK_INT(hc_lock(h, NULL, "case", 0, &l), 0);
		CHECK_INT(hc_next(h, l, &idx, &e), 1);
		CHECK_STR(e->aname, "foo");
		CHECK_INT(hc_next(h, l, &idx, &e), 1);
		CHECK(!strncmp(e->aname, "FOO~", 4) && strlen(e->aname) == 8);
		ln_strlcpy(nm, e->aname, sizeof(nm));
		CHECK_INT(hc_next(h, l, &idx, &e), 0);
		hc_unlock(h, l);
		CHECK_INT(hc_lock(h, NULL, "case/foo", 0, &a), 0);
		CHECK_STR(a->rpath, "case/foo");
		hc_unlock(h, a);
		CHECK_INT(hc_lock(h, NULL, "case/FOO", 0, &a), 0);
		CHECK_STR(a->rpath, "case/FOO");
		hc_unlock(h, a);
		h->ttl_ms = 0;          /* force the listing path */
		{
			char p[64];
			ln_snprintf(p, sizeof(p), "case/%s", nm);
			CHECK_INT(hc_lock(h, NULL, p, 0, &a), 0);
			CHECK_STR(a->rpath, "case/FOO");
			hc_unlock(h, a);
		}
		h->ttl_ms = 3000;
	}
	umount(h);
}

static void namespace_ops(void)
{
	HC *h = mount("mem://t/ns?seed=1", 0);
	HLock *a, *b;
	HFile *f;
	LnStat st;

	CHECK_INT(hc_mkdir(h, NULL, "NewDir", &a), 0);
	CHECK(a->excl);
	CHECK_INT(hc_mkdir(h, NULL, "newdir", &b), LN_EEXIST);
	CHECK_INT(hc_mkdir(h, NULL, "nodir/x", &b), LN_ENOENT);
	CHECK_INT(hc_mkdir(h, NULL, "trail/", &b), 0);   /* trailing '/' ignored */
	CHECK_STR(b->rpath, "trail");
	hc_unlock(h, b);
	CHECK_INT(hc_mkdir(h, NULL, "..", &b), LN_EINVAL);
	CHECK_INT(hc_delete(h, NULL, "NewDir"), LN_EINUSE);   /* locked */
	hc_unlock(h, a);
	CHECK_INT(hc_open(h, NULL, "newdir/f", HC_NEW, &f), 0);
	CHECK_INT(hc_write(h, f, "abc", 3), 3);
	CHECK_INT(hc_delete(h, NULL, "NewDir/F"), LN_EINUSE);  /* open */
	CHECK_INT(hc_close(h, f), 0);
	CHECK_INT(hc_delete(h, NULL, "NewDir"), LN_ENOTEMPTY);
	CHECK_INT(hc_open(h, NULL, "NewDir", HC_OLD, &f), LN_EISDIR);
	CHECK_INT(hc_open(h, NULL, "NewDir", HC_NEW, &f), LN_EISDIR);
	CHECK_INT(hc_open(h, NULL, "missing", HC_OLD, &f), LN_ENOENT);
	CHECK_INT(hc_open(h, NULL, "missing/x", HC_NEW, &f), LN_ENOENT);

	/* rename: onto existing, case-only, into itself, locks follow */
	CHECK_INT(hc_rename(h, NULL, "ReadMe.txt", NULL, "MixedCase.txt"), LN_EEXIST);
	CHECK_INT(hc_lock(h, NULL, "newdir/f", 0, &a), 0);
	CHECK_INT(hc_rename(h, NULL, "newdir", NULL, "Renamed"), 0);
	CHECK_STR(a->rpath, "Renamed/f");
	CHECK_INT(hc_stat_lock(h, a, &st), 0);
	CHECK_INT(st.size, 3);
	hc_unlock(h, a);
	CHECK_INT(hc_rename(h, NULL, "renamed", NULL, "RENAMED"), 0);
	CHECK_INT(hc_lock(h, NULL, "RENAMED", 0, &a), 0);
	CHECK_STR(a->rpath, "RENAMED");
	hc_unlock(h, a);
	CHECK_INT(h->ops->stat(h->fs, "RENAMED", &st), 0);
	CHECK_INT(hc_rename(h, NULL, "Renamed", NULL, "renamed/sub"), LN_EINUSE);
	CHECK_INT(hc_rename(h, NULL, "Renamed/f", NULL, "Dir1/sub/g"), 0);
	CHECK_INT(hc_rename(h, NULL, ":", NULL, "x"), LN_EINUSE);
	CHECK_INT(hc_rename(h, NULL, "nothere", NULL, "x"), LN_ENOENT);
	CHECK_INT(hc_delete(h, NULL, "Renamed"), 0);
	CHECK_INT(hc_delete(h, NULL, "Renamed"), LN_ENOENT);

	/* attributes */
	memset(&st, 0, sizeof(st));
	st.prot = LN_P_READ | LN_P_WRITE;
	CHECK_INT(hc_setattr(h, NULL, "dir1/sub/g", &st, LN_SET_PROT), 0);
	CHECK_INT(hc_delete(h, NULL, "dir1/sub/g"), LN_EACCES);     /* delete protected */
	strcpy(st.comment, "a note \xc3\xa4");
	st.mtime = 1000000000;
	CHECK_INT(hc_setattr(h, NULL, "dir1/sub/g", &st, LN_SET_COMMENT | LN_SET_MTIME), 0);
	CHECK_INT(hc_lock(h, NULL, "dir1/sub/g", 0, &a), 0);
	CHECK_INT(hc_stat_lock(h, a, &st), 0);
	CHECK_STR(st.comment, "a note \xc3\xa4");
	CHECK_INT(st.mtime, 1000000000);
	CHECK_INT(st.prot, LN_P_READ | LN_P_WRITE);
	hc_unlock(h, a);
	{
		char l1[32], u8s[32];
		hc_utf8_to_latin1("a note \xc3\xa4 \xc5\xbf", l1, sizeof(l1));
		CHECK_STR(l1, "a note \xe4 ?");
		hc_latin1_to_utf8("\xe4x", u8s, sizeof(u8s));
		CHECK_STR(u8s, "\xc3\xa4x");
	}
	{
		LnStatFs sf;
		CHECK_INT(hc_statfs(h, &sf), 0);
		CHECK(sf.total_bytes == 64 * 1024 * 1024);
		CHECK_STR(sf.volume, "ns");
	}
	umount(h);
}

static u32 rnd_state = 12345;
static u32 rnd(void) { rnd_state = rnd_state * 1103515245 + 12345; return rnd_state >> 8; }

/* write 1 MB in random chunk sizes with random seeks, compare with a model */
static void io_test(HC *h, const char *name)
{
	const long N = 1024 * 1024;
	u8 *model = malloc((size_t)N), *buf = malloc((size_t)N);
	HFile *f;
	long pos = 0, i;
	u64 old;
	for (i = 0; i < N; i++)
		model[i] = (u8)rnd();
	CHECK_INT(hc_open(h, NULL, name, HC_NEW, &f), 0);
	while (pos < N) {
		long n = (long)(rnd() % 3 == 0 ? rnd() % 100000 : rnd() % 700) + 1;
		if (n > N - pos)
			n = N - pos;
		CHECK_INT(hc_write(h, f, model + pos, n), n);
		pos += n;
	}
	/* rewrite some ranges in place */
	for (i = 0; i < 50; i++) {
		long at = (long)(rnd() % (u32)N), n = (long)(rnd() % 3000) + 1, k;
		if (at + n > N)
			n = N - at;
		for (k = 0; k < n; k++)
			model[at + k] = (u8)rnd();
		CHECK_INT(hc_seek(h, f, at, HC_SEEK_SET, &old), 0);
		CHECK_INT(hc_write(h, f, model + at, n), n);
	}
	CHECK_INT(hc_seek(h, f, 0, HC_SEEK_END, &old), 0);
	CHECK_INT(hc_seek(h, f, 0, HC_SEEK_CUR, &old), 0);
	CHECK_INT(old, N);
	CHECK_INT(hc_seek(h, f, 1, HC_SEEK_END, &old), LN_EINVAL);
	CHECK_INT(hc_seek(h, f, -1, HC_SEEK_SET, &old), LN_EINVAL);
	CHECK_INT(hc_close(h, f), 0);

	CHECK_INT(hc_open(h, NULL, name, HC_OLD, &f), 0);
	CHECK_INT(f->size, N);
	pos = 0;
	while (pos < N) {
		long n = (long)(rnd() % 3 == 0 ? rnd() % 100000 : rnd() % 900) + 1, got;
		got = hc_read(h, f, buf + pos, n);
		CHECK(got > 0);
		if (got <= 0)
			break;
		pos += got;
	}
	CHECK_INT(pos, N);
	CHECK_INT(hc_read(h, f, buf, 10), 0);
	CHECK(!memcmp(buf, model, (size_t)N));
	/* random reads */
	for (i = 0; i < 200; i++) {
		long at = (long)(rnd() % (u32)N), n = (long)(rnd() % 5000) + 1, want = n;
		if (at + want > N)
			want = N - at;
		CHECK_INT(hc_seek(h, f, at, HC_SEEK_SET, &old), 0);
		CHECK_INT(hc_read(h, f, buf, n), want);
		CHECK(!memcmp(buf, model + at, (size_t)want));
	}
	/* read/write mix on MODE_OLDFILE, then truncate */
	CHECK_INT(hc_seek(h, f, 10, HC_SEEK_SET, &old), 0);
	CHECK_INT(hc_write(h, f, "XYZ", 3), 3);
	CHECK_INT(hc_read(h, f, buf, 2), 2);
	CHECK(buf[0] == model[13] && buf[1] == model[14]);
	CHECK_INT(hc_seek(h, f, 9, HC_SEEK_SET, &old), 0);
	CHECK_INT(hc_read(h, f, buf, 5), 5);
	CHECK(!memcmp(buf + 1, "XYZ", 3));
	CHECK_INT(hc_set_size(h, f, 100, HC_SEEK_SET, &old), 0);
	CHECK_INT(old, 100);
	CHECK_INT(hc_seek(h, f, 0, HC_SEEK_CUR, &old), 0);
	CHECK_INT(old, 14);
	CHECK_INT(hc_set_size(h, f, -50, HC_SEEK_END, &old), 0);
	CHECK_INT(old, 50);
	{
		LnStat st;
		CHECK_INT(hc_stat_file(h, f, &st), 0);
		CHECK_INT(st.size, 50);
	}
	CHECK_INT(hc_close(h, f), 0);
	free(model);
	free(buf);
}

static void io(void)
{
	HC *h = mount("mem://t/io?maxio=8192", 0);
	HFile *f, *g;
	HLock *l;
	io_test(h, "big.bin");
	/* DOS sharing: NEWFILE is exclusive, OLDFILE/READWRITE shared */
	CHECK_INT(hc_open(h, NULL, "big.bin", HC_OLD, &f), 0);
	CHECK_INT(hc_open(h, NULL, "BIG.BIN", HC_RW, &g), 0);
	CHECK_INT(hc_close(h, g), 0);
	CHECK_INT(hc_open(h, NULL, "big.bin", HC_NEW, &g), LN_EINUSE);
	CHECK_INT(hc_lock(h, NULL, "big.bin", 1, &l), LN_EINUSE);
	CHECK_INT(hc_lock_file(h, f, &l), 0);
	hc_unlock(h, l);
	CHECK_INT(hc_close(h, f), 0);
	CHECK_INT(hc_open(h, NULL, "big.bin", HC_NEW, &f), 0);
	CHECK_INT(hc_open(h, NULL, "big.bin", HC_OLD, &g), LN_EINUSE);
	CHECK_INT(hc_lock(h, NULL, "big.bin", 0, &l), LN_EINUSE);
	CHECK_INT(hc_change_file(h, f, 0), 0);
	CHECK_INT(hc_lock(h, NULL, "big.bin", 0, &l), 0);
	/* FH_FROM_LOCK */
	CHECK_INT(hc_open_lock(h, l, &g), 0);
	CHECK_INT(hc_write(h, f, "hello", 5), 5);
	{
		char b[8];
		CHECK_INT(hc_read(h, g, b, 8), 5);
		CHECK(!memcmp(b, "hello", 5));
	}
	CHECK_INT(hc_close(h, g), 0);
	CHECK_INT(hc_close(h, f), 0);
	/* write-behind flushed by idle and by Examine */
	CHECK_INT(hc_open(h, NULL, "wb", HC_NEW, &f), 0);
	CHECK_INT(hc_write(h, f, "12345", 5), 5);
	CHECK(hc_dirty(h));
	CHECK_INT(hc_lock(h, NULL, "wb", 0, &l), LN_EINUSE);
	CHECK_INT(hc_change_file(h, f, 0), 0);
	CHECK_INT(hc_lock(h, NULL, "wb", 0, &l), 0);
	{
		LnStat st;
		CHECK_INT(hc_stat_lock(h, l, &st), 0);
		CHECK_INT(st.size, 5);
	}
	hc_unlock(h, l);
	CHECK(!hc_dirty(h));
	CHECK_INT(hc_close(h, f), 0);
	umount(h);
}

static void readonly_full(void)
{
	HC *h = mount("mem://t/ro?seed=1", 1);
	HFile *f;
	HLock *l;
	LnStat st;
	memset(&st, 0, sizeof(st));
	CHECK_INT(hc_open(h, NULL, "x", HC_NEW, &f), LN_EROFS);
	CHECK_INT(hc_open(h, NULL, "x", HC_RW, &f), LN_EROFS);
	CHECK_INT(hc_mkdir(h, NULL, "x", &l), LN_EROFS);
	CHECK_INT(hc_delete(h, NULL, "ReadMe.txt"), LN_EROFS);
	CHECK_INT(hc_rename(h, NULL, "ReadMe.txt", NULL, "x"), LN_EROFS);
	CHECK_INT(hc_setattr(h, NULL, "ReadMe.txt", &st, LN_SET_PROT), LN_EROFS);
	CHECK_INT(hc_open(h, NULL, "ReadMe.txt", HC_OLD, &f), 0);
	CHECK_INT(hc_write(h, f, "x", 1), LN_EROFS);
	{
		char b[64];
		CHECK_INT(hc_read(h, f, b, sizeof(b)), 35);
	}
	CHECK_INT(hc_close(h, f), 0);
	h->readonly = 0;   /* ACTION_WRITE_PROTECT off */
	CHECK_INT(hc_open(h, NULL, "x", HC_NEW, &f), 0);
	CHECK_INT(hc_close(h, f), 0);
	umount(h);

	/* server-side read-only */
	h = mount("mem://t/ro2?ro=1&seed=1", 0);
	CHECK_INT(hc_open(h, NULL, "x", HC_NEW, &f), LN_EROFS);
	CHECK_INT(hc_open(h, NULL, "ReadMe.txt", HC_OLD, &f), 0);    /* falls back to read-only */
	CHECK_INT(hc_write(h, f, "x", 1), LN_EACCES);
	CHECK_INT(hc_close(h, f), 0);
	umount(h);

	/* disk full */
	h = mount("mem://t/full?size=100000", 0);
	{
		static u8 big[150000];
		long w;
		CHECK_INT(hc_open(h, NULL, "f", HC_NEW, &f), 0);
		w = hc_write(h, f, big, sizeof(big));
		CHECK_INT(w, 6 * 16384);                          /* partial write */
		CHECK_INT(hc_write(h, f, big, 1000), 1000);       /* buffered: fits */
		CHECK_INT(hc_write(h, f, big, 2000), 2000);       /* buffered: does not fit */
		CHECK_INT(hc_close(h, f), LN_ENOSPC);
		CHECK_INT(hc_open(h, NULL, "g", HC_NEW, &f), 0);
		CHECK_INT(hc_write(h, f, big, 20000), LN_ENOSPC);
		CHECK_INT(hc_close(h, f), 0);
	}
	umount(h);
}

static void reconnect(void)
{
	HC *h;
	HLock *l;
	HFile *f;
	/* every 7th call drops; files go stale and must be reopened */
	h = mount("mem://t/rc?dropevery=13&stale=1&maxio=4096&seed=1", 0);
	io_test(h, "rc.bin");
	CHECK(h->reconnects > 10);
	CHECK_INT(count_dir(h, ":", NULL), 8);
	CHECK_INT(hc_lock(h, NULL, "Dir1/sub/deep.txt", 0, &l), 0);
	hc_unlock(h, l);
	umount(h);

	/* refuse=3: three failed reconnects, then it comes back */
	h = mount("mem://t/rc2?dropevery=11&refuse=3&seed=1", 0);
	io_test(h, "rc.bin");
	CHECK(h->reconnects > 5);
	umount(h);

	/* the server stays away: give up, fail fast, retry later */
	h = mount("mem://t/rc3?dropevery=4&refuse=1000&seed=1", 0);
	h->reconnect_ms = 0;
	CHECK_INT(hc_open(h, NULL, "ReadMe.txt", HC_OLD, &f), 0);
	{
		int r = 0, i;
		char b[8];
		for (i = 0; i < 5 && r >= 0; i++)
			r = (int)hc_read(h, f, b, 1);
		CHECK_INT(r, LN_ECONNRESET);
	}
	CHECK(h->offline);
	CHECK_INT(hc_lock(h, NULL, "ReadMe.txt", 0, &l), LN_ECONNRESET);
	h->retry_ms = 0;
	CHECK_INT(hc_lock(h, NULL, "ReadMe.txt", 0, &l), LN_ECONNRESET);
	/* close always works */
	hc_close(h, f);
	umount(h);
}

int main(void)
{
	names();
	namespace_ops();
	io();
	readonly_full();
	reconnect();
	T_DONE("t_hcore");
}
