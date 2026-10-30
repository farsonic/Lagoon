/*
 * Lagoon - native command-line client over any backend (testing aid):
 *   lncli [-v N] URL ls [path] | stat path | cat path | get rpath lfile |
 *         put lfile rpath | mkdir path | rm path | mv from to | df |
 *         shares | touch path unixtime | trunc path size
 * Credentials come from the URL (smb://user:pass@host/share).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include "ln_vfs.h"
#include "ln_sys.h"
#include "ln_net.h"

/* errors go to stdout on the Amiga (the test harness captures one stream) */
#ifdef __VBCC__
#define ERR stdout
#else
#define ERR stderr
#endif

static void share_cb(void *ud, const char *name, const char *comment)
{
	(void)ud;
	printf("%-24s %s\n", name, comment ? comment : "");
}

static void pstat(const char *name, const LnStat *st)
{
	printf("%c %10llu %10u %04o %c%c%c%c %s%s%s\n", st->type == LN_T_DIR ? 'd' : st->type == LN_T_LINK ? 'l' : '-',
	       (unsigned long long)st->size, st->mtime, st->mode & 07777,
	       st->prot & LN_P_READ ? 'r' : '-', st->prot & LN_P_WRITE ? 'w' : '-',
	       st->prot & LN_P_EXEC ? 'e' : '-', st->prot & LN_P_DELETE ? 'd' : '-', name,
	       st->comment[0] ? "  # " : "", st->comment);
}

int main(int argc, char **argv)
{
	const LnOps *ops;
	LnFs *fs;
	const char *cmd;
	int r, ai = 1;
	if (argc > 2 && !strcmp(argv[1], "-v")) { ln_log_level = atoi(argv[2]); ai = 3; }
	if (argc - ai < 2) {
		fprintf(ERR, "usage: lncli [-v N] URL ls|stat|cat|get|put|mkdir|rm|mv|df|shares|touch|trunc ...\n");
		return 2;
	}
	ln_net_init();
	atexit(ln_net_exit);
	cmd = argv[ai + 1];
	if (!strcmp(cmd, "shares")) {
		LnUrl u;
		LnCreds c;
		if (ln_url_parse(argv[ai], &u) || !(ops = ln_vfs_find(u.scheme))) { fprintf(ERR, "bad url\n"); return 2; }
		if (!ops->list_shares) { fprintf(ERR, "not supported\n"); return 1; }
		memset(&c, 0, sizeof(c));
		strcpy(c.user, u.user); strcpy(c.password, u.password); strcpy(c.domain, u.domain);
		r = ops->list_shares(&u, &c, share_cb, NULL);
		if (r < 0) { fprintf(ERR, "shares: %s\n", ln_strerror(r)); return 1; }
		return 0;
	}
	r = ln_vfs_mount_url(argv[ai], NULL, &ops, &fs);
	if (r) { fprintf(ERR, "mount: %s\n", ln_strerror(r)); return 1; }
	{
		const char *a1 = argc > ai + 2 ? argv[ai + 2] : "", *a2 = argc > ai + 3 ? argv[ai + 3] : "";
		if (!strcmp(cmd, "ls")) {
			LnDir *d;
			char name[512];
			LnStat st;
			r = ops->opendir(fs, a1, &d);
			if (!r) {
				while ((r = ops->readdir(d, name, sizeof(name), &st)) > 0)
					pstat(name, &st);
				ops->closedir(d);
			}
		} else if (!strcmp(cmd, "stat")) {
			LnStat st;
			if (!(r = ops->stat(fs, a1, &st))) pstat(a1, &st);
		} else if (!strcmp(cmd, "cat") || !strcmp(cmd, "get")) {
			LnFile *f;
			FILE *out = !strcmp(cmd, "cat") ? stdout : fopen(a2, "wb");
			if (!out) { perror(a2); return 1; }
			r = ops->open(fs, a1, LN_O_READ, &f);
			if (!r) {
				static char buf[65536];
				u64 off = 0;
				long n, chunk = ops->max_io ? ops->max_io(fs) : 65536;
				if (chunk > (long)sizeof(buf)) chunk = sizeof(buf);
				while ((n = ops->read(f, off, buf, chunk)) > 0) { fwrite(buf, 1, (size_t)n, out); off += (u64)n; }
				r = n < 0 ? (int)n : 0;
				ops->close(f);
			}
			if (out != stdout) fclose(out);
		} else if (!strcmp(cmd, "put")) {
			FILE *in = fopen(a1, "rb");
			LnFile *f;
			if (!in) { perror(a1); return 1; }
			r = ops->open(fs, a2, LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC, &f);
			if (!r) {
				static char buf[65536];
				u64 off = 0;
				size_t n;
				long chunk = ops->max_io ? ops->max_io(fs) : 65536;
				if (chunk > (long)sizeof(buf)) chunk = sizeof(buf);
				while ((n = fread(buf, 1, (size_t)chunk, in)) > 0) {
					long w = ops->write(f, off, buf, (long)n);
					if (w < 0) { r = (int)w; break; }
					off += (u64)w;
				}
				{ int c = ops->close(f); if (!r) r = c; }
			}
			fclose(in);
		} else if (!strcmp(cmd, "mkdir")) r = ops->mkdir(fs, a1);
		else if (!strcmp(cmd, "rm")) r = ops->remove(fs, a1);
		else if (!strcmp(cmd, "mv")) r = ops->rename(fs, a1, a2);
		else if (!strcmp(cmd, "df")) {
			LnStatFs st;
			if (!(r = ops->statfs(fs, &st)))
				printf("total %llu free %llu block %u%s volume \"%s\"\n", (unsigned long long)st.total_bytes,
				       (unsigned long long)st.free_bytes, st.block_size, st.readonly ? " ro" : "", st.volume);
		} else if (!strcmp(cmd, "touch")) {
			LnStat st;
			memset(&st, 0, sizeof(st));
			st.mtime = (u32)strtoul(a2, NULL, 10);
			r = ops->setattr(fs, a1, &st, LN_SET_MTIME);
		} else if (!strcmp(cmd, "trunc")) {
			LnFile *f;
			r = ops->open(fs, a1, LN_O_WRITE, &f);
			if (!r) { r = ops->truncate(f, strtoull(a2, NULL, 10)); ops->close(f); }
		} else { fprintf(ERR, "unknown command %s\n", cmd); r = LN_EINVAL; }
	}
	if (r < 0) fprintf(ERR, "%s: %s\n", cmd, ln_strerror(r));
	ops->unmount(fs);
	return r < 0 ? 1 : 0;
}
