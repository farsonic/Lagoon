/*
 * Lagoon - Finder info and resource forks for the AFP server, in AppleDouble "._" files.
 *
 * A Mac file has a type and creator, Finder flags and a resource fork; SMB, NFS and the VFS
 * have none of these. macOS keeps them, on servers that lack them, in a file "._name" beside
 * "name": AppleDouble version 2 (RFC 1740's successor, Apple's "AppleSingle/AppleDouble Formats
 * for Foreign Files", 1990), and Samba's vfs_fruit reads and writes the same files. The server
 * does the same, so a file copied from the Mac to a share keeps its icon and its resources when
 * a Mac running macOS (or this server again) looks at it.
 *
 * The files the server writes have two entries: Finder info (ID 9, 32 bytes) at 50 and the
 * resource fork (ID 2) at 82, last, so that it can grow without moving anything. Files written
 * by macOS have more in the Finder info entry (extended attributes) and the resource fork
 * further on; they are read by their entry table and written in place.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "afps_int.h"
#include "../ln_sys.h"

#define AD_MAGIC   0x00051607u
#define AD_VERSION 0x00020000u
#define AD_RSRC    2
#define AD_FINFO   9

int afps_hidden_name(const char *name)
{
	return !strncmp(name, "._", 2) || !strcmp(name, ".DS_Store") || !strcmp(name, ".AppleDouble") ||
	       !strcmp(name, ".AppleDB") || !strcmp(name, ".AppleDesktop") || !strcmp(name, ".TemporaryItems");
}

int afps_ad_name(const char *path, char *out, size_t max)
{
	char dir[AFPS_PATH_MAX], base[260];
	ln_path_parent(dir, sizeof dir, path);
	if (ln_snprintf(base, sizeof base, "._%s", ln_path_base(path)) >= (int)sizeof base)
		return LN_ENAMETOOLONG;
	return ln_path_join(out, max, dir, base);
}

/* parse a header read from the start of a "._" file */
static int parse(const u8 *h, long n, AfpsAd *ad)
{
	int i, cnt;
	memset(ad, 0, sizeof *ad);
	if (n < 26 || ln_be32(h) != AD_MAGIC || ln_be32(h + 4) != AD_VERSION)
		return LN_EPROTO;
	cnt = ln_be16(h + 24);
	for (i = 0; i < cnt && 26 + 12 * i + 12 <= n; i++) {
		const u8 *e = h + 26 + 12 * i;
		u32 id = ln_be32(e), off = ln_be32(e + 4), len = ln_be32(e + 8);
		if (id == AD_FINFO && len >= 32 && off + 32 <= (u32)n) {
			memcpy(ad->finfo, h + off, 32);
			ad->finfo_pos = off;
		} else if (id == AD_FINFO && len >= 32) {
			ad->finfo_pos = off;             /* beyond what was read: read it on its own */
		} else if (id == AD_RSRC) {
			ad->rsrc_off = off;
			ad->rsrc_len = len;
			ad->rlen_pos = 26 + 12 * (u32)i + 8;
		}
	}
	ad->exists = 1;
	return LN_OK;
}

static int read_hdr(const LnOps *ops, LnFile *f, AfpsAd *ad)
{
	u8 h[512];
	long n = ops->read(f, 0, h, sizeof h);
	int r;
	if (n < 0)
		return (int)n;
	r = parse(h, n, ad);
	if (r == LN_OK && ad->finfo_pos && ad->finfo_pos + 32 > (u32)n && ops->read(f, ad->finfo_pos, ad->finfo, 32) != 32)
		memset(ad->finfo, 0, 32);
	return r;
}

/* a new "._" file: Finder info at 50, an empty resource fork at 82 */
static void make_hdr(u8 h[AFPS_AD_HDR], const u8 finfo[32])
{
	memset(h, 0, AFPS_AD_HDR);
	ln_put_be32(h, AD_MAGIC);
	ln_put_be32(h + 4, AD_VERSION);
	memcpy(h + 8, "Mac OS X        ", 16);   /* the filler macOS writes, for its benefit */
	ln_put_be16(h + 24, 2);
	ln_put_be32(h + 26, AD_FINFO);
	ln_put_be32(h + 30, 50);
	ln_put_be32(h + 34, 32);
	ln_put_be32(h + 38, AD_RSRC);
	ln_put_be32(h + 42, AFPS_AD_HDR);
	ln_put_be32(h + 46, 0);
	if (finfo)
		memcpy(h + 50, finfo, 32);
}

static void new_ad(AfpsAd *ad, const u8 *finfo)
{
	memset(ad, 0, sizeof *ad);
	if (finfo)
		memcpy(ad->finfo, finfo, 32);
	ad->finfo_pos = 50;
	ad->rsrc_off = AFPS_AD_HDR;
	ad->rlen_pos = 46;
	ad->exists = 1;
}

int afps_ad_read(const LnOps *ops, LnFs *fs, const char *path, AfpsAd *ad)
{
	char adp[AFPS_PATH_MAX];
	LnFile *f;
	int r;
	memset(ad, 0, sizeof *ad);
	if (afps_ad_name(path, adp, sizeof adp) != LN_OK || ops->open(fs, adp, LN_O_READ, &f) != LN_OK)
		return LN_OK;                            /* no "._" file: nothing to tell */
	r = read_hdr(ops, f, ad);
	ops->close(f);
	if (r != LN_OK)
		memset(ad, 0, sizeof *ad);           /* not AppleDouble after all: ignore it */
	return LN_OK;
}

int afps_ad_open(const LnOps *ops, LnFs *fs, const char *path, int write, int create, LnFile **f, AfpsAd *ad)
{
	char adp[AFPS_PATH_MAX];
	u8 h[AFPS_AD_HDR];
	int r = afps_ad_name(path, adp, sizeof adp);
	if (r != LN_OK)
		return r;
	r = ops->open(fs, adp, write ? LN_O_READ | LN_O_WRITE : LN_O_READ, f);
	if (r == LN_OK) {
		r = read_hdr(ops, *f, ad);
		if (r == LN_OK && !ad->rlen_pos)
			r = LN_EPROTO;               /* Finder info only: no room for a fork (not ours) */
		if (r != LN_OK)
			ops->close(*f);
		return r;
	}
	if (r != LN_ENOENT || !create)
		return r;
	r = ops->open(fs, adp, LN_O_READ | LN_O_WRITE | LN_O_CREATE | LN_O_EXCL, f);
	if (r != LN_OK)
		return r;
	make_hdr(h, NULL);
	if (ops->write(*f, 0, h, sizeof h) != (long)sizeof h) {
		ops->close(*f);
		return LN_EIO;
	}
	new_ad(ad, NULL);
	return LN_OK;
}

int afps_ad_set_rlen(const LnOps *ops, LnFile *f, AfpsAd *ad, u32 len)
{
	u8 b[4];
	ln_put_be32(b, len);
	if (ops->write(f, ad->rlen_pos, b, 4) != 4)
		return LN_EIO;
	ad->rsrc_len = len;
	return LN_OK;
}

int afps_ad_set_finfo(const LnOps *ops, LnFs *fs, const char *path, const u8 finfo[32])
{
	char adp[AFPS_PATH_MAX];
	LnFile *f;
	AfpsAd ad;
	u8 h[AFPS_AD_HDR];
	int r = afps_ad_name(path, adp, sizeof adp);
	if (r != LN_OK)
		return r;
	if (ops->open(fs, adp, LN_O_READ | LN_O_WRITE, &f) == LN_OK) {
		r = read_hdr(ops, f, &ad);
		if (r == LN_OK && ad.finfo_pos)
			r = ops->write(f, ad.finfo_pos, finfo, 32) == 32 ? LN_OK : LN_EIO;
		else if (r == LN_OK)
			r = LN_ENOTSUP;                  /* an AppleDouble file without Finder info */
		ops->close(f);
		return r;
	}
	r = ops->open(fs, adp, LN_O_READ | LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC, &f);
	if (r != LN_OK)
		return r;
	make_hdr(h, finfo);
	r = ops->write(f, 0, h, sizeof h) == (long)sizeof h ? LN_OK : LN_EIO;
	ops->close(f);
	return r;
}
