/*
 * Lagoon - the AFP server's internals, shared by afps_asp.c, afps_afp.c, afps_names.c,
 * afps_adouble.c and tests/t_afpsrv.c. The AFP 3 constants, the request builder (AfpBuf) and the
 * date conversion are the AFP client's (src/core/afp/afp_int.h): the server writes what the
 * client parses. What AFP 2.x has that AFP 3 dropped is defined here, from Inside AppleTalk,
 * second edition, chapter 13.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef AFPS_INT_H
#define AFPS_INT_H

#include "afps.h"
#include "../afp/afp_int.h"

/* ---- ASP (Inside AppleTalk 11-39) ---- */
enum { SP_CLOSESESS = 1, SP_COMMAND = 2, SP_GETSTATUS = 3, SP_OPENSESS = 4, SP_TICKLE = 5,
       SP_WRITE = 6, SP_WRITECONT = 7, SP_ATTENTION = 8 };
#define ASP_VERSION 0x0100
/* SPError codes (Inside AppleTalk 11-17; the Mac's aspBadVersNum ... are the same numbers) */
enum { ASPERR_BADVERS = -1066, ASPERR_NOMORESESS = -1068, ASPERR_PARAM = -1070,
       ASPERR_SERVERBUSY = -1071, ASPERR_SESSCLOSED = -1072, ASPERR_SIZE = -1073 };
#define ASP_TICKLE_S   30        /* tickles every 30 seconds ... */
#define ASP_TIMEOUT_MS 120000u   /* ... and a session dies after two minutes of silence */

/* ---- AFP 2.x calls that AFP 3 (afp_int.h) does not list ---- */
enum {
	FPByteRangeLock = 1, FPCloseDir = 3, FPCopyFile = 5, FPEnumerate = 9, FPFlush = 10,
	FPMapID = 21, FPMapName = 22, FPOpenDir = 25, FPRead = 27, FPSetDirParms = 29,
	FPSetFileParms = 30, FPSetVolParms = 32, FPWrite = 33, FPChangePassword = 36,
	FPGetUserInfo = 37, FPGetSrvrMsg = 38, FPCreateID = 39, FPDeleteID = 40, FPResolveID = 41,
	FPExchangeFiles = 42, FPCatSearch = 43, FPGetIcon = 51, FPGetIconInfo = 52, FPAddAPPL = 53,
	FPRemoveAPPL = 54, FPGetAPPL = 55, FPAddIcon = 192
};
/* AFP 2.x: bit 13 of the file and directory bitmaps is the ProDOS info (AFP 3 reused it) */
#define FDBIT_PRODOS   0x2000
/* the bits an AFP 2.x client may ask for */
#define AFPS_FBITS     0x27FF    /* attr .. rsrc length, ProDOS */
#define AFPS_DBITS     0x3FFF    /* attr .. access rights, ProDOS */
#define AFPS_VBITS     0x01FF    /* attr .. name */
/* the parent of the root directory, and the root (Inside AppleTalk 13-10) */
#define AFPS_PARENT_OF_ROOT 1
#define AFPS_ROOT           2
#define AFPS_FIRST_ID       16   /* IDs below are reserved */
#define AFPS_VOLID          1
#define AFPS_DTREF          1
/* path types: short (ProDOS/MS-DOS) and long (Mac) names */
#define AFPS_PATH_SHORT 1
#define AFPS_PATH_LONG  2
/* names on the wire: 31 Mac Roman bytes for files and folders (the Mac's own limit) */
#define AFPS_NAME_MAX 31
/* server paths: the VFS has no limit of its own; this is plenty for a Mac's 31-byte names */
#define AFPS_PATH_MAX 1024

/* ---- the directory and file ID table (afps_names.c) ----
 * AFP 2.x names everything by a directory ID and a path from there. The VFS knows only paths,
 * so each folder (and each file the client has seen, for its file number) gets an ID when it is
 * first met; the entry keeps its parent's ID and its own name, so a rename or move is one edit
 * and the paths below follow. Folder IDs are never reused while the server runs, and folders
 * are never forgotten. Files are: only the newest AFPS_LIVE_FILES keep their names, so that a
 * session that browses a large share holds a bounded table (afps_names.c, docs/mac.md). */
typedef struct AfpsNode {
	char *name;              /* the server's name (UTF-8 NFC); NULL = unused or put away */
	u32   parent;
	u32   hnext;             /* next ID in the same hash chain (put away: in the away chain;
	                            free: the next free slot), 0 = end */
	u32   mark;              /* in use: the table's clock when last looked up; a mangled file
	                            put away: its name's hash (afps_names_hash), never 0 */
	u8    isdir;
	u8    pins;              /* open forks on it: never put away */
} AfpsNode;
#define AFPS_HASH 512
#define AFPS_PAGE 256            /* nodes per page */
#define AFPS_LIVE_FILES 1024     /* file names kept; the oldest beyond go */

typedef struct AfpsNames {
	AfpsNode **page;         /* npages pointers, the pages in use allocated */
	u32  npages;
	u32  count;              /* IDs 0 .. count-1 have a slot */
	u32  free;               /* a slot given back (its hnext the next), 0 = none */
	u32  live;               /* files with a name */
	u32  evict;              /* where put_away looks next */
	u32  clock;              /* counts lookups, for mark */
	u32  hash[AFPS_HASH];
	u32  away[AFPS_HASH];    /* mangled files put away, chained by hnext */
} AfpsNames;

int   afps_names_init(AfpsNames *t);
void  afps_names_free(AfpsNames *t);
/* the ID of name in parent, made if new; 0 = out of memory. isdir -1: as it was */
u32   afps_names_id(AfpsNames *t, u32 parent, const char *name, int isdir);
/* the ID of name in parent if known, else 0 */
u32   afps_names_find(const AfpsNames *t, u32 parent, const char *name);
const AfpsNode *afps_names_node(const AfpsNames *t, u32 id);
/* the server path of id ("" for the root); LN_ENOENT if id is unknown */
int   afps_names_path(const AfpsNames *t, u32 id, char *out, size_t max);
/* id is now name in parent (rename or move); forget removes it */
void  afps_names_move(AfpsNames *t, u32 id, u32 parent, const char *name);
void  afps_names_forget(AfpsNames *t, u32 id);
/* a mangled file's ID that was put away: its name's hash (else 0), and the name found again */
u32   afps_names_put_away(const AfpsNames *t, u32 id);
u32   afps_names_hash(const char *name);
int   afps_names_revive(AfpsNames *t, u32 id, u32 parent, const char *name);
/* an open fork holds its file's node (by +1 on open, -1 on close) */
void  afps_names_pin(AfpsNames *t, u32 id, int by);

/* Mac Roman <-> UTF-8. to_mac: the name the Mac sees, at most 31 bytes; a name with characters
 * Mac Roman lacks, or longer, becomes "start#ID" (the ID in hex, as Netatalk does), which
 * from_mac recognises. '/' in a Mac name is ':' on the server and the other way round (a Mac
 * name cannot hold ':', a server path cannot hold '/'). Return lengths, or -1. */
int   afps_to_mac(const char *utf8, u32 id, u8 *out, size_t max);
int   afps_mac_to_utf8(const u8 *mac, size_t n, char *out, size_t max);
/* the mangled form's ID ("#1A2B" at the end), or 0 */
u32   afps_mangled_id(const u8 *mac, size_t n);

/* resolve an AFP pathname (type byte, Pascal string: elements separated by NUL, each extra NUL
 * goes up one level) from directory did. Out: the parent's ID and the last element's server
 * name ("" when the path names did itself or an ancestor, *id then set). */
typedef struct AfpsPath {
	u32  parent;             /* the folder the object is in */
	u32  id;                 /* the object's ID if the path ends at a known folder, else 0 */
	char name[256];          /* the last element (server name), "" if the path ends in a folder */
	char mac[32];            /* the last element as the Mac wrote it (Mac Roman), for mangling */
} AfpsPath;

/* ---- AppleDouble (afps_adouble.c) ----
 * Finder info (type, creator, flags, icon position) and the resource fork of "name" live in
 * "._name" beside it, the AppleDouble version 2 format macOS and Samba's vfs_fruit use:
 * entry 9 the 32 bytes of Finder info, entry 2 the resource fork, last in the file so that it
 * can grow. A missing "._" file means empty Finder info and no resource fork. */
typedef struct AfpsAd {
	u8   finfo[32];
	u32  rsrc_off, rsrc_len; /* the resource fork's place in the "._" file */
	u32  rlen_pos;           /* where the header keeps rsrc_len, 0 = no resource fork entry */
	u32  finfo_pos;          /* where the Finder info is, 0 = no Finder info entry */
	int  exists;
} AfpsAd;
#define AFPS_AD_HDR 82           /* header 26 + 2 entries of 12 + Finder info 32 */
int  afps_ad_name(const char *path, char *out, size_t max);   /* "dir/._name" */
int  afps_ad_read(const LnOps *ops, LnFs *fs, const char *path, AfpsAd *ad);
/* write Finder info, creating the "._" file if needed (keeps a resource fork there) */
int  afps_ad_set_finfo(const LnOps *ops, LnFs *fs, const char *path, const u8 finfo[32]);
/* open the "._" file for the resource fork; makes an empty one when create */
int  afps_ad_open(const LnOps *ops, LnFs *fs, const char *path, int write, int create, LnFile **f, AfpsAd *ad);
/* set the resource fork length in an open "._" file's header */
int  afps_ad_set_rlen(const LnOps *ops, LnFile *f, AfpsAd *ad, u32 len);
/* names that are AppleDouble or other bookkeeping files and never shown to the Mac */
int  afps_hidden_name(const char *name);

/* ---- the server ---- */
#define AFPS_MAXSESS  8
#define AFPS_MAXFORK  32
#define AFPS_MAXWRITE 4
#define AFPS_RECENT   32

typedef struct AfpsSess {
	u8     used, id;
	u8     logged_in, vol_open;
	u8     warned;           /* told the server is going down */
	AsAddr wss;              /* the workstation's session socket */
	u32    last_rx;          /* ln_ms() of the last packet from the workstation */
	u32    tickle;           /* the request ID of our tickle, 0 = none */
} AfpsSess;

typedef struct AfpsFork {
	u8      used, rsrc, write, sess;
	u32     node;
	LnFile *f;
	AfpsAd  ad;              /* resource fork: where it is in the "._" file */
} AfpsFork;

/* an SPWrite waiting for its WriteContinue's answer */
typedef struct AfpsWrite {
	u8     used, sess;
	u32    reqid;            /* our WriteContinue request */
	AsReq  req;              /* the Write request, answered when the data has been written */
	u8     cmd[AS_ATP_DATA];
	size_t cmdlen;
} AfpsWrite;

/* FPEnumerate's window on a folder (afps_afp.c). The AppleShare client reads a folder in pages
 * (StartIndex 1, then on by what came back), and a folder may hold thousands of items, more
 * than the Mac bridge's memory takes as a list. So the folder's listing stays open and the
 * server keeps only a window of it: the entries around the page being read, packed into a
 * fixed buffer, in the order the share gives them. A page past the window reads on; a page
 * before it lists the folder again from the start. Memory: this buffer and the backend's own
 * listing buffer, whatever the folder's size (docs/mac.md, "Large folders"). */
#define AFPS_WIN_BYTES 16384
#define AFPS_AD_BITS   8192
typedef struct AfpsWin {
	u32    dir;              /* the folder's ID, 0 = none */
	LnDir *d;                /* its listing while there is more to read, else NULL */
	u32    when;             /* ln_ms() of the last use */
	u32    files_before, dirs_before;   /* the entries that went out of the front */
	size_t used;             /* bytes of buf in use */
	u32    buf[AFPS_WIN_BYTES / 4];     /* the entries (afps_afp.c, WinEnt), four-byte aligned */
	/* the folder's "._" files, as bits of their names' hashes, from a first look at the whole
	 * listing: a file whose bit is clear has no Finder info to read, which saves a lookup on
	 * the share for nearly every item (on Samba a lookup that fails reads the whole folder) */
	u8     ad[AFPS_AD_BITS / 8];
	u8     adknown;
} AfpsWin;
#define AFPS_WIN_IDLE_MS 30000   /* a listing left open this long is closed */

struct AfpsServer {
	AfpsConfig  cfg;
	const LnOps *ops;
	LnFs       *fs;
	AsTransport t;
	AfpsNames   names;
	AfpsSess    sess[AFPS_MAXSESS];
	AfpsFork    fork[AFPS_MAXFORK];
	AfpsWrite   wr[AFPS_MAXWRITE];
	u8          next_sid;
	struct { AsAddr a; u16 tid; } recent[AFPS_RECENT];
	unsigned    recent_pos;
	AfpsWin     win;
	struct { u32 id, when; u16 n; } offs[16];   /* recent folders' offspring counts */
	unsigned    offs_pos;
	u8          no_ad;       /* put_params: this item has no "._" file (the window's bits) */
	u8          scratch[AS_QUANTUM + 64];   /* replies are built here */
};

/* afps_afp.c: one AFP call. cmd/n: the command block; wdata/wlen: an SPWrite's data. The reply
 * goes to rep (at most rmax bytes), its length to *rlen; returns the AFP result code. */
s32  afps_afp_call(AfpsServer *s, AfpsSess *se, const u8 *cmd, size_t n, const u8 *wdata, size_t wlen,
                   u8 *rep, size_t rmax, size_t *rlen);
/* how many bytes an SPWrite with this command block will send (FPWrite, FPAddIcon) */
size_t afps_write_size(const u8 *cmd, size_t n);
/* a session ends: its forks close */
void afps_afp_close_session(AfpsServer *s, AfpsSess *se);
/* once a second: listings left open are closed */
void afps_afp_tick(AfpsServer *s);
void afps_afp_free(AfpsServer *s);

#endif
