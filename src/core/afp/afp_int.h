/*
 * Lagoon - AFP backend internals: DSI framing, AFP 3.x command codes,
 * bitmaps, errors, packing and parsing helpers, the login methods.
 * Shared by afp_dsi.c, afp_uam.c, afp_ops.c and tests/t_afp_unit.c.
 * Written from Apple's "AFP Reference" (AFP 3.x) and the DSI description
 * in "AppleShare IP / AFP over TCP".
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef AFP_INT_H
#define AFP_INT_H

#include "../ln_vfs.h"
#include "../ln_net.h"
#include "afp_crypto.h"

/* ---- DSI ---- */
#define DSI_HDR 16
enum { DSI_REQUEST = 0, DSI_REPLY = 1 };
enum {
	DSI_CLOSESESSION = 1, DSI_COMMAND = 2, DSI_GETSTATUS = 3, DSI_OPENSESSION = 4,
	DSI_TICKLE = 5, DSI_WRITE = 6, DSI_ATTENTION = 8
};
/* DSIOpenSession options */
enum { DSIOPT_SERVQUANT = 0, DSIOPT_ATTNQUANT = 1, DSIOPT_REPLCSIZE = 2 };
/* DSIAttention bits */
#define DSIATTN_SHUTDOWN  0x8000
#define DSIATTN_CRASH     0x4000
#define DSIATTN_MESSAGE   0x2000
#define DSIATTN_NORECONN  0x1000
#define DSIATTN_MINUTES   0x0fff

typedef struct DsiHdr {
	u8  flags, cmd;
	u16 id;
	u32 code;                /* error code (replies) or write offset (DSIWrite) */
	u32 len;                 /* total data length */
} DsiHdr;

void dsi_put_header(u8 h[DSI_HDR], int flags, int cmd, u16 id, u32 code, u32 len);
void dsi_get_header(const u8 h[DSI_HDR], DsiHdr *d);

/* one DSI session over TCP (afp_dsi.c) */
typedef struct AfpConn {
	LnSock *s;
	u16  reqid;
	u32  quantum;            /* server request quantum (largest request we may send) */
	u32  last_tx;            /* ln_ms() of our last packet, for tickles */
	int  timeout_ms;         /* per receive */
	int  attention;          /* last DSIAttention code seen (0 = none) */
	int  closed_by_server;
} AfpConn;
/* connect + DSIOpenSession */
int  afp_conn_open(AfpConn *c, const char *host, u16 port, int timeout_ms);
/* DSICloseSession (if polite) and close the socket */
void afp_conn_close(AfpConn *c, int polite);
/* send a DSICommand (or a DSIWrite carrying wdata after req) and wait for
 * its reply, answering tickles and attentions meanwhile. The reply data
 * goes to reply (up to rmax bytes, the rest is discarded), its length to
 * *rlen, the AFP result to *code. Returns LN_OK, LN_ECONNRESET (the
 * connection is closed then) or LN_EBREAK. */
int  afp_transact(AfpConn *c, int dsicmd, const u8 *req, size_t reqlen, const void *wdata, size_t wlen,
                  void *reply, size_t rmax, size_t *rlen, s32 *code);
/* keep-alive: drain whatever the server sent (tickles, attentions) and
 * send a DSITickle */
int  afp_conn_tickle(AfpConn *c);
/* DSIGetStatus (FPGetSrvrInfo before a session) on its own connection */
int  afp_getstatus(const char *host, u16 port, int timeout_ms, u8 *buf, size_t max, size_t *len);

/* ---- AFP commands ---- */
enum {
	FPCloseVol = 2, FPCloseFork = 4, FPCreateDir = 6, FPCreateFile = 7, FPDelete = 8,
	FPFlushFork = 11, FPGetForkParms = 14, FPGetSrvrInfo = 15, FPGetSrvrParms = 16,
	FPGetVolParms = 17, FPLogin = 18, FPLoginCont = 19, FPLogout = 20, FPMoveAndRename = 23,
	FPOpenVol = 24, FPOpenFork = 26, FPRename = 28, FPSetForkParms = 31,
	FPGetFileDirParms = 34, FPSetFileDirParms = 35, FPOpenDT = 48, FPCloseDT = 49,
	FPAddComment = 56, FPRemoveComment = 57, FPGetComment = 58, FPReadExt = 60,
	FPWriteExt = 61, FPLoginExt = 63, FPEnumerateExt = 66, FPEnumerateExt2 = 68
};

/* ---- AFP result codes ---- */
enum {
	kFPNoErr = 0,
	kFPAccessDenied = -5000, kFPAuthContinue = -5001, kFPBadUAM = -5002, kFPBadVersNum = -5003,
	kFPBitmapErr = -5004, kFPCantMove = -5005, kFPDenyConflict = -5006, kFPDirNotEmpty = -5007,
	kFPDiskFull = -5008, kFPEOFErr = -5009, kFPFileBusy = -5010, kFPFlatVol = -5011,
	kFPItemNotFound = -5012, kFPLockErr = -5013, kFPMiscErr = -5014, kFPNoMoreLocks = -5015,
	kFPNoServer = -5016, kFPObjectExists = -5017, kFPObjectNotFound = -5018, kFPParamErr = -5019,
	kFPRangeNotLocked = -5020, kFPRangeOverlap = -5021, kFPSessClosed = -5022,
	kFPUserNotAuth = -5023, kFPCallNotSupported = -5024, kFPObjectTypeErr = -5025,
	kFPTooManyFilesOpen = -5026, kFPServerGoingDown = -5027, kFPCantRename = -5028,
	kFPDirNotFound = -5029, kFPIconTypeError = -5030, kFPVolLocked = -5031,
	kFPObjectLocked = -5032, kFPContainsSharedErr = -5033, kFPIDNotFound = -5034,
	kFPIDExists = -5035, kFPDiffVolErr = -5036, kFPCatalogChanged = -5037,
	kFPSameObjectErr = -5038, kFPBadIDErr = -5039, kFPPwdSameErr = -5040,
	kFPPwdTooShortErr = -5041, kFPPwdExpiredErr = -5042, kFPInsideSharedErr = -5043,
	kFPInsideTrashErr = -5044, kFPPwdNeedsChangeErr = -5045, kFPPwdPolicyErr = -5046,
	kFPDiskQuotaExceeded = -5047
};
int afp_err(s32 code);                 /* kFP* -> LN_E* */

/* ---- server flags (FPGetSrvrInfo) ---- */
#define AFPSRV_COPYFILE     0x0001
#define AFPSRV_CHGPASSWD    0x0002
#define AFPSRV_NOSAVEPASSWD 0x0004
#define AFPSRV_SRVMSG       0x0008
#define AFPSRV_SRVSIG       0x0010
#define AFPSRV_TCPIP        0x0020
#define AFPSRV_NOTIFY       0x0040
#define AFPSRV_RECONNECT    0x0080
#define AFPSRV_DIRSERVICES  0x0100
#define AFPSRV_UTF8NAME     0x0200
#define AFPSRV_UUIDS        0x0400
#define AFPSRV_EXTSLEEP     0x0800
#define AFPSRV_SUPERCLIENT  0x8000

/* ---- volume bitmap / attributes ---- */
#define VOLBIT_ATTR       0x0001
#define VOLBIT_SIG        0x0002
#define VOLBIT_CDATE      0x0004
#define VOLBIT_MDATE      0x0008
#define VOLBIT_BDATE      0x0010
#define VOLBIT_ID         0x0020
#define VOLBIT_BFREE      0x0040
#define VOLBIT_BTOTAL     0x0080
#define VOLBIT_NAME       0x0100
#define VOLBIT_XBFREE     0x0200
#define VOLBIT_XBTOTAL    0x0400
#define VOLBIT_BSIZE      0x0800

#define VOLATTR_READONLY    0x0001
#define VOLATTR_PASSWORD    0x0002
#define VOLATTR_FILEIDS     0x0004
#define VOLATTR_CATSEARCH   0x0008
#define VOLATTR_BLANKPRIVS  0x0010
#define VOLATTR_UNIXPRIVS   0x0020
#define VOLATTR_UTF8NAMES   0x0040
#define VOLATTR_NONETUIDS   0x0080
#define VOLATTR_CASESENS    0x1000

/* ---- file / directory bitmaps (same bit = same field where they overlap) ---- */
#define FDBIT_ATTR     0x0001
#define FDBIT_PDID     0x0002
#define FDBIT_CDATE    0x0004
#define FDBIT_MDATE    0x0008
#define FDBIT_BDATE    0x0010
#define FDBIT_FINFO    0x0020
#define FDBIT_LNAME    0x0040
#define FDBIT_SNAME    0x0080
#define FDBIT_NODEID   0x0100
#define FBIT_DFLEN     0x0200
#define FBIT_RFLEN     0x0400
#define FBIT_XDFLEN    0x0800
#define FBIT_LAUNCH    0x1000
#define FDBIT_UTF8NAME 0x2000
#define FBIT_XRFLEN    0x4000
#define FDBIT_UNIXPR   0x8000
#define DBIT_OFFCNT    0x0200
#define DBIT_OWNERID   0x0400
#define DBIT_GROUPID   0x0800
#define DBIT_ACCESS    0x1000

/* attributes */
#define ATTR_INVISIBLE     0x0001
#define ATTR_MULTIUSER     0x0002
#define ATTR_SYSTEM        0x0004
#define ATTR_DOPEN         0x0008
#define ATTR_ROPEN         0x0010
#define ATTR_WRITEINHIBIT  0x0020   /* files only */
#define ATTR_BACKUPNEEDED  0x0040
#define ATTR_RENAMEINHIBIT 0x0080
#define ATTR_DELETEINHIBIT 0x0100
#define ATTR_SETCLEAR      0x8000

/* fork access modes */
#define AFP_ACC_READ      0x0001
#define AFP_ACC_WRITE     0x0002
#define AFP_ACC_DENYREAD  0x0010
#define AFP_ACC_DENYWRITE 0x0020

/* UNIX privileges: ua_permissions user-access byte (most significant) */
#define AR_USEARCH 0x01
#define AR_UREAD   0x02
#define AR_UWRITE  0x04
#define AR_UOWN    0x80

#define AFP_ROOT_DID   2
#define AFP_PATH_UTF8  3

/* AFP dates: signed seconds since 2000-01-01 00:00 UTC; 0x80000000 = unknown */
#define AFP_EPOCH_DELTA 946684800u
#define AFP_DATE_NONE   0x80000000u
u32 afp_date_to_unix(u32 d);
u32 afp_date_from_unix(u32 t);

/* ---- request builder ---- */
typedef struct AfpBuf {
	u8    *p;
	size_t len, max;
	int    err;              /* set when something did not fit */
} AfpBuf;
void afp_b_init(AfpBuf *b, u8 *mem, size_t max);
void afp_b_u8(AfpBuf *b, unsigned v);
void afp_b_u16(AfpBuf *b, unsigned v);
void afp_b_u32(AfpBuf *b, u32 v);
void afp_b_u64(AfpBuf *b, u64 v);
void afp_b_mem(AfpBuf *b, const void *p, size_t n);
void afp_b_pstr(AfpBuf *b, const char *s);          /* Pascal string (<= 255 bytes) */
void afp_b_pad(AfpBuf *b);                          /* to an even offset */
/* pathname: type 3 (UTF-8), text encoding hint 0, u16 length, then the
 * NFC path converted to NFD with '/' separators turned into NUL bytes. */
void afp_b_path(AfpBuf *b, const char *path);
/* AFPName for FPLoginExt: type 3, u16 length, bytes (no hint) */
void afp_b_name3(AfpBuf *b, const char *s);

/* ---- FPGetSrvrInfo ---- */
#define AFP_MAXUAM 16
enum { UAM_GUEST = 1, UAM_CLEARTXT = 2, UAM_DHCAST128 = 4, UAM_DHX2 = 8 };
typedef struct AfpSrvInfo {
	char machine[34];
	char name[128];          /* UTF-8 server name if given, else the Mac Roman one as is */
	u16  flags;
	int  version;            /* best common: 34, 33, 32, 31, 30; 0 = none */
	char version_str[16];    /* "AFP3.4" ... */
	u32  uams;               /* UAM_* offered */
} AfpSrvInfo;
int afp_parse_srvinfo(const u8 *p, size_t n, AfpSrvInfo *si);

/* ---- file/dir parameters ---- */
typedef struct AfpParams {
	int  isdir;
	u16  attr;
	u32  pdid, cdate, mdate, nodeid;   /* dates are Unix time */
	u64  size;
	u16  offspring;
	int  has_unix;
	u32  uid, gid, perms, ua;          /* ua: user, world, group, owner access bytes */
	char name[256];                    /* NFC UTF-8 (UTF8Name if requested) */
} AfpParams;
/* parse one parameter block for bitmap (file or dir layout) */
int afp_parse_params(const u8 *p, size_t n, u16 bitmap, int isdir, AfpParams *out);

/* ---- DHX2 / DHCAST128 client side math (afp_uam.c) ---- */
typedef struct AfpDhx {
	u16 id;
	size_t plen;               /* prime length in bytes */
	u8  p[512], ma[512];
	u8  key[16];               /* CAST-128 key: MD5(shared) for DHX2, shared for DHCAST128 */
	u8  cnonce[16], snonce[16];
	u8  msg[512 + 16];         /* LoginCont 1 payload */
} AfpDhx;
/* DHX2 step 1 reply (id, g, len, p, Mb) + our secret ra -> Ma, key */
int afp_dhx2_reply1(AfpDhx *x, const u8 *rep, size_t n, const u8 *ra, size_t ralen);
/* LoginCont 1 payload after the id: Ma || CAST(K, cnonce); returns length */
size_t afp_dhx2_cont1(AfpDhx *x, u8 *out);
/* check reply 2 (id + 32 encrypted bytes): clientNonce+1, saves serverNonce */
int afp_dhx2_reply2(AfpDhx *x, const u8 *rep, size_t n);
/* LoginCont 2 payload after the id: CAST(K, serverNonce+1 || password[256]) */
size_t afp_dhx2_cont2(AfpDhx *x, const char *password, u8 *out);
/* DHCAST128: Ma for the login, then the reply (id, Mb, 32 enc bytes) and
 * the continuation CAST(K, serverNonce+1 || password[64]) */
void afp_dhcast_ma(AfpDhx *x, const u8 *ra, size_t ralen);
int  afp_dhcast_reply(AfpDhx *x, const u8 *rep, size_t n, const u8 *ra, size_t ralen);
size_t afp_dhcast_cont(AfpDhx *x, const char *password, u8 *out);
/* 128-bit big-endian increment */
void afp_nonce_inc(u8 n[16]);

#endif
