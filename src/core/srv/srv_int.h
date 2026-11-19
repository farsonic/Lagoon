/*
 * Lagoon - SMB2 server internals shared by srv_conn.c (framing, NEGOTIATE,
 * sessions, signing, compounds, dispatch), srv_auth.c (SPNEGO/NTLMSSP and
 * NTLMv2 checking), srv_file.c (trees and file operations), srv_rpc.c
 * (srvsvc on IPC$), srv_names.c (NetBIOS/mDNS answers) and srv_loop.c (the
 * network). Written from MS-SMB2, MS-NLMP, MS-SPNG, MS-SRVS, MS-FSCC, C706.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef SRV_INT_H
#define SRV_INT_H

#include "../ln_srv.h"
#include "../ln_sys.h"
#include "../ln_hash.h"
#include "../ln_cipher.h"
#include "../smb/smb_int.h"

/* more NTSTATUS values (smb_int.h has the client's) */
#define ST_INVALID_INFO_CLASS      0xC0000003u
#define ST_INFO_LENGTH_MISMATCH    0xC0000004u
#define ST_NO_SUCH_FILE            0xC000000Fu
#define ST_BUFFER_TOO_SMALL        0xC0000023u
#define ST_OBJECT_NAME_INVALID     0xC0000033u
#define ST_OBJECT_NAME_COLLISION   0xC0000035u
#define ST_OBJECT_PATH_NOT_FOUND   0xC000003Au
#define ST_OBJECT_PATH_SYNTAX_BAD  0xC000003Bu
#define ST_SHARING_VIOLATION       0xC0000043u
#define ST_DELETE_PENDING          0xC0000056u
#define ST_DISK_FULL               0xC000007Fu
#define ST_INSUFFICIENT_RESOURCES  0xC000009Au
#define ST_MEDIA_WRITE_PROTECTED   0xC00000A2u
#define ST_FILE_IS_A_DIRECTORY     0xC00000BAu
#define ST_BAD_NETWORK_NAME        0xC00000CCu
#define ST_REQUEST_NOT_ACCEPTED    0xC00000D0u
#define ST_DIRECTORY_NOT_EMPTY     0xC0000101u
#define ST_NOT_A_DIRECTORY         0xC0000103u
#define ST_TOO_MANY_OPENED_FILES   0xC000011Fu
#define ST_CANNOT_DELETE           0xC0000121u
#define ST_FS_DRIVER_REQUIRED      0xC000019Cu
#define ST_NOT_FOUND               0xC0000225u
#define ST_NOT_A_REPARSE_POINT     0xC0000275u
#define ST_NAME_TOO_LONG           0xC0000106u
#define ST_INVALID_HANDLE          0xC0000008u
#define ST_NETWORK_NAME_DELETED    0xC00000C9u
#define ST_IO_DEVICE_ERROR         0xC0000185u

/* access mask bits */
#define A_READ_DATA     0x00000001u
#define A_WRITE_DATA    0x00000002u
#define A_APPEND_DATA   0x00000004u
#define A_READ_EA       0x00000008u
#define A_WRITE_EA      0x00000010u
#define A_EXECUTE       0x00000020u
#define A_READ_ATTR     0x00000080u
#define A_WRITE_ATTR    0x00000100u
#define A_DELETE        0x00010000u
#define A_READ_CONTROL  0x00020000u
#define A_WRITE_DAC     0x00040000u
#define A_WRITE_OWNER   0x00080000u
#define A_SYNCHRONIZE   0x00100000u
#define A_MAX_ALLOWED   0x02000000u
#define A_GENERIC_ALL   0x10000000u
#define A_GENERIC_EXEC  0x20000000u
#define A_GENERIC_WRITE 0x40000000u
#define A_GENERIC_READ  0x80000000u
#define A_ALL_RW        0x001F01FFu
#define A_ALL_RO        0x001200A9u
#define A_WRITE_ANY     (A_WRITE_DATA | A_APPEND_DATA | A_WRITE_EA | A_WRITE_ATTR | A_DELETE | A_WRITE_DAC | \
                         A_WRITE_OWNER | A_GENERIC_WRITE | A_GENERIC_ALL | 0x40u /* DELETE_CHILD */)

/* file attributes */
#define FA_READONLY  0x0001u
#define FA_HIDDEN    0x0002u
#define FA_SYSTEM    0x0004u
#define FA_DIRECTORY 0x0010u
#define FA_ARCHIVE   0x0020u
#define FA_NORMAL    0x0080u

typedef struct SrvTree SrvTree;
typedef struct SrvOpen SrvOpen;
typedef struct SrvSession SrvSession;

struct SrvTree {
	SrvTree *next;
	u32  id;
	int  share;              /* index into LnSrv shares, -1 = IPC$ */
	int  readonly;           /* share read-only, or guest on a share that is not writable */
	u32  maxacc;
};

/* directory listing state of an open directory */
typedef struct SrvDirState {
	LnDir *d;
	int   started;
	int   dots;              /* "." and ".." still to send: 2, 1, 0 */
	int   done;
	char  pattern[128];      /* UTF-8, "*" for all */
	int   have_pending;      /* an entry that did not fit last time */
	char  pname[256];
	LnStat pst;
	u32   index;
} SrvDirState;

struct SrvOpen {
	SrvOpen *next;
	u64  id;                 /* both halves of the FileId */
	SrvTree *tree;
	char *path;              /* UTF-8 relative to the share, "" = root */
	int  is_dir, is_pipe;
	u32  access;             /* granted */
	LnFile *f;               /* open for data, NULL otherwise */
	int  fflags;             /* LN_O_READ/WRITE it was opened with */
	int  written;            /* data written: re-apply a set time after close */
	int  delete_on_close;
	int  set_mtime;          /* SET_INFO gave a write time */
	u32  mtime;
	u64  pos;                /* FilePositionInformation */
	SrvDirState *dir;
	/* named pipe (srvsvc): pending output */
	u8  *pout;
	size_t poutlen, poutoff;
	u16  max_frag;
	int  bound;
};

struct SrvSession {
	SrvSession *next;
	u64  id;
	int  valid;              /* authenticated */
	int  guest, anon;
	char user[64];
	int  sign;               /* sign responses (and require signed requests) */
	u8   preauth[64];        /* 3.1.1 session preauth hash */
	SmbConn *k;              /* signing keys (smb_derive_keys / smb_sign_msg) */
	/* NTLMSSP exchange */
	u8  *neg;                /* client NEGOTIATE message */
	size_t neglen;
	u8  *chal;               /* our CHALLENGE message */
	size_t challen;
	u8  *mechlist;           /* the client's DER MechTypeList (for the mechListMIC) */
	size_t mechlen;
	int  spnego;             /* the client wraps tokens in SPNEGO */
	u8   srvchal[8];
	SrvTree *trees;
	u32  next_tid;
};

struct LnSrv {
	LnSrvCfg cfg;
	int nshares;
	LnSrvShare share[LN_SRV_MAX_SHARES];
	int nusers;
	struct { char name[64]; u8 nthash[16]; } user[LN_SRV_MAX_USERS];
	u8  guid[16];
	u64 start_ft;
	int nconns;
};

struct LnSrvConn {
	LnSrv *srv;
	char peer[48];
	int  negotiated;         /* an SMB2 NEGOTIATE succeeded */
	u16  dialect;
	u16  cli_secmode;
	u32  cli_caps;
	u8   cli_guid[16];
	u16  cli_dialects[16];
	int  ncli_dialects;
	int  sign_algo;          /* 3.1.1 SIGNING_CAPABILITIES choice */
	u8   preauth[64];        /* 3.1.1 connection preauth hash */
	u32  credits;            /* granted and not yet used */
	SrvSession *sessions;
	u64  next_sid;
	SrvOpen *opens;
	int  nopens;
	u64  next_fid;
	/* reply buffer: [4 NBSS][responses...] */
	u8  *tx;
	size_t txcap, txlen;
	/* the request being handled */
	const u8 *req;           /* SMB2 header */
	u32  reqlen;
	const u8 *body;          /* req + 64 */
	u32  blen;
	SrvSession *sess;        /* session of the request (may be NULL) */
	SrvTree *tree;
	u64  last_fid;           /* FileId of the last CREATE in a compound (related requests) */
	u32  last_status;
	u32  last_ms;            /* time of the last request (idle timeout) */
	size_t resp_off;         /* offset of the reply being built in tx */
};

/* ---- srv_conn.c ---- */
/* reserve n bytes of response body (zeroed); NULL when it does not fit */
u8  *srv_body(LnSrvConn *c, size_t n);
/* error response with status (ErrorData: n bytes, may be NULL) */
void srv_error(LnSrvConn *c, u32 status, const u8 *data, size_t n);
void srv_set_status(LnSrvConn *c, u32 status);
/* the request's FileId (16 bytes at p); resolves the compound "previous" id */
SrvOpen *srv_find_open(LnSrvConn *c, const u8 *p);
u32  srv_max_io(const LnSrvConn *c);
SrvSession *srv_find_session(LnSrvConn *c, u64 id);
void srv_session_free(LnSrvConn *c, SrvSession *s);
void srv_preauth_add(u8 h[64], const u8 *m, size_t n);
int  srv_utf16_to_utf8(const u8 *p, size_t bytes, char *out, size_t max);

/* ---- srv_auth.c ---- */
void srv_session_setup(LnSrvConn *c);
/* SPNEGO NegTokenInit2 for the NEGOTIATE response; returns its length */
size_t srv_spnego_hint(u8 *out);
/* NTLMv2 check (exposed for tests): ResponseKeyNT from the NT hash */
void srv_ntowfv2(const u8 nthash[16], const char *user, const char *domain, u8 out[16]);
/* 1 = NtChallengeResponse matches, basekey set */
int  srv_ntlmv2_check(const u8 nthash[16], const char *user, const char *domain, const u8 srvchal[8],
                      const u8 *ntresp, size_t ntlen, u8 basekey[16]);

/* ---- srv_file.c ---- */
void srv_tree_connect(LnSrvConn *c);
void srv_tree_disconnect(LnSrvConn *c);
void srv_create(LnSrvConn *c);
void srv_close(LnSrvConn *c);
void srv_flush(LnSrvConn *c);
void srv_read(LnSrvConn *c);
void srv_write(LnSrvConn *c);
void srv_query_directory(LnSrvConn *c);
void srv_query_info(LnSrvConn *c);
void srv_set_info(LnSrvConn *c);
void srv_ioctl(LnSrvConn *c);
void srv_lock(LnSrvConn *c);
void srv_close_open(LnSrvConn *c, SrvOpen *o);
void srv_tree_free(LnSrvConn *c, SrvSession *s, SrvTree *t);
u32  srv_status(int lnerr);
/* "a/b/c" from an SMB path (UTF-16LE, '\'); ST_* on a bad name, 0 ok */
u32  srv_path(LnSrvConn *c, const u8 *p16, size_t bytes, char *out, size_t max);

/* ---- srv_rpc.c ---- */
/* feed a DCE/RPC PDU written to \PIPE\srvsvc; the answer goes to o->pout */
int  srv_rpc_input(LnSrvConn *c, SrvOpen *o, const u8 *pdu, size_t n);

#endif
