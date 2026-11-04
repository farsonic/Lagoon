/*
 * Lagoon - SMB 2/3 backend internals shared by smb_conn.c (transport,
 * credits, signing, encryption), smb_auth.c (NTLMSSP/SPNEGO, keys),
 * smb_rpc.c (srvsvc share enumeration), smb_ops.c (LnOps) and the unit
 * tests. Written from MS-SMB2, MS-NLMP, MS-SPNG/RFC 4178, MS-SRVS, C706.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef SMB_INT_H
#define SMB_INT_H

#include "../ln_types.h"
#include "../ln_err.h"
#include "../ln_net.h"
#include "../ln_vfs.h"
#include "../ln_cipher.h"
#include "../ln_hash.h"
#include "../ln_sys.h"

/* commands */
enum {
	SMB2_NEGOTIATE = 0, SMB2_SESSION_SETUP = 1, SMB2_LOGOFF = 2, SMB2_TREE_CONNECT = 3,
	SMB2_TREE_DISCONNECT = 4, SMB2_CREATE = 5, SMB2_CLOSE = 6, SMB2_FLUSH = 7, SMB2_READ = 8,
	SMB2_WRITE = 9, SMB2_LOCK = 10, SMB2_IOCTL = 11, SMB2_CANCEL = 12, SMB2_ECHO = 13,
	SMB2_QUERY_DIRECTORY = 14, SMB2_CHANGE_NOTIFY = 15, SMB2_QUERY_INFO = 16, SMB2_SET_INFO = 17,
	SMB2_OPLOCK_BREAK = 18
};

/* header flags */
#define SMB2_FLAGS_SERVER_TO_REDIR 0x00000001
#define SMB2_FLAGS_ASYNC_COMMAND   0x00000002
#define SMB2_FLAGS_RELATED         0x00000004
#define SMB2_FLAGS_SIGNED          0x00000008

#define SMB2_HDR 64
#define SMB2_TF_HDR 52           /* transform header (encryption) */

/* dialects */
#define SMB_D202 0x0202
#define SMB_D210 0x0210
#define SMB_D300 0x0300
#define SMB_D302 0x0302
#define SMB_D311 0x0311

/* NTSTATUS values we look at */
#define ST_OK                      0x00000000u
#define ST_PENDING                 0x00000103u
#define ST_BUFFER_OVERFLOW         0x80000005u
#define ST_NO_MORE_FILES           0x80000006u
#define ST_MORE_PROCESSING         0xC0000016u
#define ST_END_OF_FILE             0xC0000011u
#define ST_LOGON_FAILURE           0xC000006Du
#define ST_ACCESS_DENIED           0xC0000022u
#define ST_NETWORK_SESSION_EXPIRED 0xC000035Cu
#define ST_USER_SESSION_DELETED    0xC0000203u
#define ST_NOT_SUPPORTED           0xC00000BBu
#define ST_INVALID_DEVICE_REQUEST  0xC0000010u
#define ST_FILE_CLOSED             0xC0000128u
#define ST_OBJECT_NAME_NOT_FOUND   0xC0000034u
#define ST_INVALID_PARAMETER       0xC000000Du

/* signing algorithms (also the 3.1.1 SIGNING_CAPABILITIES ids) */
enum { SMB_SIGN_HMAC = 0, SMB_SIGN_CMAC = 1, SMB_SIGN_GMAC = 2 };
/* ciphers (3.1.1 ENCRYPTION_CAPABILITIES ids) */
enum { SMB_C_NONE = 0, SMB_C_CCM128 = 1, SMB_C_GCM128 = 2, SMB_C_CCM256 = 3, SMB_C_GCM256 = 4 };

typedef struct SmbConn {
	LnSock *sock;
	int dead;                /* transport lost / out of sync: only reconnect helps */
	int timeout_ms;

	/* negotiated */
	u16 max_dialect;         /* client limit (url dialect=) */
	u16 dialect;
	u16 srv_secmode;
	u32 srv_caps;
	u8  srv_guid[16], cli_guid[16];
	u32 max_trans, max_read, max_write;
	int large_mtu;
	u16 cipher;              /* SMB_C_* the server accepted (3.x) */
	int sign_algo;           /* SMB_SIGN_* */
	int want_gmac;           /* offer AES-GMAC signing (3.1.1) */
	int offer_encrypt;       /* offer encryption capabilities */
	u16 cipher_only;         /* offer just this cipher (url cipher=), 0 = all */
	u8  preauth[64];         /* 3.1.1 connection preauth hash */

	/* credits and message ids */
	u64 next_mid;
	u32 credits;

	/* session / tree */
	u64 sid;
	u32 tid;
	u16 session_flags;       /* 1 guest, 2 null, 4 encrypt */
	int sign;                /* sign requests and require signed replies */
	int force_sign;          /* sign the next request even if signing is off (VALIDATE_NEGOTIATE) */
	int encrypt;             /* encrypt everything (session/share/url) */
	int keys;                /* session keys derived */
	u8  session_key[16];
	u8  sign_key[16];
	LnAes sign_aes;
	LnGcm *sign_gcm;         /* GMAC signing (heap) */
	LnGcm *enc_gcm, *dec_gcm;/* GCM ciphers (heap) */
	LnAes *enc_aes, *dec_aes;/* CCM ciphers (heap) */
	u8  nonce_salt[4];
	u64 nonce_ctr;

	/* buffers: tx holds [4 nbss][52 transform][64 hdr][body] */
	u8  *tx;
	size_t txcap;
	u8  *rx;                 /* raw frame */
	size_t rxcap;
	/* last reply */
	u8  *msg;                /* SMB2 header of the reply (in rx) */
	u32 msglen;
	u32 status;
	u8  *body;               /* msg + 64 */
	u32 blen;
	u32 reqlen;              /* plain length of the last request at tx+56 */
	int was_encrypted;
} SmbConn;

#define LN_LOG_ON(l) ((l) <= ln_log_level)

#define SMB_TX_OFF 56            /* offset of the SMB2 header in tx */

/* ---- smb_conn.c ---- */
int  smb_connect(SmbConn *c, const char *host, u16 port);
void smb_disconnect(SmbConn *c);  /* closes the socket, frees keys and buffers */
/* make room for a body of n bytes and return a pointer to it (zeroed) */
u8  *smb_body(SmbConn *c, size_t n);
/* send the request whose body (blen bytes) was built at smb_body(); wait
 * for the final reply (STATUS_PENDING interims are skipped). resp_bytes
 * is the expected reply payload (for the credit charge). Returns LN_OK
 * (check c->status) or a transport error (LN_ECONNRESET, LN_ECRYPTO ...). */
int  smb_call(SmbConn *c, u16 cmd, size_t blen, u32 resp_bytes);
/* verify the signature of the reply in c->msg with the current keys:
 * 0 ok, LN_ECRYPTO */
int  smb_verify(SmbConn *c);
/* set up signing/encryption keys from c->session_key (and preauth hash) */
int  smb_derive_keys(SmbConn *c, const u8 *preauth64);
/* compute the signature of an SMB2 message (header at m) */
void smb_sign_msg(SmbConn *c, const u8 *m, size_t len, u8 sig[16]);
/* largest single READ/WRITE payload we may send now (credits, server max) */
u32  smb_io_limit(SmbConn *c, u32 server_max, u32 cap);
/* NEGOTIATE (dialect, contexts, preauth) */
int  smb_negotiate(SmbConn *c);

/* SP800-108 counter mode KDF with HMAC-SHA256 (labels include their NUL) */
void smb_kdf(const u8 *key, size_t klen, const void *label, size_t llen, const void *ctx, size_t clen,
             u8 *out, int outbits);

/* ---- smb_auth.c ---- */
int  smb_session_setup(SmbConn *c, const LnCreds *cr, const char *host, int sign_required);

/* NTLM pieces (exposed for tests) */
void ntlm_ntowfv2(const char *user, const char *domain, const char *password, u8 out[16]);
/* NTProofStr and SessionBaseKey from ResponseKeyNT, server challenge and
 * the "temp" blob (MS-NLMP 3.3.2) */
void ntlm_v2_proof(const u8 key[16], const u8 srvchal[8], const u8 *temp, size_t tlen, u8 proof[16], u8 basekey[16]);
/* NTLMSSP MAC (extended session security + key exchange) */
void ntlm_mac(const u8 signkey[16], LnRc4 *seal, u32 seq, const u8 *msg, size_t n, u8 out[16]);

/* ---- smb_status.c ---- */
int smb_err(u32 status);
const char *smb_status_name(u32 status);

/* ---- small helpers (smb_conn.c) ---- */
u32  smb_ft2unix(u64 ft);
u64  smb_unix2ft(u32 t);
/* UTF-8 path relative to the share -> UTF-16LE with '\' separators;
 * returns bytes or LN_ENAMETOOLONG */
int  smb_path16(const char *prefix, const char *path, u8 *out, size_t max);

/* ---- smb_rpc.c ---- */
int smb_enum_shares(SmbConn *c, const char *host, int all, ln_share_cb cb, void *ud);

/* ---- tree/file helpers (smb_ops.c, used by smb_rpc.c) ---- */
int smb_tree_connect(SmbConn *c, const char *host, const char *share, u32 *flags, u32 *maxacc);
typedef struct SmbCreate {
	u32 access, attrs, share, disposition, options;
	/* out */
	u8  fid[16];
	u32 action, fattrs;
	u64 ctime, atime, mtime, chtime, alloc, eof;
	u64 diskid;              /* from the QFid context, 0 if none */
	int apple;               /* the server answered the AAPL context (macOS / vfs_fruit) */
} SmbCreate;
int smb_create(SmbConn *c, const u8 *name16, int nlen, SmbCreate *cr, int aapl);
int smb_close(SmbConn *c, const u8 fid[16]);

#endif
