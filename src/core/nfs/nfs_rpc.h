/*
 * Lagoon - NFS backend internals: XDR (RFC 4506), ONC RPC over TCP with
 * record marking and AUTH_SYS (RFC 5531), portmapper GETPORT (RFC 1833),
 * NFSv3 attribute decoding (RFC 1813). Shared by nfs_rpc.c, nfs_ops.c and
 * the unit tests (tests/t_nfs_unit.c).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef NFS_RPC_H
#define NFS_RPC_H

#include "../ln_types.h"
#include "../ln_err.h"
#include "../ln_net.h"
#include "../ln_vfs.h"

/* ---- program numbers ---- */
#define PMAP_PROG   100000u
#define PMAP_VERS   2u
#define PMAP_GETPORT 3u
#define MOUNT_PROG  100005u
#define MOUNT_VERS  3u
#define NFS_PROG    100003u
#define NFS_VERS    3u

enum { MNT3_NULL = 0, MNT3_MNT = 1, MNT3_DUMP = 2, MNT3_UMNT = 3, MNT3_UMNTALL = 4, MNT3_EXPORT = 5 };
enum {
	NFS3_NULL = 0, NFS3_GETATTR, NFS3_SETATTR, NFS3_LOOKUP, NFS3_ACCESS, NFS3_READLINK,
	NFS3_READ, NFS3_WRITE, NFS3_CREATE, NFS3_MKDIR, NFS3_SYMLINK, NFS3_MKNOD, NFS3_REMOVE,
	NFS3_RMDIR, NFS3_RENAME, NFS3_LINK, NFS3_READDIR, NFS3_READDIRPLUS, NFS3_FSSTAT,
	NFS3_FSINFO, NFS3_PATHCONF, NFS3_COMMIT
};

/* nfsstat3 values we treat specially */
#define NFS3ERR_NOENT       2
#define NFS3ERR_EXIST      17
#define NFS3ERR_NOTDIR     20
#define NFS3ERR_ISDIR      21
#define NFS3ERR_INVAL      22
#define NFS3ERR_STALE      70
#define NFS3ERR_BADHANDLE  10001
#define NFS3ERR_BAD_COOKIE 10003
#define NFS3ERR_NOTSUPP    10004
#define NFS3ERR_JUKEBOX    10008

/* ftype3 */
enum { NF3REG = 1, NF3DIR, NF3BLK, NF3CHR, NF3LNK, NF3SOCK, NF3FIFO };

/* ACCESS3 bits */
#define ACCESS3_READ    0x01
#define ACCESS3_LOOKUP  0x02
#define ACCESS3_MODIFY  0x04
#define ACCESS3_EXTEND  0x08
#define ACCESS3_DELETE  0x10
#define ACCESS3_EXECUTE 0x20

/* stable_how */
enum { NFS_UNSTABLE = 0, NFS_DATA_SYNC = 1, NFS_FILE_SYNC = 2 };

#define NFS_FHMAX 64

typedef struct NfsFh {
	u32 len;
	u8  data[NFS_FHMAX];
} NfsFh;

/* fattr3 */
typedef struct NfsAttr {
	u32 type, mode, nlink, uid, gid;
	u64 size, used, fsid, fileid;
	u32 atime, mtime, ctime;     /* seconds (nanoseconds dropped) */
} NfsAttr;

/* ---- XDR: one cursor type for encoding (pos <= cap) and decoding (pos <= len) ---- */
typedef struct NfsXdr {
	u8    *buf;
	size_t len;                  /* decode: bytes available */
	size_t cap;                  /* encode: buffer size */
	size_t pos;
	int    err;                  /* set on overflow / short data; sticky */
} NfsXdr;

void xdr_init_enc(NfsXdr *x, u8 *buf, size_t cap);
void xdr_init_dec(NfsXdr *x, const u8 *buf, size_t len);
void xdr_put_u32(NfsXdr *x, u32 v);
void xdr_put_u64(NfsXdr *x, u64 v);
void xdr_put_fixed(NfsXdr *x, const void *p, size_t n);          /* padded to 4 */
void xdr_put_opaque(NfsXdr *x, const void *p, size_t n);         /* length + data + pad */
void xdr_put_string(NfsXdr *x, const char *s);
void xdr_put_fh(NfsXdr *x, const NfsFh *fh);
u32  xdr_get_u32(NfsXdr *x);
u64  xdr_get_u64(NfsXdr *x);
void xdr_get_fixed(NfsXdr *x, void *p, size_t n);
/* variable opaque: returns a pointer into the buffer and the length, NULL on error / > max */
const u8 *xdr_get_opaque(NfsXdr *x, u32 *len, u32 max);
/* string into out (NUL terminated); LN_OK, LN_ENAMETOOLONG (skipped) or LN_EPROTO */
int  xdr_get_string(NfsXdr *x, char *out, size_t outmax);
void xdr_skip(NfsXdr *x, size_t n);
int  xdr_get_fh(NfsXdr *x, NfsFh *fh);
void xdr_get_fattr(NfsXdr *x, NfsAttr *a);
/* post_op_attr: returns 1 if attributes followed (stored in a, may be NULL) */
int  xdr_get_post_attr(NfsXdr *x, NfsAttr *a);
/* wcc_data: pre_op_attr + post_op_attr */
int  xdr_get_wcc(NfsXdr *x, NfsAttr *a);

/* ---- RPC ---- */
#define RPC_CREDMAX 400

/* AUTH_SYS (flavor 1) credential body; returns its length or -1 */
int  rpc_auth_sys(u8 *out, size_t max, u32 stamp, const char *machine, u32 uid, u32 gid,
                  const u32 *gids, int ngids);
/* start a call message in x (reserving 4 bytes for the record mark) */
void rpc_begin_call(NfsXdr *x, u32 xid, u32 prog, u32 vers, u32 proc, const u8 *cred, size_t credlen);
/* write the record mark (single, last fragment); returns total bytes to send */
size_t rpc_finish_call(NfsXdr *x);
/* read one record (all fragments) with rd() into *buf (grown with ln_realloc up to max);
 * *len = record size. */
typedef int (*rpc_read_fn)(void *ctx, void *buf, size_t n);
int  rpc_read_record(rpc_read_fn rd, void *ctx, u8 **buf, size_t *cap, size_t *len, size_t max);
/* check a reply record: LN_OK with *body = offset of the results,
 * RPC_XID_OTHER if it answers another call, or an LN_E* code */
#define RPC_XID_OTHER 1
int  rpc_check_reply(const u8 *p, size_t n, u32 xid, size_t *body);
/* last rejection detail for logs */
extern const char *rpc_last_error;

/* an RPC client connection (one program/version on one TCP port) */
typedef struct NfsRpc {
	LnSock *sock;
	char    host[128];
	u16     port;
	u32     prog, vers;
	u32     xid;
	int     secure;              /* bind a reserved local port (<1024) */
	int     timeout_ms;          /* per reply */
	u8      cred[RPC_CREDMAX];
	size_t  credlen;
	u8     *sbuf;                /* request */
	size_t  scap, slen;
	u8     *rbuf;                /* reply record */
	size_t  rcap, rlen;
	size_t  rmax;                /* largest accepted reply */
} NfsRpc;

int  rpc_open(NfsRpc *r, const char *host, u16 port, u32 prog, u32 vers, size_t scap, size_t rmax,
              int secure, int timeout_ms, const u8 *cred, size_t credlen);
int  rpc_connect(NfsRpc *r);
void rpc_disconnect(NfsRpc *r);
void rpc_close(NfsRpc *r);       /* disconnect + free buffers */
/* start a request: returns an encoder positioned after the call header */
void rpc_begin(NfsRpc *r, NfsXdr *x, u32 proc);
/* send x, wait for the reply; reconnects and retransmits once on a lost
 * connection or timeout. On LN_OK, *res decodes the results. */
int  rpc_call(NfsRpc *r, NfsXdr *x, NfsXdr *res);
/* resend the request in sbuf with a fresh xid (after NFS3ERR_JUKEBOX) */
int  rpc_recall(NfsRpc *r, NfsXdr *res);

/* portmapper: TCP port of prog/vers on host (0 = not registered) */
int  pmap_getport(const char *host, u16 pmport, u32 prog, u32 vers, int timeout_ms, u16 *port);

/* ---- NFS helpers ---- */
int  nfs_stat_to_ln(u32 st);
int  mnt_stat_to_ln(u32 st);
/* NfsAttr -> LnStat; prot from the mode bits for the credentials */
void nfs_attr_to_stat(const NfsAttr *a, u32 uid, u32 gid, const u32 *gids, int ngids, LnStat *st);
/* LN_P_* from an ACCESS3 result */
u32  nfs_access_to_prot(u32 acc, int type);

#endif
