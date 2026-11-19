/*
 * Lagoon - the SMB2 file server (`Lagoon SERVE`): shares Amiga folders with
 * Windows, macOS and Linux. Portable like the rest of src/core: every shared
 * folder is an LnOps backend (ln_vfs.h) - a host directory in the native
 * tests (src/host/fs_posix.c), dos.library on the Amiga (src/amiga/fs_dos.c),
 * or the "mem" backend in unit tests.
 *
 * Protocol: SMB 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1 (signing with HMAC-SHA256,
 * AES-CMAC or AES-GMAC; no encryption), the SMB1 multi-protocol NEGOTIATE
 * answered with an SMB2 upgrade, NTLMSSP in SPNEGO with NTLMv2 checked
 * against NT hashes (guest and anonymous logons when a share allows guests),
 * compound requests, IPC$ with \PIPE\srvsvc (share lists by DCE/RPC), and the
 * file operations Windows, macOS and smbclient use. See docs/server.md.
 *
 * Layers: LnSrv holds the configuration; an LnSrvConn is one client
 * connection, fed whole SMB messages (ln_srv_conn_input) so it can be tested
 * without sockets; ln_srv_serve() is the network loop (TCP 445/139, NetBIOS
 * name service on UDP 137, mDNS on UDP 5353) with several clients at once.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_SRV_H
#define LN_SRV_H

#include "ln_types.h"
#include "ln_err.h"
#include "ln_vfs.h"
#include "ln_net.h"

#define LN_SRV_MAX_SHARES 16
#define LN_SRV_MAX_USERS  16

typedef struct LnSrvShare {
	char name[32];           /* the name clients see ("Work") */
	char comment[64];
	char path[128];          /* shown in share lists (level 2), may be "" */
	const LnOps *ops;        /* the folder, opened by the caller */
	LnFs *fs;
	int  readonly;
	int  guest;              /* guests and anonymous clients may use it */
	char users[128];         /* allowed users (spaces/commas), "" = every user */
} LnSrvShare;

typedef struct LnSrvCfg {
	char name[16];           /* computer / NetBIOS name ("AMIGA") */
	char domain[16];         /* workgroup ("WORKGROUP") */
	char comment[64];        /* server comment */
	int  sign_required;      /* refuse unsigned requests (no guests then) */
	u16  max_dialect;        /* 0 = 0x0311 */
	u32  max_io;             /* largest READ/WRITE, 0 = 65536 */
	int  max_conns;          /* clients at once, 0 = 8 */
	int  max_opens;          /* open files per connection, 0 = 64 */
	int  name_max;           /* longest file name the folders take, 0 = 255 */
} LnSrvCfg;

typedef struct LnSrv LnSrv;
typedef struct LnSrvConn LnSrvConn;

LnSrv *ln_srv_new(const LnSrvCfg *cfg);
void   ln_srv_free(LnSrv *s);            /* does not unmount the shares' file systems */
int    ln_srv_add_share(LnSrv *s, const LnSrvShare *sh);
int    ln_srv_add_user(LnSrv *s, const char *name, const u8 nthash[16]);
int    ln_srv_has_guest_share(const LnSrv *s);
const LnSrvCfg *ln_srv_cfg(const LnSrv *s);
void   ln_srv_set_max_dialect(LnSrv *s, u16 d);   /* tests: 0x0202 ... 0x0311 */

/* one client connection. peer is shown in logs. */
LnSrvConn *ln_srv_conn_new(LnSrv *s, const char *peer);
void       ln_srv_conn_free(LnSrvConn *c);   /* closes its open files */
/* process one message (the NetBIOS session payload, without the 4-byte
 * length): out and outlen give the reply including its 4-byte NBSS header, valid
 * until the next call (*outlen 0 = nothing to send). msg may be modified
 * (signature checks zero the signature field in place). LN_OK, or a negative
 * code when the connection must be dropped (bad framing, encryption asked). */
int        ln_srv_conn_input(LnSrvConn *c, u8 *msg, size_t len, const u8 **out, size_t *outlen);

/* ---- network ---- */
typedef struct LnSrvNet {
	u16 port;                /* SMB over TCP, 0 = 445 */
	u16 nbt_port;            /* NetBIOS session service, 0 = none (139 usual) */
	u16 nbns_port;           /* NetBIOS name service, 0 = none (137 usual) */
	u16 mdns_port;           /* mDNS responder, 0 = none (5353 usual) */
	int idle_minutes;        /* drop a connection idle this long (no open files), 0 = 20 */
} LnSrvNet;

/* serve until poll_cb returns non-zero (it is called at least once a
 * second; its value is returned) or Ctrl-C (LN_EBREAK). LN_EINUSE when the
 * port is taken. */
int ln_srv_serve(LnSrv *s, const LnSrvNet *n, int (*poll_cb)(void *ud), void *ud);

/* ---- from lagoon.conf (srv_conf.c) ----
 * build a server from c's server/export/user lines; open_share opens each
 * export's folder (platform specific). Exports that fail to open are left
 * out and logged (*failed counts them). NULL when out of memory. */
typedef int (*ln_srv_open_fn)(void *ud, const char *path, int readonly, const LnOps **ops, LnFs **fs);
struct LnConf;
LnSrv *ln_srv_from_conf(const struct LnConf *c, ln_srv_open_fn open_share, void *ud, int *failed);
/* unmount the shares' file systems, then ln_srv_free */
void   ln_srv_free_all(LnSrv *s);

/* ---- name services (srv_names.c), packet level for tests ----
 * answer a NetBIOS name service packet for our name / workgroup: the reply
 * length (0 = no answer) */
int ln_srv_nbns_answer(const LnSrv *s, const LnAddr *me, const u8 *pkt, size_t len, u8 *out, size_t outmax);
/* answer an mDNS query: reply length (0 = none); *unicast set when it must
 * go back to the sender (legacy unicast / QU) instead of the group */
int ln_srv_mdns_answer(const LnSrv *s, const LnAddr *me, u16 port, const u8 *pkt, size_t len, int from_5353,
                       u8 *out, size_t outmax, int *unicast);
/* unsolicited announcement of our service and host name */
int ln_srv_mdns_announce(const LnSrv *s, const LnAddr *me, u16 port, u8 *out, size_t outmax);

#endif
