/*
 * Lagoon - an AFP 2.1 file server over AppleTalk (ASP on ATP), backed by Lagoon's VFS.
 *
 * Why it exists: a classic Mac already has an AppleShare client in its System file, and the
 * Finder mounts what that client offers as an ordinary volume. Lagoon reaches modern shares over
 * TCP (SMB 2/3, NFS v3, AFP over TCP); this server offers one of them to the Mac's own AppleShare
 * client, inside the same Mac, so the Finder shows it on the desktop with no file system of
 * Lagoon's own (docs/mac.md, "Lagoon's bridge"). Because every backend implements LnOps
 * (ln_vfs.h), the server works the same on all three.
 *
 * The layers, from Inside AppleTalk, second edition (1990), chapters 11 (ASP) and 13 (AFP):
 *   afps_asp.c    the server end of ASP: GetStatus, OpenSess, Command, Write (with its
 *                 WriteContinue), Tickle, CloseSess, Attention; duplicate requests dropped
 *   afps_afp.c    the AFP 2.0/2.1 calls System 7's AppleShare client makes
 *   afps_names.c  Mac Roman names, the directory ID table, AFP pathnames
 *   afps_adouble.c  Finder info and resource forks in AppleDouble "._" files, as macOS keeps them
 * ATP itself stays outside: the transport (AsTransport) is the Mac's own .ATP driver on the Mac
 * (src/mac/bridge), or an in-memory one in the tests (tests/t_afpsrv.c). The core never calls
 * the Mac: it is plain C99 like the rest of src/core.
 *
 * One server serves one volume (the share) under one NBP name, to any number of sessions (the
 * Mac's own client opens one). Calls are made by one task at a time; afps_input may block in the
 * VFS while it works, which is why the Mac runs it on a thread of its own (src/mac/bridge).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef AFPS_H
#define AFPS_H

#include "../ln_vfs.h"

/* an AppleTalk socket address: network, node, socket (Inside AppleTalk 4-8) */
typedef struct AsAddr {
	u16 net;
	u8  node, socket;
} AsAddr;

/* ATP limits (Inside AppleTalk 9-7): 578 data bytes a packet, 8 packets a response */
#define AS_ATP_DATA   578
#define AS_ATP_MAXRSP 8
#define AS_QUANTUM    (AS_ATP_DATA * AS_ATP_MAXRSP)    /* 4624: the most one transaction carries */

/* a transaction request that arrived at the server's socket */
typedef struct AsReq {
	AsAddr   src;
	u16      tid;
	u8       xo;             /* exactly-once (Command, Write, OpenSess) */
	u8       bitmap;         /* the response packets the requester has room for */
	u8       user[4];        /* ATP user bytes: the ASP header */
	const u8 *data;
	size_t   len;
} AsReq;

/* what the server needs of ATP */
typedef struct AsTransport {
	void *ud;
	u8    socket;            /* the server's socket: session listening and session socket at once */
	/* answer req: user bytes on the first packet, data split into AS_ATP_DATA pieces (at most
	 * as many as req->bitmap allows; the server never gives more), EOM on the last */
	int  (*respond)(void *ud, const AsReq *req, const u8 user[4], const u8 *data, size_t len);
	/* start a transaction request from the server's socket to dst. xo: exactly-once; nresp:
	 * response packets wanted; retries -1 = until cancelled. The answer comes back with
	 * afps_reply(*id, ...); a cancelled request never answers */
	int  (*request)(void *ud, AsAddr dst, const u8 user[4], const u8 *data, size_t len, int xo,
	                int nresp, int timeout_s, int retries, u32 *id);
	void (*cancel)(void *ud, u32 id);
} AsTransport;

typedef struct AfpsConfig {
	char server[32];         /* server name (NBP object, FPGetSrvrInfo), Mac Roman, <= 31 */
	char volume[28];         /* the volume's name, Mac Roman, <= 27 (AFP 2.x) */
	char machine[17];        /* FPGetSrvrInfo machine type */
	int  readonly;
	int  no_guest;           /* refuse "No User Authent" */
	char user[32];           /* if set, "Cleartxt Passwrd" with this user name and password */
	char password[9];        /* AFP 2.x passwords are 8 bytes, NUL-padded */
} AfpsConfig;

typedef struct AfpsServer AfpsServer;

/* ops/fs: a mounted share the server uses (and does not unmount). The transport is copied. */
AfpsServer *afps_new(const AfpsConfig *cfg, const LnOps *ops, LnFs *fs, const AsTransport *t);
/* tells open sessions the server is going down now (ASP Attention, AFP's code $8000); the server
 * goes on answering, so that the clients can log out and put their volumes away */
void afps_shutdown(AfpsServer *s);
/* closes what sessions are left (CloseSess; Attention first if afps_shutdown was not called)
 * and frees the server */
void afps_free(AfpsServer *s);
/* a request arrived */
void afps_input(AfpsServer *s, const AsReq *req);
/* a request the server sent was answered (err 0, the response packets' data in order) or
 * failed (err < 0: retries exhausted) */
void afps_reply(AfpsServer *s, u32 id, int err, const u8 *data, size_t len);
/* about once a second: sessions whose other end has been silent for two minutes close */
void afps_tick(AfpsServer *s);
/* sessions open now */
int  afps_sessions(const AfpsServer *s);
/* the status block FPGetSrvrInfo / ASP GetStatus returns (for tests) */
size_t afps_status(const AfpsServer *s, u8 *out, size_t max);

/* ---- the multinode in front of the server (afps_relay.c) ----
 * System 7's AppleShare client will not use a server on its own node (it gives up with
 * afpSameNodeErr, -5063, before it sends a packet). So on the Mac the server's name is answered
 * for from a second node of the same Mac, a multinode (Inside Macintosh: Networking, chapter
 * 12), and what the client sends there is passed on to the server's socket on the user node,
 * and back. The server and its ATP stay on the user node, on the Mac's own .ATP. */

/* an NBP lookup (DDP type 2: BrRq or LkUp, Inside AppleTalk 7-15) for object:type@zone? If it
 * matches, the LkUp-Reply naming 'me' goes into out (its length returned) and *to is where it
 * goes; 0 otherwise. Wildcards: "=" for a whole field, one "\xC5" (the Mac's approximately-
 * equal sign) within one; letters compare without case; any zone is taken for ours. */
size_t afps_nbp_answer(const u8 *nbp, size_t n, const char *object, const char *type, AsAddr me,
                       u8 *out, size_t max, AsAddr *to);

typedef struct AfpsRelay {
	AsAddr server;           /* the server's socket on the user node */
	AsAddr vnode;            /* the multinode (net, node) and the socket clients use there */
	u16    cnet;             /* the client last heard from */
	u8     cnode, have_client;
} AfpsRelay;
/* a datagram that came to the multinode: hdr is its long DDP header (13 bytes, Inside
 * AppleTalk 4-16), rewritten in place for passing on (the checksum dropped). Returns 1 to send
 * it on: client to vnode:socket goes to the server, from vnode:client socket; server to
 * vnode:x goes to the client's socket x, from vnode:socket. 0: not ours to pass on. */
int afps_relay(AfpsRelay *r, u8 hdr[13]);

#endif
