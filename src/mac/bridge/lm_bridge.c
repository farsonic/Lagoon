/*
 * Lagoon on the classic Mac OS: the AppleShare bridge. A share Lagoon reaches over TCP is
 * offered to the Mac's own AppleShare client as an AFP server on this Mac's own AppleTalk node,
 * and mounted on the desktop like any AppleShare volume (docs/mac.md, "Lagoon's bridge").
 *
 * What it uses of the Mac (Inside Macintosh: Networking, 1994; the parameter blocks are its
 * assembly-language summaries, chapters 2, 6 and 12, and Technote NW 13): the .ATP driver for
 * the transactions (POpenATPSkt, PGetRequest, PSendResponse, PNSendRequest, PKillSendReq,
 * PCloseATPSkt), which keeps exactly-once responses for retransmission itself, and the .MPP
 * driver for a multinode (AddNode, NetWrite, RemoveNode). The multinode is there because the
 * AppleShare client refuses a server on its own node (afpSameNodeErr, -5063: the first test):
 * the server's name is answered for from the multinode, and what clients send the multinode is
 * passed on to the server's .ATP socket on the user node and back (src/core/afpsrv/
 * afps_relay.c). .MPP loops datagrams between the user node and its multinodes itself, so the
 * bridge needs no network: with Lagoon EtherTalk (which gives .MPP multinodes) it works whether
 * the Ethernet has anybody on it or not. The AFP server above it all is src/core/afpsrv.
 *
 * Why a thread. The AppleShare client is called synchronously by whatever program is in
 * front: the Finder asks for a folder's contents with a File Manager call and spins until the
 * answer is there, and System 7 switches programs only at WaitNextEvent. So an AFP server that
 * answered from Lagoon's event loop would never be asked again once the Finder waits on it.
 * The server therefore runs at deferred-task time, which comes after every interrupt whatever
 * program is running, spinning or not. But the server's work is the VFS (SMB, NFS or AFP over
 * TCP through Riptide), which waits for the network in many places. So it runs on a thread of
 * its own: a second stack, switched to from a deferred task (bridge_glue.S) and switched away
 * from whenever it waits, Riptide's waits included (the thread's Riptide client yields to here,
 * mac_main.c). A Time Manager task asks for the deferred task every few milliseconds while the
 * thread has something to wait for, and every AppleTalk call's completion asks for it at once.
 *
 * The rules that follow from running at deferred-task time, and how they are kept:
 *   - no Memory Manager: the thread's ln_alloc comes from a pool (lm_pool.c) taken at start;
 *   - no Toolbox: the host name and time zone are looked up at start, in the application;
 *   - Riptide's core is one program's at a time: when the application is inside it
 *     (lm_app_core, net_mac.c) the deferred task leaves the thread alone and tries again;
 *   - the stack sniffer (a VBL task that takes a stack pointer below the heap's top for a
 *     collision, System Error 28) is switched off while the thread runs (StkLowPt $110 = 0);
 *   - the drivers are opened, and the socket made, by the application before the thread starts.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../../core/ln_sys.h"
#include "../../core/ln_net.h"
#include "../../core/afpsrv/afps_int.h"
#include "lm_bridge.h"

void *mm_alloc(unsigned long n);
void  mm_free(void *p);
void  lm_yield(void *arg);                       /* mac_main.c: the application's wait */

/* bridge_glue.S */
void  lmb_switch(void **save_sp, void *load_sp);
void  lmb_thread_start(void);
void  lmb_tm_entry(void);
void  lmb_dt_entry(void);
void  lmb_done_entry(void);
short lmb_open(void *pb);
short lmb_control(void *pb);
short lmb_control_async(void *pb);
short lmb_control_immed(void *pb);
short lmb_volmount(void *pb);
void  lmb_instime(void *tm);
void  lmb_rmvtime(void *tm);
void  lmb_primetime(void *tm, long ms);
short lmb_dtinstall(void *dt);
unsigned short lmb_irq_off(void);
void  lmb_irq_restore(unsigned short sr);
extern void *lm_a5;                              /* mac_thunks.S */

#define LM_STKLOWPT (*(volatile unsigned long *)0x110)

/* ---- parameter blocks (Inside Macintosh: Networking, the assembly-language summaries) ---- */
#define PB_SIZE      64
#define PB_COMPL     12          /* ioCompletion */
#define PB_RESULT    16          /* ioResult: 1 while the call runs */
#define PB_USERDATA  18          /* ATP user bytes */
#define PB_REQTID    22
#define PB_REFNUM    24
#define PB_CSCODE    26
#define PB_SOCKET    28          /* atpSocket; NBP interval */
#define PB_FLAGS     29          /* atpFlags; NBP count */
#define PB_ADDR      30          /* addrBlock; NBP entityPtr */
#define PB_REQLEN    34          /* reqLength; NBP verifyFlag */
#define PB_REQPTR    36
#define PB_BDS       40
#define PB_NBUFS     44          /* numOfBuffs; bitMap of a request; aKillQEl */
#define PB_TIMEOUT   45          /* timeOutVal; bdsSize of a response */
#define PB_NRESPS    46          /* numOfResps; transID of a response */
#define PB_RETRY     47
/* .MPP calls */
#define CS_SETSELFSEND  256
#define CS_GETATALKINFO 258
#define CS_NETWRITE     261
#define CS_ADDNODE      262
#define CS_REMOVENODE   263
#define MN_TRYAGAIN     -1021        /* AddNode: try again at once (Technote NW 13) */
/* .ATP calls */
#define CS_NSENDREQUEST 248
#define CS_CLOSEATPSKT  250
#define CS_SENDRESPONSE 252
#define CS_GETREQUEST   253
#define CS_OPENATPSKT   254
#define CS_KILLSENDREQ  258
/* atpFlags */
#define ATPF_EOM 0x10
#define ATPF_XO  0x20
/* a buffer data structure element: buffSize, buffPtr, dataSize, userBytes */
#define BDS_SIZE 12

#define W16(p, o) (*(volatile short *)((unsigned char *)(p) + (o)))
#define W32(p, o) (*(volatile long *)((unsigned char *)(p) + (o)))
#define B8(p, o)  (*(volatile unsigned char *)((unsigned char *)(p) + (o)))

/* ---- the bridge's state, one share at a time ---- */
#define NGETREQ 4
#define NRSP    8
#define NREQ    8
#define STACK_SIZE (64 * 1024L)
#define POOL_SIZE  (768 * 1024L)

typedef struct Rsp { unsigned char pb[PB_SIZE]; unsigned char bds[AS_ATP_MAXRSP * BDS_SIZE]; u8 data[AS_QUANTUM]; int busy; } Rsp;
typedef struct Req {
	unsigned char pb[PB_SIZE];
	unsigned char bds[AS_ATP_MAXRSP * BDS_SIZE];
	u8   data[8];
	u8   rbuf[AS_QUANTUM];
	u32  id;
	int  busy, cancelled;
} Req;
typedef struct Get { unsigned char pb[PB_SIZE]; u8 buf[AS_ATP_DATA]; int armed; } Get;

typedef struct Bridge {
	Get  get[NGETREQ];
	Rsp  rsp[NRSP];
	Req  req[NREQ];
	struct { unsigned char pb[PB_SIZE]; unsigned char wds[20]; u8 hdr[18]; u8 data[AS_ATP_DATA + 8]; } nw[4];
	unsigned char kill_pb[PB_SIZE];
	unsigned char stack[STACK_SIZE];
	unsigned char pool[POOL_SIZE];
} Bridge;

static Bridge *br;
static short mpp_ref, atp_ref;
static u8 sock;                                  /* our ATP socket */
static int old_self = -1;                        /* intranode delivery as it was */
static volatile int state, last_err, last_oserr;
static volatile int stop_wanted;
static AsAddr user_node, vnode;                  /* our user node, and the multinode */
static int have_vnode;
static AfpsRelay relay;

/* the multinode's datagrams, put here by its receive routine (bridge_glue.S) at interrupt time:
 * what .MPP had in its Read Header Area (the LAP header, then the long DDP header), then the
 * rest of the datagram. A slot is full while len is not 0. */
#define MN_SLOTS 8
struct mn_slot { volatile unsigned short len, rha; u8 buf[620]; };
struct mn_slot lmb_mn_ring[MN_SLOTS];
volatile unsigned long lmb_mn_head;
static unsigned long mn_tail;
void lmb_mn_recv(void);
static char url[LN_URL_MAX + 64];
static LnCreds creds;
static char share_name[64];
static u8 srv_name[33], vol_name[29];            /* Pascal strings, Mac Roman, and a NUL after */
static AfpsServer *srv;
static u32 req_gen;

/* the thread */
volatile int lmb_in_thread;
static void *host_sp, *thread_sp;
static volatile int alive, dt_queued, wanted_ms = 10;
static unsigned long saved_stklowpt;
static struct { long qlink; short qtype; void (*addr)(void); long count, wake, res; } tm;
static struct { long qlink; short qtype, flags; void (*addr)(void); long param, res; } dt;
static volatile unsigned long n_tm, n_dt, n_run, n_busy;     /* for the log: is it running? */

/* ---- scheduling (interrupt time) ---- */
static void ask_dt(void)
{
	unsigned short sr = lmb_irq_off();
	if (alive && !dt_queued) {
		dt_queued = 1;
		lmb_dtinstall(&dt);
	}
	lmb_irq_restore(sr);
}

/* the completion routine of every asynchronous call the thread makes */
void lmb_kick(void) { ask_dt(); }

void lmb_tm(void)
{
	if (!alive)
		return;
	n_tm++;
	ask_dt();
	lmb_primetime(&tm, wanted_ms);
}

void lmb_dt(void)
{
	dt_queued = 0;
	n_dt++;
	if (!alive || lmb_in_thread)
		return;
	if (lm_app_core) {
		n_busy++;
		return;                                  /* Lagoon is in Riptide's core: next time */
	}
	n_run++;
	saved_stklowpt = LM_STKLOWPT;
	LM_STKLOWPT = 0;                             /* no stack sniffer on the thread's stack */
	lmb_in_thread = 1;
	lmb_switch(&host_sp, thread_sp);
	lmb_in_thread = 0;
	LM_STKLOWPT = saved_stklowpt;
}

/* the thread waits: back to the deferred task, again in ms milliseconds or when a call ends */
void lmb_thread_yield(unsigned ms)
{
	wanted_ms = ms < 2 ? 2 : (int)ms;
	lmb_switch(&thread_sp, host_sp);
}

static void wait_pb(unsigned char *pb)
{
	while (W16(pb, PB_RESULT) > 0)
		lmb_thread_yield(5);
}

static void pb_init(unsigned char *pb, short ref, short cs)
{
	memset(pb, 0, PB_SIZE);
	W32(pb, PB_COMPL) = (long)lmb_done_entry;
	W16(pb, PB_REFNUM) = ref;
	W16(pb, PB_CSCODE) = cs;
}

/* ---- the server's transport on .ATP ---- */
static void put_addr(unsigned char *pb, AsAddr a)
{
	W16(pb, PB_ADDR) = (short)a.net;
	B8(pb, PB_ADDR + 2) = a.node;
	B8(pb, PB_ADDR + 3) = a.socket;
}

static int t_respond(void *ud, const AsReq *q, const u8 user[4], const u8 *data, size_t len)
{
	Rsp *r = NULL;
	int i, n;
	(void)ud;
	while (!r) {
		for (i = 0; i < NRSP && !r; i++)
			if (!br->rsp[i].busy || W16(br->rsp[i].pb, PB_RESULT) <= 0)
				r = &br->rsp[i];
		if (!r)
			lmb_thread_yield(5);                 /* every response still waits for its release */
	}
	if (len > AS_QUANTUM)
		len = AS_QUANTUM;
	memcpy(r->data, data, len);
	n = len ? (int)((len + AS_ATP_DATA - 1) / AS_ATP_DATA) : 1;
	memset(r->bds, 0, sizeof r->bds);
	for (i = 0; i < n; i++) {
		unsigned char *e = r->bds + i * BDS_SIZE;
		size_t off = (size_t)i * AS_ATP_DATA, k = len - off < AS_ATP_DATA ? len - off : AS_ATP_DATA;
		if (!len)
			k = 0;
		W16(e, 0) = (short)k;
		W32(e, 2) = (long)(r->data + off);
		if (i == 0)
			memcpy(e + 8, user, 4);
	}
	pb_init(r->pb, atp_ref, CS_SENDRESPONSE);
	B8(r->pb, PB_SOCKET) = sock;
	B8(r->pb, PB_FLAGS) = ATPF_EOM;
	put_addr(r->pb, q->src);
	W32(r->pb, PB_BDS) = (long)r->bds;
	B8(r->pb, PB_NBUFS) = (unsigned char)n;
	B8(r->pb, PB_TIMEOUT) = (unsigned char)n;    /* bdsSize */
	W16(r->pb, PB_NRESPS) = (short)q->tid;       /* transID */
	r->busy = 1;
	W16(r->pb, PB_RESULT) = 1;
	lmb_control_async(r->pb);
	return LN_OK;
}

static int t_request(void *ud, AsAddr dst, const u8 user[4], const u8 *data, size_t len, int xo, int nresp,
                     int timeout_s, int retries, u32 *id)
{
	Req *r = NULL;
	int i;
	(void)ud;
	for (i = 0; i < NREQ && !r; i++)
		if (!br->req[i].busy)
			r = &br->req[i];
	if (!r)
		return LN_ENOMEM;
	memset(r->bds, 0, sizeof r->bds);
	if (nresp < 1) nresp = 1;
	if (nresp > AS_ATP_MAXRSP) nresp = AS_ATP_MAXRSP;
	for (i = 0; i < nresp; i++) {
		W16(r->bds + i * BDS_SIZE, 0) = AS_ATP_DATA;
		W32(r->bds + i * BDS_SIZE, 2) = (long)(r->rbuf + i * AS_ATP_DATA);
	}
	if (len > sizeof r->data)
		len = sizeof r->data;
	memcpy(r->data, data, len);
	pb_init(r->pb, atp_ref, CS_NSENDREQUEST);
	memcpy(r->pb + PB_USERDATA, user, 4);
	B8(r->pb, PB_SOCKET) = sock;
	B8(r->pb, PB_FLAGS) = xo ? ATPF_XO : 0;
	put_addr(r->pb, dst);
	W16(r->pb, PB_REQLEN) = (short)len;
	W32(r->pb, PB_REQPTR) = (long)r->data;
	W32(r->pb, PB_BDS) = (long)r->bds;
	B8(r->pb, PB_NBUFS) = (unsigned char)nresp;
	B8(r->pb, PB_TIMEOUT) = (unsigned char)(timeout_s > 0 ? timeout_s : 1);
	B8(r->pb, PB_RETRY) = (unsigned char)(retries < 0 ? 255 : retries);   /* 255: for ever */
	r->id = (++req_gen << 8) | (u32)(r - br->req + 1);
	r->busy = 1;
	r->cancelled = 0;
	*id = r->id;
	W16(r->pb, PB_RESULT) = 1;
	lmb_control_async(r->pb);
	return LN_OK;
}

static void t_cancel(void *ud, u32 id)
{
	unsigned k = (id & 0xFF) - 1;
	Req *r;
	(void)ud;
	if (k >= NREQ)
		return;
	r = &br->req[k];
	if (!r->busy || r->id != id)
		return;
	r->cancelled = 1;
	if (W16(r->pb, PB_RESULT) > 0) {
		pb_init(br->kill_pb, atp_ref, CS_KILLSENDREQ);
		W32(br->kill_pb, PB_NBUFS) = (long)r->pb;    /* aKillQEl */
		W16(br->kill_pb, PB_RESULT) = 1;
		lmb_control_async(br->kill_pb);
		wait_pb(br->kill_pb);
	}
}

static void arm(Get *g)
{
	pb_init(g->pb, atp_ref, CS_GETREQUEST);
	B8(g->pb, PB_SOCKET) = sock;
	W16(g->pb, PB_REQLEN) = AS_ATP_DATA;
	W32(g->pb, PB_REQPTR) = (long)g->buf;
	g->armed = 1;
	W16(g->pb, PB_RESULT) = 1;
	lmb_control_async(g->pb);
}

/* look at every call that has ended; returns whether there was anything */
static int poll_calls(void)
{
	int i, any = 0;
	for (i = 0; i < NGETREQ; i++) {
		Get *g = &br->get[i];
		short res;
		if (!g->armed || (res = W16(g->pb, PB_RESULT)) > 0)
			continue;
		g->armed = 0;
		any = 1;
		if (res == 0 && srv) {
			AsReq q;
			memset(&q, 0, sizeof q);
			q.src.net = (u16)W16(g->pb, PB_ADDR);
			q.src.node = B8(g->pb, PB_ADDR + 2);
			q.src.socket = B8(g->pb, PB_ADDR + 3);
			/* the transaction ID: in reqTID when atpFlags says it is valid (tidValid, bit 1),
			   else where Inside Macintosh II had it, transID at 46: System 7.1's .ATP puts it
			   there (the testbed: reqTID stayed 0 and the client never took the answer) */
			q.tid = (u16)((B8(g->pb, PB_FLAGS) & 0x02) ? W16(g->pb, PB_REQTID) : W16(g->pb, PB_NRESPS));
			q.xo = (B8(g->pb, PB_FLAGS) & ATPF_XO) != 0;
			q.bitmap = B8(g->pb, PB_NBUFS);
			memcpy(q.user, g->pb + PB_USERDATA, 4);
			q.data = g->buf;
			q.len = (size_t)(unsigned short)W16(g->pb, PB_REQLEN);
			afps_input(srv, &q);
		}
		if (!stop_wanted && res != -1105)        /* reqAborted: the socket is closing */
			arm(g);
	}
	for (i = 0; i < NREQ; i++) {
		Req *r = &br->req[i];
		short res;
		if (!r->busy || (res = W16(r->pb, PB_RESULT)) > 0)
			continue;
		r->busy = 0;
		any = 1;
		if (!r->cancelled && srv) {
			/* the response packets' data, in order, into one piece */
			int k, n = B8(r->pb, PB_NRESPS);
			size_t len = 0;
			for (k = 0; k < n && k < AS_ATP_MAXRSP; k++) {
				unsigned char *e = r->bds + k * BDS_SIZE;
				size_t ds = (unsigned short)W16(e, 6);
				if ((u8 *)W32(e, 2) != r->rbuf + len)
					memmove(r->rbuf + len, (u8 *)W32(e, 2), ds);
				len += ds;
			}
			afps_reply(srv, r->id, res == 0 ? 0 : LN_ETIMEDOUT, r->rbuf, len);
		}
	}
	return any;
}

/* ---- the thread ---- */
/* send a datagram from the multinode: hdr is its 13-byte long DDP header, data what follows */
static void mn_send(const u8 *hdr, const u8 *data, size_t len)
{
	int i, k = -1;
	while (k < 0) {
		for (i = 0; i < 4 && k < 0; i++)
			if (W16(br->nw[i].pb, PB_RESULT) <= 0)
				k = i;
		if (k < 0)
			lmb_thread_yield(2);
	}
	if (len > AS_ATP_DATA + 8)
		len = AS_ATP_DATA + 8;
	/* the write-data structure: the header at an odd address (three bytes for the LAP
	   header .MPP fills in, then the DDP header), the data, a zero */
	memset(br->nw[k].hdr, 0, sizeof br->nw[k].hdr);
	memcpy(br->nw[k].hdr + 1 + 3, hdr, 13);
	memcpy(br->nw[k].data, data, len);
	W16(br->nw[k].wds, 0) = 16;
	W32(br->nw[k].wds, 2) = (long)(br->nw[k].hdr + 1);
	W16(br->nw[k].wds, 6) = (short)len;
	W32(br->nw[k].wds, 8) = (long)br->nw[k].data;
	W16(br->nw[k].wds, 12) = 0;
	pb_init(br->nw[k].pb, mpp_ref, CS_NETWRITE);
	B8(br->nw[k].pb, 29) = 0;                    /* checkSumFlag: leave the header's (none) */
	W32(br->nw[k].pb, 30) = (long)br->nw[k].wds;
	W16(br->nw[k].pb, PB_RESULT) = 1;
	lmb_control_async(br->nw[k].pb);
}

/* what came to the multinode: NBP lookups for us answered, the rest relayed */
static int poll_multinode(void)
{
	int any = 0;
	while (lmb_mn_ring[mn_tail].len) {
		struct mn_slot *sl = &lmb_mn_ring[mn_tail];
		unsigned len = sl->len, rha = sl->rha;
		static int logged;
		any = 1;
		if (logged < 8) {                       /* the first few, for the log */
			logged++;
			LN_LOG(2, "bridge: t%lu multinode got %u bytes (%u in the header area): %02x %02x %02x | %02x%02x %02x%02x %02x%02x %02x%02x %02x %02x %02x %02x %02x",
			       *(volatile unsigned long *)0x16A, len, rha, sl->buf[0], sl->buf[1], sl->buf[2], sl->buf[3], sl->buf[4], sl->buf[5], sl->buf[6],
			       sl->buf[7], sl->buf[8], sl->buf[9], sl->buf[10], sl->buf[11], sl->buf[12], sl->buf[13], sl->buf[14], sl->buf[15]);
			LN_LOG(2, "bridge:   then %02x %02x %02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
			       sl->buf[16], sl->buf[17], sl->buf[18], sl->buf[19], sl->buf[20], sl->buf[21], sl->buf[22], sl->buf[23],
			       sl->buf[24], sl->buf[25], sl->buf[26], sl->buf[27]);
		}
		/* the LAP header (destination, source, type), then the datagram: what was in the
		   header area and what ReadRest brought are one piece here. .MPP's own loopback puts
		   only five bytes in the header area (the testbed), a frame from the wire sixteen. */
		if (len >= 16 && sl->buf[2] == 2) {     /* LAP type 2: a long DDP header */
			u8 *h = sl->buf + 3, *d = sl->buf + 16;
			size_t dlen = len - 16, ddplen = ln_be16(h) & 0x3FF;
			if (ddplen >= 13 && ddplen - 13 < dlen)
				dlen = ddplen - 13;
			if (h[8] == 0xFF && h[12] == 2) {
				u8 out[120], rh[13];
				AsAddr to, me = vnode;
				size_t n = afps_nbp_answer(d, dlen, (const char *)srv_name + 1, "AFPServer", me, out, sizeof out, &to);
				if (n) {
					memset(rh, 0, sizeof rh);
					ln_put_be16(rh + 4, to.net);
					ln_put_be16(rh + 6, vnode.net);
					rh[8] = to.node;
					rh[9] = vnode.node;
					rh[10] = to.socket;
					rh[11] = 2;                  /* NBP's socket, the names information socket */
					rh[12] = 2;
					ln_put_be16(rh, (u16)(13 + n));
					LN_LOG(2, "bridge: NBP lookup from %u.%u:%u answered", to.net, to.node, to.socket);
					mn_send(rh, out, n);
				}
			} else if (h[12] == 4 && h[10] == 4 && h[8] == vnode.node && dlen >= 1 && d[0] == 1) {
				/* AppleTalk Echo (Inside AppleTalk 5-3): the AppleShare client asks the server's
				   node first. The reply is the request with function 2, back where it came from */
				u8 rh[13];
				memset(rh, 0, sizeof rh);
				ln_put_be16(rh, (u16)(13 + dlen));
				memcpy(rh + 4, h + 6, 2);            /* to: its network, node and socket */
				ln_put_be16(rh + 6, vnode.net);
				rh[8] = h[9];
				rh[9] = vnode.node;
				rh[10] = h[11];
				rh[11] = 4;
				rh[12] = 4;
				d[0] = 2;
				mn_send(rh, d, dlen);
			} else if (afps_relay(&relay, h)) {
				mn_send(h, d, dlen);
			}
		}
		sl->len = 0;
		mn_tail = (mn_tail + 1) % MN_SLOTS;
	}
	return any;
}

static void fail(int err, int oserr)
{
	last_err = err;
	last_oserr = oserr;
	state = LMB_FAILED;
	LN_LOG(0, "bridge: failed (Lagoon %d, AppleTalk %d)", err, oserr);
}

void lmb_thread_main(void)
{
	const LnOps *ops = NULL;
	LnFs *fs = NULL;
	AsTransport t;
	AfpsConfig cfg;
	int r, i;
	u32 last_tick;

	LN_LOG(1, "bridge: the thread runs; connecting");
	r = ln_vfs_mount_url(url, &creds, &ops, &fs);
	ln_wipe(&creds, sizeof creds);
	ln_wipe(url, sizeof url);
	if (r != LN_OK) {
		fail(r, 0);
		goto done;
	}
	memset(&t, 0, sizeof t);
	t.socket = sock;
	t.respond = t_respond;
	t.request = t_request;
	t.cancel = t_cancel;
	memset(&cfg, 0, sizeof cfg);
	memcpy(cfg.server, srv_name + 1, srv_name[0]);
	memcpy(cfg.volume, vol_name + 1, vol_name[0]);
	ln_strlcpy(cfg.machine, "Lagoon", sizeof cfg.machine);
	srv = afps_new(&cfg, ops, fs, &t);
	if (!srv) {
		fail(LN_ENOMEM, 0);
		goto done;
	}
	for (i = 0; i < NGETREQ; i++)
		arm(&br->get[i]);
	relay.server = user_node;
	relay.vnode = vnode;
	state = LMB_SERVING;
	LN_LOG(1, "bridge: %s offered on socket %u", share_name, sock);
	last_tick = ln_ms();
	while (!stop_wanted) {
		int a = poll_multinode(), b = poll_calls();
		if (a || b)
			continue;
		if (ln_ms() - last_tick >= 1000) {
			last_tick = ln_ms();
			afps_tick(srv);
		}
		lmb_thread_yield(afps_sessions(srv) ? 20 : 100);
	}
done:
	state = LMB_STOPPING;
	if (srv) {
		u32 t0 = ln_ms();
		afps_free(srv);                          /* Attention and CloseSess to the client */
		srv = NULL;
		for (;;) {                               /* let those go out, two seconds at most */
			int busy = 0;
			poll_calls();
			for (i = 0; i < NREQ; i++)
				busy |= br->req[i].busy;
			if (!busy || ln_ms() - t0 > 2000)
				break;
			lmb_thread_yield(20);
		}
	}
	if (fs)
		ops->unmount(fs);
	alive = 0;                                   /* lm_bridge_stop does the rest */
	for (;;)
		lmb_thread_yield(1000);
}

/* ---- the application's side ---- */
static short open_driver(const char *name)
{
	unsigned char pb[PB_SIZE], pn[16];
	size_t n = strlen(name);
	memset(pb, 0, sizeof pb);
	pn[0] = (unsigned char)n;
	memcpy(pn + 1, name, n);
	*(unsigned char **)(pb + 18) = pn;           /* ioNamePtr */
	if (lmb_open(pb) != 0)
		return 0;
	return W16(pb, PB_REFNUM);
}

static short sync_call(unsigned char *pb)
{
	W32(pb, PB_COMPL) = 0;
	return lmb_control(pb);
}

/* a share's name as a Mac Roman Pascal string of at most max bytes */
static void mac_name(const char *utf8, u8 *out, size_t max)
{
	int n = afps_to_mac(utf8, 0, out + 1, max);
	if (n < 0 || afps_mangled_id(out + 1, (size_t)n)) {
		n = 0;                                   /* not Mac Roman: keep the plain part */
		while (utf8[n] && (u8)utf8[n] < 0x80 && (size_t)n < max) {
			out[1 + n] = (u8)(utf8[n] == ':' ? '/' : utf8[n]);
			n++;
		}
	}
	if (!n)
		memcpy(out + 1, "Lagoon", n = 6);
	out[0] = (u8)n;
	out[n + 1] = 0;
}

/* our user node's address (PGetAppleTalkInfo: ourAddr, network << 8 | node) */
static int user_address(AsAddr *a)
{
	unsigned char pb[80], link[8], zone[34];
	unsigned long ours;
	memset(pb, 0, sizeof pb);
	W16(pb, PB_REFNUM) = mpp_ref;
	W16(pb, PB_CSCODE) = CS_GETATALKINFO;
	W16(pb, 28) = 1;                             /* version */
	W32(pb, 70) = (long)link;                    /* linkAddr */
	W32(pb, 74) = (long)zone;                    /* zoneName */
	if (sync_call(pb) != 0)
		return -1;
	ours = (unsigned long)W32(pb, 50);
	a->net = (u16)(ours >> 8);
	a->node = (u8)ours;
	LN_LOG(1, "bridge: the user node is %u.%u (ourAddr %08lx)", a->net, a->node, ours);
	return 0;
}

/* a multinode: AddNode, an immediate synchronous Control call, again while .MPP says so */
static short add_multinode(AsAddr *a)
{
	unsigned char pb[PB_SIZE + 70];
	short r;
	int tries = 0;
	do {
		memset(pb, 0, sizeof pb);
		W16(pb, PB_REFNUM) = mpp_ref;
		W16(pb, PB_CSCODE) = CS_ADDNODE;
		W32(pb, 44) = (long)lmb_mn_recv;         /* recvRoutine */
		r = lmb_control_immed(pb);
	} while (r == MN_TRYAGAIN && ++tries < 100);
	if (r == 0) {
		a->net = (u16)W16(pb, 40);               /* actNodeAddr */
		a->node = B8(pb, 42);
	}
	return r;
}

static void cleanup_atalk(void)
{
	unsigned char pb[PB_SIZE];
	if (have_vnode) {
		memset(pb, 0, sizeof pb);
		W16(pb, PB_REFNUM) = mpp_ref;
		W16(pb, PB_CSCODE) = CS_REMOVENODE;
		W16(pb, 36) = (short)vnode.net;          /* nodeAddr */
		B8(pb, 38) = vnode.node;
		sync_call(pb);
		have_vnode = 0;
	}
	if (sock) {
		memset(pb, 0, sizeof pb);
		W16(pb, PB_REFNUM) = atp_ref;
		W16(pb, PB_CSCODE) = CS_CLOSEATPSKT;
		B8(pb, PB_SOCKET) = sock;
		sync_call(pb);                           /* our pending calls end with reqAborted */
		sock = 0;
	}
	if (old_self == 0) {
		memset(pb, 0, sizeof pb);
		W16(pb, PB_REFNUM) = mpp_ref;
		W16(pb, PB_CSCODE) = CS_SETSELFSEND;
		B8(pb, 28) = 0;
		sync_call(pb);
	}
	old_self = -1;
}

int lm_bridge_start(const char *u, const LnCreds *cr, const char *name)
{
	unsigned char pb[PB_SIZE];
	long *frame;
	short r = -1;
	if (state == LMB_STARTING || state == LMB_SERVING || state == LMB_STOPPING)
		return LN_EINUSE;
	state = LMB_OFF;
	last_err = last_oserr = 0;
	mpp_ref = open_driver(".MPP");               /* fails when AppleTalk is off in the Chooser */
	atp_ref = mpp_ref ? open_driver(".ATP") : 0;
	if (!mpp_ref || !atp_ref)
		return LN_ENONET;
	/* intranode delivery: the AppleShare client on this node reaches our socket */
	memset(pb, 0, sizeof pb);
	W16(pb, PB_REFNUM) = mpp_ref;
	W16(pb, PB_CSCODE) = CS_SETSELFSEND;
	B8(pb, 28) = 1;                              /* newSelfFlag */
	if (sync_call(pb) == 0)
		old_self = B8(pb, 29);                   /* oldSelfFlag */
	memset(pb, 0, sizeof pb);
	W16(pb, PB_REFNUM) = atp_ref;
	W16(pb, PB_CSCODE) = CS_OPENATPSKT;
	r = sync_call(pb);                           /* socket 0, address filter 0: any */
	if (r != 0) {
		cleanup_atalk();
		last_oserr = r;
		return LN_ENONET;
	}
	sock = B8(pb, PB_SOCKET);
	memset(lmb_mn_ring, 0, sizeof lmb_mn_ring);
	lmb_mn_head = mn_tail = 0;
	if (user_address(&user_node) != 0 || (r = add_multinode(&vnode)) != 0) {
		LN_LOG(0, "bridge: no multinode (%d)", r);
		cleanup_atalk();
		last_oserr = r;
		return LN_ENOTSUP;                       /* the AppleTalk connection has no multinodes */
	}
	have_vnode = 1;
	user_node.socket = sock;
	vnode.socket = sock;
	LN_LOG(1, "bridge: the server is %u.%u:%u, its name on the multinode %u.%u", user_node.net, user_node.node,
	       sock, vnode.net, vnode.node);
	if (!br)
		br = mm_alloc(sizeof *br);
	if (!br || lm_pool_init(br->pool, sizeof br->pool) != LN_OK) {
		cleanup_atalk();
		return LN_ENOMEM;
	}
	if (ln_net_thread_attach() != LN_OK) {
		cleanup_atalk();
		return LN_ENONET;
	}
	(void)ln_hostname();                         /* the Toolbox calls the thread may not make */
	(void)ln_tz_minutes();
	ln_strlcpy(url, u, sizeof url);
	if (cr)
		creds = *cr;
	else
		memset(&creds, 0, sizeof creds);
	ln_strlcpy(share_name, name, sizeof share_name);
	mac_name(name, srv_name, 31);
	mac_name(name, vol_name, 27);
	memset(br->get, 0, sizeof br->get);
	memset(br->rsp, 0, sizeof br->rsp);
	memset(br->req, 0, sizeof br->req);
	stop_wanted = 0;
	/* the thread's first frame: the registers lmb_switch takes (A5 Lagoon's), then its start */
	frame = (long *)(br->stack + STACK_SIZE) - 13;
	memset(frame, 0, 13 * sizeof(long));
	frame[9] = (long)lm_a5;                      /* d2-d7 a2-a4, then a5 */
	frame[11] = (long)lmb_thread_start;
	thread_sp = frame;
	state = LMB_STARTING;
	memset(&tm, 0, sizeof tm);
	tm.addr = lmb_tm_entry;
	memset(&dt, 0, sizeof dt);
	dt.qtype = 7;                                /* dtQType (Inside Macintosh: Processes 6-11) */
	dt.addr = lmb_dt_entry;
	alive = 1;
	lmb_instime(&tm);
	lmb_primetime(&tm, 10);
	LN_LOG(1, "bridge: starting for %s", share_name);
	return LN_OK;
}

int lm_bridge_state(int *err, int *oserr)
{
	static unsigned long last;
	unsigned long now = *(volatile unsigned long *)0x16A;
	if (now - last >= 120) {
		last = now;
		LN_LOG(2, "bridge: state %d; Time Manager %lu, deferred %lu, thread %lu, Lagoon busy %lu, app core %d",
		       state, n_tm, n_dt, n_run, n_busy, lm_app_core);
	}
	if (err) *err = last_err;
	if (oserr) *oserr = last_oserr;
	return state;
}

const char *lm_bridge_name(void)
{
	return state == LMB_SERVING || state == LMB_STARTING ? share_name : "";
}

int lm_bridge_mount(void)
{
	/* AFPVolMountInfo (Inside Macintosh: Files 2-110): the offsets count from the record's
	 * start; guest: no user name, no password */
	unsigned char info[200], pb[80];
	unsigned char *p = info + 24;
	int zone, server, vol, user;
	short r;
	if (state != LMB_SERVING)
		return -1;
	memset(info, 0, sizeof info);
	zone = (int)(p - info);   *p++ = 1; *p++ = '*';
	server = (int)(p - info); memcpy(p, srv_name, srv_name[0] + 1); p += srv_name[0] + 1;
	vol = (int)(p - info);    memcpy(p, vol_name, vol_name[0] + 1); p += vol_name[0] + 1;
	user = (int)(p - info);   *p++ = 0;          /* user, password and volume password: empty */
	W16(info, 0) = (short)(p - info);
	memcpy(info + 2, "afpm", 4);
	W16(info, 6) = 0;                            /* flags */
	B8(info, 8) = 7;                             /* NBP interval, 8-tick units */
	B8(info, 9) = 3;                             /* NBP count */
	W16(info, 10) = 1;                           /* kNoUserAuthentication */
	W16(info, 12) = (short)zone;
	W16(info, 14) = (short)server;
	W16(info, 16) = (short)vol;
	W16(info, 18) = (short)user;
	W16(info, 20) = (short)user;
	W16(info, 22) = (short)user;
	memset(pb, 0, sizeof pb);
	W32(pb, 32) = (long)info;                    /* ioBuffer */
	r = lmb_volmount(pb);                        /* spins here while the thread serves it */
	LN_LOG(1, "bridge: PBVolumeMount %d (volume %d)", r, W16(pb, 22));
	return r;
}

void lm_bridge_stop(void)
{
	unsigned long t0;
	if (!br || state == LMB_OFF)
		return;
	stop_wanted = 1;
	t0 = *(volatile unsigned long *)0x16A;       /* Ticks */
	while (alive && *(volatile unsigned long *)0x16A - t0 < 15 * 60)
		lm_yield(NULL);
	lmb_rmvtime(&tm);
	{
		int was_alive = alive;
		alive = 0;
		t0 = *(volatile unsigned long *)0x16A;
		while (dt_queued && *(volatile unsigned long *)0x16A - t0 < 120)
			lm_yield(NULL);                      /* a deferred task already queued runs first */
		if (dt_queued)
			LN_LOG(0, "bridge: the deferred task never ran");
		cleanup_atalk();
		if (!was_alive)
			ln_net_thread_detach();          /* else the thread's client is in a wait: left */
		if (!was_alive) {
			/* the thread finished: its memory can go */
			mm_free(br);
			br = NULL;
		}
		/* else it is stuck in a wait: its memory stays (the application's heap goes with it) */
	}
	srv = NULL;
	state = LMB_OFF;
	LN_LOG(1, "bridge: stopped");
}
