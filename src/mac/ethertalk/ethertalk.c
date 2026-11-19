/*
 * Lagoon EtherTalk - the 'atlk': AppleTalk Phase 2 over an Ethernet card's .ENET driver.
 *
 * Backstory. Apple's AppleTalk Manager stays in charge (.MPP, .ATP, .XPP, the LAP Manager, all
 * in System 7.1); a connection file only moves datagrams between .MPP and a network, and claims
 * the node's address there. For Ethernet that is AppleTalk Phase 2 (Inside AppleTalk, second
 * edition, chapter 2, "EtherTalk"): DDP datagrams in 802.3 frames with 802.2 SNAP headers,
 * AARP to find whose Ethernet address an AppleTalk address is and to make sure nobody else has
 * ours (ten probes, a fifth of a second apart), and 09:00:07:FF:FF:FF for broadcasts. This file
 * is that: what each 'atlk' call does (et_dispatch), the write hook (et_write), the two 802.2
 * protocol handlers the LAP Manager calls (et_rx_ddp, et_rx_aarp), and a VBL task that asks
 * again for addresses nobody has answered for yet (et_tick). atlk_glue.S has the registers.
 *
 * Multinodes (Technote NW 13): besides the user node, .MPP may ask for up to MAXNODES - 1 more
 * addresses for programs that take their own datagrams (Lagoon's AppleShare bridge has one, so
 * that the Mac's AppleShare client, which will not use a server on its own node, sees the
 * server on another). Each address is claimed with AARP like the user node and answered for
 * afterwards; datagrams for it go up with its address reference number, and AGetNodeRef tells
 * .MPP which addresses are this Mac's, so that it loops datagrams between them itself.
 *
 * What it does not do (yet): zone multicast addresses (an NBP lookup in our own zone goes to the
 * broadcast address instead, which every node hears too), routing (packets for other nodes are
 * dropped, not passed to a router on this Mac).
 *
 * The node's address is .MPP's: it picks a network and node (from parameter RAM, or at random
 * in the startup range $FF00-$FFFE) and asks AAddNode to claim it; after a router's ZIP
 * GetNetInfo answer it may give it back (ADelNode) and claim another. Everything here runs
 * either at system task time (AInstall, AShutDown, AAddNode) or at interrupt time (the rest);
 * the shared tables are touched with interrupts off.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "ethertalk.h"

#define NULL ((void *)0)

/* ---- small things C usually brings ---- */
void *memcpy(void *d, const void *s, unsigned long n)
{
	u8 *dp = d; const u8 *sp = s;
	while (n--) *dp++ = *sp++;
	return d;
}
void *memset(void *d, int c, unsigned long n)
{
	u8 *dp = d;
	while (n--) *dp++ = (u8)c;
	return d;
}
static int same6(const u8 *a, const u8 *b)
{
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
}
static u16 get16(const u8 *p) { return (u16)(p[0] << 8 | p[1]); }
static void put16(u8 *p, u16 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }

/* ---- the log: on Aurora68 (a Raspberry Pi in the 68000 socket) each line goes to the Pi
   kernel's log through the slot-9 mailbox's INFO command; elsewhere there is no log. ---- */
#ifdef AURORA68_LOG
static void a68_log(const char *s, u32 n)
{
	volatile u8 *c = (volatile u8 *)((*(volatile u8 *)0xCB2 ? 0xF9000000u : 0x00900000u) + 0x1000u);
	u32 seq, i;
	*(volatile u16 *)(c + 8) = 2;
	*(const char *volatile *)(c + 28) = s;
	*(volatile u32 *)(c + 32) = n;
	seq = *(volatile u32 *)c + 1;
	*(volatile u32 *)c = seq;
	for (i = 0; i < 200000u && *(volatile u32 *)(c + 4) != seq; i++) ;
}
/* %s %c %d %u %x with an optional zero-padded width, nothing else */
static void et_log(const char *fmt, ...)
{
	char line[240], *o = line, *end = line + sizeof line - 1;
	const char *pre = "EtherTalk: ";
	__builtin_va_list ap;
	while (*pre) *o++ = *pre++;
	__builtin_va_start(ap, fmt);
	for (; *fmt && o < end; fmt++) {
		int w = 0;
		if (*fmt != '%') { *o++ = *fmt; continue; }
		fmt++;
		while (*fmt >= '0' && *fmt <= '9') w = w * 10 + (*fmt++ - '0');
		if (*fmt == 's') { const char *s = __builtin_va_arg(ap, const char *); while (*s && o < end) *o++ = *s++; }
		else if (*fmt == 'c') *o++ = (char)__builtin_va_arg(ap, int);
		else {
			char t[12]; int n = 0, neg = 0; u32 v = __builtin_va_arg(ap, u32), base = *fmt == 'x' ? 16 : 10;
			if (*fmt == 'd' && (s32)v < 0) { neg = 1; v = (u32)-(s32)v; }
			do { t[n++] = "0123456789abcdef"[v % base]; v /= base; } while (v);
			while (n < w) t[n++] = '0';
			if (neg && o < end) *o++ = '-';
			while (n && o < end) *o++ = t[--n];
		}
	}
	__builtin_va_end(ap);
	*o = 0;
	a68_log(line, (u32)(o - line));
}
#define LOG(...) et_log(__VA_ARGS__)
#else
static inline void et_nolog(const char *fmt, ...) { (void)fmt; }   /* no log: the calls vanish */
#define LOG(...) et_nolog(__VA_ARGS__)
#endif

/* ---- state ---- */
#define AMT_SIZE 16                 /* the address mapping table: AppleTalk address -> Ethernet */
#define NTX      4                  /* frames on their way out at once */
#define NPEND    4                  /* datagrams waiting for an AARP answer */
#define MAXNODES 4                  /* the user node and three multinodes */
#define FRAME    (14 + 8 + DDP_MAX) /* 802.3 header, 802.2 LLC and SNAP, the datagram */

struct amt { u32 addr; u8 mac[6]; u8 used; u8 stamp; };
struct tx { u8 pb[50]; u8 wds[12]; u8 frame[FRAME]; };
struct pend { u32 addr; u16 len; u8 used, tries; u8 frame[FRAME]; };

static struct {
	s16 refnum;                     /* the card's .ENET driver */
	u8  mac[6];
	u8  slot, srsrc, port;
	u8  installed, multi, ddp_on, aarp_on, vbl_on, open;
	u8  stamp;                      /* AMT age counter, for replacing the oldest entry */
	u8  *mpp;                       /* .MPP's variables, from AAddNode */
	u32 node;                       /* the user node's address (network << 8 | node); 0 = none */
	struct { u32 addr; u16 ref; u8 used; } nodes[MAXNODES];   /* the user node and multinodes */
	u32 tentative;                  /* the address being probed for */
	volatile u8 conflict;           /* somebody answered for the tentative address */
	u8  logged_rx, logged_tx;       /* the first frames each way go to the log */
	u32 rx_ddp, rx_aarp, tx_frames, tx_drops;
} g;
static struct amt amt[AMT_SIZE];
static struct tx tx[NTX];
static struct pend pend[NPEND];
/* datagrams for one of this Mac's own nodes, handed up by a deferred task (et_loop_run). An
   ATP response is up to eight datagrams, which .ATP writes in one go, before any deferred task
   can run: with eight slots (seven usable) the eighth of a full response was dropped, and the
   requester had to ask for it again after its retry time (the bridge's FPRead of 4608 bytes is
   such a response). Room for three whole responses */
#define NLOOP 25
static struct { u16 len; u8 ddp[DDP_MAX]; } loopq[NLOOP];
static volatile u8 loop_head, loop_tail, loop_queued;
static struct { void *qlink; s16 qtype; s16 flags; void *addr; void *param; u32 res; } __attribute__((packed)) loop_dt;
static struct { void *qlink; s16 qtype; void *addr; s16 count, phase; } __attribute__((packed)) vbl;
u32 et_d1_out;
u8 et_rxbuf[1536];
u16 et_rp_calls, et_rr_calls;

/* the node table entry for an address, or NULL */
static int node_index(u32 a)
{
	int i;
	for (i = 0; i < MAXNODES; i++)
		if (g.nodes[i].used && g.nodes[i].addr == (a & 0xFFFFFF))
			return i;
	return -1;
}

static const u8 bcast[6] = { 0x09, 0x00, 0x07, 0xFF, 0xFF, 0xFF };   /* AppleTalk broadcast, Phase 2 */
static const u8 llc_ddp[8] = { 0xAA, 0xAA, 0x03, 0x08, 0x00, 0x07, 0x80, 0x9B };
static const u8 llc_aarp[8] = { 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x80, 0xF3 };

/* ---- out to the wire ----
   Each transmit slot owns its parameter block, a one-entry write data structure and the frame.
   EWrite runs asynchronously (the write hook is called at interrupt time as often as not), and
   a slot is free again once ioResult is no longer positive. */
#define PB_RESULT 16
#define PB_REFNUM 24
#define PB_CSCODE 26
#define PB_EPTR   30

static struct tx *free_slot(void)
{
	int i;
	for (i = 0; i < NTX; i++)
		if (*(volatile s16 *)(tx[i].pb + PB_RESULT) <= 0)
			return &tx[i];
	return NULL;
}

/* the slot's frame already holds the payload from byte 14 on; payload = LLC/SNAP + data */
static void enet_send(struct tx *t, const u8 *to, u16 payload)
{
	u8 *w = t->wds;
	memcpy(t->frame, to, 6);
	memcpy(t->frame + 6, g.mac, 6);
	put16(t->frame + 12, payload);
	put16(w, (u16)(14 + payload));
	*(u8 **)(w + 2) = t->frame;
	put16(w + 6, 0);                                /* the list ends */
	memset(t->pb, 0, sizeof t->pb);
	*(s16 *)(t->pb + PB_RESULT) = 1;
	*(s16 *)(t->pb + PB_REFNUM) = g.refnum;
	*(s16 *)(t->pb + PB_CSCODE) = ENET_WRITE;
	*(u8 **)(t->pb + PB_EPTR) = w;
	g.tx_frames++;
	et_control_async(t->pb);
}

/* an AARP packet (Inside AppleTalk 2-11): 28 bytes after the LLC/SNAP header */
static void put_atalk(u8 *p, u32 a) { p[0] = 0; p[1] = (u8)(a >> 16); p[2] = (u8)(a >> 8); p[3] = (u8)a; }
static u32 get_atalk(const u8 *p) { return (u32)p[1] << 16 | (u32)p[2] << 8 | p[3]; }

static void aarp_send(int fn, const u8 *to, const u8 *their_hw, u32 mine, u32 theirs)
{
	struct tx *t;
	u8 *p;
	u16 sr = et_irq_off();
	t = free_slot();
	if (!t) { g.tx_drops++; et_irq_restore(sr); return; }
	p = t->frame + 14;
	memcpy(p, llc_aarp, 8);
	put16(p + 8, AARP_HW_ETHER);
	put16(p + 10, AARP_PROTO_DDP);
	p[12] = 6; p[13] = 4;
	put16(p + 14, (u16)fn);
	memcpy(p + 16, g.mac, 6);
	put_atalk(p + 22, mine);
	if (their_hw) memcpy(p + 26, their_hw, 6); else memset(p + 26, 0, 6);
	put_atalk(p + 32, theirs);
	enet_send(t, to, 8 + 28);
	et_irq_restore(sr);
}

/* ---- the address mapping table, and datagrams held until AARP finds their next hop ---- */
static struct amt *amt_find(u32 a)
{
	int i;
	for (i = 0; i < AMT_SIZE; i++)
		if (amt[i].used && amt[i].addr == a)
			return &amt[i];
	return NULL;
}

/* called with interrupts off */
static void amt_learn(u32 a, const u8 *mac)
{
	struct amt *e = amt_find(a);
	int i;
	if (!e) {
		e = &amt[0];
		for (i = 0; i < AMT_SIZE; i++) {
			if (!amt[i].used) { e = &amt[i]; break; }
			if ((u8)(g.stamp - amt[i].stamp) > (u8)(g.stamp - e->stamp)) e = &amt[i];
		}
	}
	e->addr = a; memcpy(e->mac, mac, 6); e->used = 1; e->stamp = ++g.stamp;
	for (i = 0; i < NPEND; i++) {                   /* anything waiting for this one goes now */
		struct tx *t;
		if (!pend[i].used || pend[i].addr != a || !(t = free_slot())) continue;
		memcpy(t->frame + 14, pend[i].frame + 14, pend[i].len);
		enet_send(t, mac, pend[i].len);
		pend[i].used = 0;
	}
}

/* ---- the write hook: .MPP's datagram, with a 3-byte LAP header in front, out as Phase 2 ---- */
long et_write(const u8 *wds, u8 *mpp, long enq, u32 dest)
{
	u8 frame_tmp[8 + DDP_MAX];
	u16 len = 0, sr;
	int skip = 3;                                   /* the LAP header: destination, source, type */
	struct amt *e;
	struct tx *t;
	const u8 *to, *lap = *(u8 *const *)(wds + 2);

	if (enq || !g.installed) {
		if (enq && g.tx_frames < 4) LOG("ENQ for node %x ignored", dest);
		return 0;
	}                                   /* AAddNode claims the address, not ENQs */
	memcpy(frame_tmp, llc_ddp, 8);
	for (; get16(wds); wds += 6) {
		u16 n = get16(wds);
		const u8 *p = *(u8 *const *)(wds + 2);
		if (skip) { u16 k = n < skip ? n : (u16)skip; p += k; n -= k; skip -= k; }
		if (len + n > DDP_MAX) { g.tx_drops++; return 0; }
		memcpy(frame_tmp + 8 + len, p, n);
		len += n;
	}
	if (g.tx_frames < 4)
		LOG("write %u bytes to %x, LAP header %02x %02x %02x", len, dest, lap[0], lap[1], lap[2]);
	if ((dest & 0xFF) != 0xFF && g.logged_tx < 4) {
		const u8 *h = frame_tmp + 8;
		g.logged_tx++;
		LOG("unicast to %x: DDP %d.%d:%d -> %d.%d:%d type %d", dest, get16(h + 6), h[9], h[11], get16(h + 4), h[8], h[10], h[12]);
	}
	dest &= 0xFFFFFF;
	sr = et_irq_off();
	if ((dest & 0xFF) != 0xFF && node_index(dest) >= 0) {
		/* for a node of this Mac: .MPP loops the user node's datagrams to multinodes itself,
		   but a multinode's NetWrite to the user node comes here (the testbed, 18 November).
		   It goes up from a deferred task, as if it had come in: never from inside a write,
		   which may be .MPP's own, in the middle of using its Read Header Area */
		u8 h = loop_head, nh = (u8)((h + 1) % NLOOP);
		if (nh == loop_tail || len > DDP_MAX) {
			g.tx_drops++;
		} else {
			memcpy(loopq[h].ddp, frame_tmp + 8, len);
			loopq[h].len = len;
			loop_head = nh;
			if (!loop_queued) {
				loop_queued = 1;
				loop_dt.qtype = 7;              /* dtQType */
				loop_dt.addr = (void *)et_dt_entry;
				et_dtinstall(&loop_dt);
			}
		}
		et_irq_restore(sr);
		return 0;
	}
	if ((dest & 0xFF) == 0xFF)
		to = bcast;
	else if ((e = amt_find(dest)) != NULL)
		to = e->mac;
	else {                                          /* nobody known: hold it and ask */
		int i;
		for (i = 0; i < NPEND && pend[i].used; i++) ;
		if (i == NPEND) { g.tx_drops++; et_irq_restore(sr); return 0; }
		pend[i].used = 1; pend[i].addr = dest; pend[i].tries = 1; pend[i].len = (u16)(8 + len);
		memcpy(pend[i].frame + 14, frame_tmp, 8 + len);
		et_irq_restore(sr);
		aarp_send(AARP_REQUEST, bcast, NULL, g.node, dest);
		return 0;
	}
	t = free_slot();
	if (t) {
		memcpy(t->frame + 14, frame_tmp, 8 + len);
		enet_send(t, to, (u16)(8 + len));
	} else
		g.tx_drops++;
	et_irq_restore(sr);
	return 0;
}

/* ---- in from the wire ---- */
static void log_header(const char *what, const u8 *rha_next, long len)
{
	if (g.logged_rx >= 2)
		return;
	g.logged_rx++;
	LOG("%s %d bytes; before A3: %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %02x%02x %02x%02x %02x%02x%02x %02x%02x%02x%02x%02x",
	    what, len, rha_next[-24], rha_next[-23], rha_next[-22], rha_next[-21], rha_next[-20], rha_next[-19],
	    rha_next[-18], rha_next[-17], rha_next[-16], rha_next[-15], rha_next[-14], rha_next[-13],
	    rha_next[-12], rha_next[-11], rha_next[-10], rha_next[-9], rha_next[-8], rha_next[-7], rha_next[-6],
	    rha_next[-5], rha_next[-4], rha_next[-3], rha_next[-2], rha_next[-1]);
}

/* pkt: the AARP packet from its hardware address length on, or from its hardware type if the
   LAP Manager left those four bytes in the rest */
void et_rx_aarp(const u8 *rha_next, const u8 *pkt, long len)
{
	u16 fn, sr;
	u32 src, dst;
	const u8 *src_hw, *dst_hw;

	g.rx_aarp++;
	log_header("AARP", rha_next, len);
	if (len >= 28 && get16(pkt) == AARP_HW_ETHER && get16(pkt + 2) == AARP_PROTO_DDP) { pkt += 4; len -= 4; }
	if (len < 24 || pkt[0] != 6 || pkt[1] != 4)
		return;
	fn = get16(pkt + 2);
	src_hw = pkt + 4; src = get_atalk(pkt + 10);
	dst_hw = pkt + 14; dst = get_atalk(pkt + 20);
	if (same6(src_hw, g.mac))
		return;                                     /* our own, heard back */
	LOG("AARP %s from %x for %x", fn == AARP_REQUEST ? "request" : fn == AARP_RESPONSE ? "response" : "probe", src, dst);
	if (g.tentative && (src == g.tentative || (fn == AARP_PROBE && dst == g.tentative)))
		g.conflict = 1;                             /* somebody has it, or wants it too */
	if (node_index(dst) >= 0 && (fn == AARP_REQUEST || fn == AARP_PROBE))
		aarp_send(AARP_RESPONSE, src_hw, src_hw, dst, src);      /* ours: say so */
	if (fn == AARP_RESPONSE || (fn == AARP_REQUEST && node_index(dst) >= 0)) {
		sr = et_irq_off();
		amt_learn(src, src_hw);
		et_irq_restore(sr);
	}
	(void)dst_hw;
}

static void deliver_up(const u8 *pkt, u16 ddplen, u32 ref);

/* pkt: the DDP datagram (long header) and whatever padding the frame had */
void et_rx_ddp(const u8 *rha_next, const u8 *pkt, long len)
{
	u16 ddplen, dnet;
	u8 dnode;
	u32 ref = 0xFFFF;                               /* the user node's, and broadcasts' */

	g.rx_ddp++;
	log_header("DDP", rha_next, len);
	if (len >= 8 + 13 && same6(pkt, llc_ddp) && pkt[6] == llc_ddp[6] && pkt[7] == llc_ddp[7]) { pkt += 8; len -= 8; }
	if (len < 13 || !g.open || !g.mpp) {
		if (g.rx_ddp <= 3) LOG("DDP dropped: open %d, .MPP %x", g.open, (u32)g.mpp);
		return;
	}
	ddplen = get16(pkt) & 0x3FF;
	if (ddplen < 13 || ddplen > len)
		return;
	dnet = get16(pkt + 4); dnode = pkt[8];
	if (dnode != 0xFF) {
		int k = node_index((u32)(dnet ? dnet : (u16)(g.node >> 8)) << 8 | dnode);
		if (k < 0)
			return;                             /* not for us, and we are no router */
		ref = g.nodes[k].ref;
	}
	/* the LAP Manager keeps the frame's header behind A3: two bytes, the destination at -22,
	   the source at -16, the 802.3 length at -10, then LLC and SNAP (Aurora68's testbed log;
	   Technote NW 13 says -24 for the destination, two bytes further back) */
	if ((get16(pkt) >> 10 & 0xF) == 0 && get16(pkt + 6)) {   /* hop count 0: its sender is on this wire */
		u16 sr = et_irq_off();
		amt_learn((u32)get16(pkt + 6) << 8 | pkt[9], rha_next - 16);   /* hop count 0: glean its sender */
		et_irq_restore(sr);
	}
	deliver_up(pkt, ddplen, ref);
}

/* a datagram (long header first) up to .MPP for the node with this reference. .MPP's Read
   Header Area at 1(A2): the LAP header as LocalTalk would have it, then the whole 13-byte long
   DDP header. */
static void deliver_up(const u8 *pkt, u16 ddplen, u32 ref)
{
	u8 *rha;
	u16 dnet = get16(pkt + 4);
	u8 dnode = pkt[8];
	/* LRdDispatch is .MPP's own routine (the LAP Manager jumps
	   through 1052(A2)), and on an extended network it compares the header's destination,
	   8(A2) and 12(A2), with the node's address before reading anything: with LocalTalk's five
	   bytes there it saw 0.0 and dropped every datagram (the testbed's log, 18 November) */
	rha = g.mpp + 1;
	rha[0] = dnode; rha[1] = pkt[9]; rha[2] = LAP_TYPE_LONG;
	memcpy(rha + 3, pkt, 13);
	{
		u16 rp = et_rp_calls, rr = et_rr_calls;
		u32 d2 = ref << 16 | LAP_TYPE_LONG;             /* the node's reference, the LAP type */
		long r = et_deliver(g.mpp, rha + 16, (u8 *)pkt + 13, (long)ddplen - 13, (long)d2);
		if (g.rx_ddp <= 3)
			LOG("up: %d bytes for %d.%d:%d, %s, ReadPacket %d ReadRest %d", ddplen, dnet, dnode, pkt[10],
			    r ? "no handler" : "taken", et_rp_calls - rp, et_rr_calls - rr);
	}
}

/* the deferred task: the datagrams et_write kept for this Mac's own nodes go up */
void et_loop_run(void)
{
	u16 sr = et_irq_off();
	loop_queued = 0;
	while (loop_tail != loop_head) {
		const u8 *p = loopq[loop_tail].ddp;
		u16 len = loopq[loop_tail].len;
		int k = node_index((u32)(get16(p + 4) ? get16(p + 4) : (u16)(g.node >> 8)) << 8 | p[8]);
		if (k >= 0 && g.open && g.mpp && len >= 13)
			deliver_up(p, len, g.nodes[k].ref);
		loop_tail = (u8)((loop_tail + 1) % NLOOP);
	}
	et_irq_restore(sr);
}

/* ---- the VBL task, every fifth of a second: ask again for next hops nobody has named ---- */
void et_tick(void)
{
	int i;
	for (i = 0; i < NPEND; i++) {
		if (!pend[i].used) continue;
		if (pend[i].tries >= AARP_REQ_TRIES) { pend[i].used = 0; g.tx_drops++; continue; }
		pend[i].tries++;
		aarp_send(AARP_REQUEST, bcast, NULL, g.node, pend[i].addr);
	}
}

/* ---- claiming an address: probe it; a probe or answer from anyone else means it is taken.
   System task time (Technote NW 13), so this may wait; Ticks moves with the VBL interrupt. ---- */
static long wait_ticks(u32 n)
{
	u32 t0 = et_ticks(), spins = 0;
	while (et_ticks() - t0 < n && !g.conflict)
		if (++spins > 4000000u) break;              /* Ticks stopped: do not hang the Mac */
	return g.conflict;
}

static long add_node(struct atlk_pb *pb)
{
	u32 a = pb->net_addr & 0xFFFFFF;
	int tries = pb->num_tries ? pb->num_tries : AARP_PROBES, i;
	if (tries > 20) tries = 20;
	g.mpp = pb->mpp_vars;
	if (node_index(a) >= 0) {                       /* one of ours already: .MPP picks another */
		LOG("AAddNode %x: ours already", a);
		return -1;
	}
	g.conflict = 0;
	g.tentative = a;
	LOG("AAddNode %x: %d probes", a, tries);
	for (i = 0; i < tries && !g.conflict; i++) {
		aarp_send(AARP_PROBE, bcast, NULL, a, a);
		wait_ticks(AARP_PROBE_TICKS);
	}
	g.tentative = 0;
	if (g.conflict) { LOG("AAddNode %x: in use", a); return -1; }
	for (i = 0; i < MAXNODES && g.nodes[i].used; i++)
		;
	if (i == MAXNODES) { LOG("AAddNode %x: no room", a); return -1; }
	g.nodes[i].addr = a;
	g.nodes[i].used = 1;
	/* the first address is the user node's, whose reference must be $FFFF whatever .MPP
	   passed (NW 13); a multinode keeps the reference .MPP gave it */
	if (!g.node) {
		g.node = a;
		pb->addr_ref = 0xFFFF;
	}
	g.nodes[i].ref = pb->addr_ref;
	LOG("AAddNode %x: ours, reference %x", a, (u32)pb->addr_ref);
	return 0;
}

static long del_node(struct atlk_pb *pb)
{
	int k = node_index(pb->net_addr);
	if (k < 0) return -1;
	LOG("ADelNode %x", g.nodes[k].addr);
	pb->addr_ref = g.nodes[k].ref;
	g.nodes[k].used = 0;
	if (g.nodes[k].addr == g.node)
		g.node = 0;
	return 0;
}

static long node_ref(struct atlk_pb *pb)
{
	int k = node_index(pb->net_addr);
	if (k < 0) return 0;
	pb->addr_ref = g.nodes[k].ref;
	return 1;
}

static long get_info(struct agetinfo *r, long size)
{
	if ((s16)size < (s16)sizeof *r) return -1;
	memset(r, 0, sizeof *r);
	r->version = 3;
	r->length = sizeof *r;
	r->speed = 10000000;                            /* 10 Mbit/s Ethernet */
	r->bandwidth = 3;
	r->slot = g.slot;
	r->flags = 0x80;                                /* extended network: Phase 2 */
	r->addr_size = 6;
	memcpy(r->addr, g.mac, 6);
	r->maxnodes = MAXNODES;
	return 0;
}

/* ---- AInstall: find the card, open its .ENET, join the AppleTalk broadcast, attach the two
   802.2 types to the LAP Manager, start the timer, become the LAP write hook ---- */
extern char _start[];                           /* atlk_glue.S: the resource's first byte */
static const u8 enet_name[] = "\005.ENET";

static long open_card(u8 slot, u8 id)
{
	u8 pb[50];
	memset(pb, 0, sizeof pb);
	*(const u8 **)(pb + 18) = enet_name;            /* ioNamePtr */
	pb[34] = slot; pb[35] = id;                     /* ioSlot, ioID */
	if (et_openslot(pb)) return 0;
	return *(s16 *)(pb + 24);                       /* ioRefNum */
}

/* The first card that opens, in the Slot Manager's order. Not just the first card: on Aurora68 the
   wired port ($81) stays in the declaration ROM of a Pi 3B whose network chip then turns out to be
   missing, and its driver refuses to open; the Wi-Fi ($83) after it is the one to use. */
static long open_first_card(u8 *slot, u8 *id)
{
	u8 sp[56];
	u8 s = 0, i = 0;
	for (int n = 0; n < 8; n++) {
		long ref;
		memset(sp, 0, sizeof sp);
		*(u16 *)(sp + 40) = 4;                  /* spCategory: catNetwork */
		*(u16 *)(sp + 42) = 1;                  /* spCType: typeEtherNet */
		sp[48] = 3;                             /* spTBMask: any driver, any hardware */
		*(u32 *)(sp + 24) = 1;                  /* spParamData: disabled sResources too */
		sp[49] = s; sp[50] = i;                 /* the next one after the last tried */
		if (et_slotmgr(0x0C, sp)) return 0;     /* SGetTypeSRsrc */
		if (sp[49] == s && sp[50] == i) return 0;
		s = sp[49]; i = sp[50];
		if ((ref = open_card(s, i)) != 0) {
			*slot = s; *id = i;
			return ref;
		}
		LOG("AInstall: the card in slot %d, sResource %d, would not open: the next", s, i);
	}
	return 0;
}

static void shutdown(void)
{
	u8 pb[50];
	if (g.installed) et_lapmgr(L_WRTREMOVE, 0, 0, g.port, NULL, NULL);
	if (g.vbl_on) et_vremove(&vbl);
	if (g.ddp_on) et_lapmgr(L_802DETACH, 0, g.refnum, 0, NULL, et_ddp_spec);
	if (g.aarp_on) et_lapmgr(L_802DETACH, 0, g.refnum, 0, NULL, et_aarp_spec);
	if (g.multi) {
		memset(pb, 0, sizeof pb);
		*(s16 *)(pb + PB_REFNUM) = g.refnum; *(s16 *)(pb + PB_CSCODE) = ENET_DELMULTI;
		memcpy(pb + 28, bcast, 6);
		et_control(pb);
	}
	g.installed = g.vbl_on = g.ddp_on = g.aarp_on = g.multi = g.open = 0;
	g.node = 0;
	memset(g.nodes, 0, sizeof g.nodes);
}

static long install(u32 pram, u8 port)
{
	u8 pb[50], info[18];
	u8 slot = (u8)(pram >> 24), id = (u8)(pram >> 16);

	if (g.installed) return 0;
	g.port = port;
	if (!slot || !(g.refnum = (s16)open_card(slot, id))) {
		if (!(g.refnum = (s16)open_first_card(&slot, &id))) { LOG("AInstall: no Ethernet card"); return -1; }
	}
	g.slot = slot; g.srsrc = id;
	memset(pb, 0, sizeof pb);
	*(s16 *)(pb + PB_REFNUM) = g.refnum; *(s16 *)(pb + PB_CSCODE) = ENET_GETINFO;
	*(u8 **)(pb + PB_EPTR) = info; *(u16 *)(pb + 34) = sizeof info;
	if (et_control(pb)) { LOG("AInstall: EGetInfo failed"); return -1; }
	memcpy(g.mac, info, 6);
	memset(pb, 0, sizeof pb);
	*(s16 *)(pb + PB_REFNUM) = g.refnum; *(s16 *)(pb + PB_CSCODE) = ENET_ADDMULTI;
	memcpy(pb + 28, bcast, 6);
	g.multi = et_control(pb) == 0;
	g.ddp_on = et_lapmgr(L_802ATTACH, 0, g.refnum, 0, (void *)et_ddp_ph, et_ddp_spec) == 0;
	g.aarp_on = et_lapmgr(L_802ATTACH, 0, g.refnum, 0, (void *)et_aarp_ph, et_aarp_spec) == 0;
	if (!g.ddp_on || !g.aarp_on) { LOG("AInstall: L802Attach failed"); shutdown(); return -1; }
	vbl.qtype = 1; vbl.addr = (void *)et_vbl; vbl.count = AARP_REQ_TICKS;
	g.vbl_on = et_vinstall(&vbl) == 0;
	/* LWrtInsert: A0 = the code for the write hook, which is this resource's first byte;
	   flags 0 (the LAP Manager delivers to our own node), no ENQ count */
	if (et_lapmgr(L_WRTINSERT, 0, 0, port, _start, NULL) != 0) { LOG("AInstall: LWrtInsert failed"); shutdown(); return -1; }
	g.installed = 1;
	et_d1_out = (u32)slot << 24 | (u32)id << 16 | ET_RSRC_ID;
	LOG("AInstall: slot %d id %x refnum %d address %02x:%02x:%02x:%02x:%02x:%02x, code at %x",
	    slot, id, g.refnum, g.mac[0], g.mac[1], g.mac[2], g.mac[3], g.mac[4], g.mac[5], (u32)_start);
	return 0;
}

/* ---- the 'atlk' calls ---- */
long et_dispatch(long sel, long d1, long port, void *a0, void *a1)
{
	switch (sel) {
	case A_INSTALL:   et_d1_out = (u32)d1; return install((u32)d1, (u8)port);
	case A_SHUTDOWN:  LOG("AShutDown"); shutdown(); return 0;
	case A_GETINFO:   LOG("AGetInfo, %d bytes", (s32)(s16)d1); return get_info(a1, (s16)d1);
	case A_OPEN:      LOG("AOpen"); g.open = 1; return 0;
	case A_CLOSE:     LOG("AClose"); g.open = 0; g.node = 0; memset(g.nodes, 0, sizeof g.nodes); return 0;
	case A_ADDNODE:   return add_node(a0);
	case A_DELNODE:   return del_node(a0);
	case A_GETNODEREF: return node_ref(a0);
	}
	LOG("call %d not handled", sel);
	return -17;                                     /* controlErr: not a call we know */
}
