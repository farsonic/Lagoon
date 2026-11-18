/*
 * Lagoon EtherTalk - AppleTalk Phase 2 over Ethernet for System 7, Lagoon's own: the constants
 * and the C side's view of the assembly glue (atlk_glue.S).
 *
 * Backstory. System 7.1 carries Apple's AppleTalk (.MPP version 57, the LAP Manager, LocalTalk)
 * but not EtherTalk, which came on a separate disk (the Network Software Installer). The pieces
 * a connection file needs are documented in three places that survive:
 *   - "EtherTalk and Alternate AppleTalk Connections Reference" (Apple, draft of 27 June 1988):
 *     the 'adev' calls GetADEV/SelectADEV, the 'atlk' calls AInstall/AShutDown, the LAP
 *     Manager's calls and the LAP write hook's registers;
 *   - Technote NW 13, "AppleTalk: The Rest of the Story" (1994): AGetInfo, AAddNode, ADelNode,
 *     AGetNodeRef, AOpen, AClose as .MPP 57 makes them, and how packets go up with an address
 *     reference number;
 *   - Inside Macintosh: Networking (1994), chapter 10: L802Attach and the LAP Manager's own
 *     802.2 dispatcher, which hands Phase 2 frames to a protocol handler per SNAP type.
 * Where they were silent, System 7.1's own .MPP ('drvr' 9) and Network control panel were read
 * (disassembled, not copied): the Read Header Area at 1(A2) of .MPP's variables, the 24-bit
 * next-hop address in D2 of the write hook, the 22-byte AGetInfo record, the 'ICN#' -4032 the
 * control panel insists on, the connection's long in extended parameter RAM at $E0.
 *
 * The frames are AppleTalk Phase 2 on Ethernet (Inside AppleTalk, second edition, chapter 2):
 * 802.3 with an 802.2 LLC header AA AA 03 and a SNAP header 08 00 07 80 9B (DDP) or
 * 00 00 00 80 F3 (AARP), broadcasts to 09:00:07:FF:FF:FF.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LAGOON_ETHERTALK_H
#define LAGOON_ETHERTALK_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;
typedef signed short s16;
typedef signed long s32;

/* the connection's resource ID: 'adev' and 'atlk' share it, and it is the low byte of the
   parameter RAM long that names the active connection. Apple kept 1-127 for itself (LocalTalk
   is 1, its EtherTalk 2); developers were to ask Apple for one of 128-254, a registry that is
   long gone, so Lagoon takes one well away from the numbers the period's card makers used. */
#define ET_RSRC_ID      168

/* the 'atlk' calls (D0 at the resource's start + 2): the 1988 reference and Technote NW 13 */
#define A_INSTALL       1
#define A_SHUTDOWN      2
#define A_GETINFO       3
#define A_OPEN          7
#define A_CLOSE         8
#define A_ADDNODE       9
#define A_DELNODE       10
#define A_GETNODEREF    11

/* the LAP Manager's calls (D0, JSR 2 bytes past the address in LAPMgrPtr, $B18) */
#define LAPMGR_PTR      0x0B18
#define L_RDDISPATCH    1
#define L_WRTINSERT     2
#define L_WRTREMOVE     3
#define L_802ATTACH     21
#define L_802DETACH     22

/* .ENET Control calls (Inside Macintosh: Networking, chapter 11) */
#define ENET_DELMULTI   245
#define ENET_ADDMULTI   246
#define ENET_WRITE      249
#define ENET_GETINFO    252

/* the AppleTalk side of Ethernet (Inside AppleTalk, 2nd ed., 2-14 and appendix B) */
#define AARP_HW_ETHER   1           /* AARP hardware type: Ethernet */
#define AARP_PROTO_DDP  0x809B      /* AARP protocol type: AppleTalk (DDP's Ethernet type) */
#define AARP_REQUEST    1
#define AARP_RESPONSE   2
#define AARP_PROBE      3
#define AARP_PROBE_TICKS 12         /* a probe every 1/5 s ... */
#define AARP_PROBES     10          /* ... ten of them, unless .MPP asks for another number */
#define AARP_REQ_TICKS  12          /* an unanswered request is sent again after 1/5 s ... */
#define AARP_REQ_TRIES  5           /* ... five times, then the waiting datagram is dropped */
#define DDP_MAX         600         /* the longest DDP datagram: 13 + 586 bytes of data, and one to spare */
#define LAP_TYPE_LONG   2           /* the LAP type .MPP reads long-header DDP under */

/* the AGetInfo record (Technote NW 13; .MPP 57 asks for 22 bytes) */
struct agetinfo {
	u16 version;                /* 3: answers AAddNode, ADelNode, AGetNodeRef */
	u16 length;
	u32 speed;                  /* bits per second */
	u8  bandwidth;              /* the router's link weight */
	u8  reserved1;
	u8  slot;                   /* the card's slot (SNMP's Router Manager reports it) */
	u8  reserved2;
	u8  flags;                  /* bit 7: an extended (Phase 2) network */
	u8  addr_size;
	u8  addr[6];
	u16 maxnodes;               /* 1: the user node only, acquired with AAddNode */
} __attribute__((packed));

/* the parameter block of AAddNode, ADelNode and AGetNodeRef (Technote NW 13: a Control block's
   header, then these at the offsets given) */
struct atlk_pb {
	u8  header[28];
	u32 net_addr;               /* $1C: network in bits 8-23, node in bits 0-7 */
	u16 num_tries;              /* $20: AARP probes to send */
	void *mpp_vars;             /* $22: .MPP's variables */
	void *port_use;             /* $26: the port-use byte */
	u16 addr_ref;               /* $2A: the address reference number */
} __attribute__((packed));

/* ---- atlk_glue.S, for the C side ---- */
s16  et_control(void *pb);                      /* _Control, waits */
s16  et_control_async(void *pb);                /* _Control ,ASYNC */
s16  et_openslot(void *pb);                     /* _Open with the slot bit */
s16  et_slotmgr(long selector, void *spblock);  /* _SlotManager */
s16  et_vinstall(void *task);
s16  et_vremove(void *task);
long et_lapmgr(long d0, long d1, long d2, long d4, void *a0, void *a1);   /* a LAP Manager call */
void et_flush_caches(void);
u16  et_irq_off(void);                          /* raise to level 7, the old SR back */
void et_irq_restore(u16 sr);
long et_deliver(void *mpp, u8 *rha_next, u8 *data, long left, long d2);   /* LRdDispatch: 0 = taken */
extern u16 et_rp_calls, et_rr_calls;            /* our ReadPacket and ReadRest, called */
u32  et_ticks(void);
extern char et_aarp_spec[], et_ddp_spec[];      /* the 802.2 protocol specifications */
void et_aarp_ph(void), et_ddp_ph(void), et_vbl(void);   /* register-level entries */

/* ---- ethertalk.c, called from the glue ---- */
long et_dispatch(long sel, long d1, long port, void *a0, void *a1);
long et_write(const u8 *wds, u8 *mpp, long enq, u32 dest);
void et_rx_aarp(const u8 *rha_next, const u8 *pkt, long len);
void et_rx_ddp(const u8 *rha_next, const u8 *pkt, long len);
void et_tick(void);
extern u32 et_d1_out;                           /* AInstall's D1 on the way out */
extern u8 et_rxbuf[1536];                       /* a received frame's rest (ReadRest) */

#endif
