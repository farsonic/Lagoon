| Lagoon EtherTalk - the 'atlk' resource's way in, and every place where AppleTalk, the LAP
| Manager or the .ENET driver call with values in registers rather than on a C stack.
|
| Backstory. An 'atlk' is a code resource that the Network control panel (or, at startup, the LAP
| Manager) loads into the system heap, calls, and then detaches, so it stays there for as long as
| the connection is in use. It has two entry points fixed by the 1988 "EtherTalk and Alternate
| AppleTalk Connections Reference": the first byte is the LAP write hook (.MPP's every outgoing
| datagram goes through it, via the LAP Manager), and two bytes in is everything else, AInstall,
| AShutDown, AGetInfo, AAddNode and the others, chosen by D0. Both are two-byte branches, as in
| Apple's own LocalTalk 'atlk' in the System file.
|
| The C side (ethertalk.c) is linked at 0 and carries a table of its 32-bit absolute fields
| (tools/mkadev.py appends it, riptide tools/mac_elf.py builds it); the first call adds the
| resource's address to each, in place, and flushes the caches. Until then only PC-relative
| addressing is used here.
|
| The register conventions, by entry:
|   atlk_write   A0 = where to go when done, A1 = the WDS, A2 = .MPP's variables, D0.B nonzero
|                = send LocalTalk ENQs (not used: AAddNode does it), D2 = the next hop (network in
|                bits 8-23, node in 0-7). D0 = the result when jumping to A0; A1, A2, D2 as they
|                came, A4-A6 and D4-D7 kept (the 1988 reference).
|   atlk_call    D0 = the call, D1, D4.B = port, A0 and A1 its arguments; D0 back, D1 back from
|                AInstall (the parameter RAM value), A1 back from AGetInfo.
|   et_ddp_ph /  the LAP Manager's 802.2 dispatcher, per Technote NW 13 "Writing the Protocol
|   et_aarp_ph   Handler for the LAP Manager": A0, A1 the driver's until ReadRest, A3 past the
|                bytes read so far, A4 -> ReadPacket (ReadRest 2 bytes on), D1 bytes left.
|   et_deliver   LRdDispatch, the other way: A2 = .MPP's variables, A3 past the header bytes put
|                in .MPP's Read Header Area, A4 -> our ReadPacket, D1 bytes left, D2 = the LAP
|                type with the address reference number in the high word. The LAP Manager
|                does not return when it finds the handler: it drops our return address and
|                jumps, so the handler's RTS comes back one level up (bsr below).
| SPDX-License-Identifier: GPL-2.0-only

	.text
	.even
	.globl	_start
_start:
	bra.s	1f			| +0: the LAP write hook
	bra.s	2f			| +2: the 'atlk' calls
	.globl	_reloc_off
_reloc_off:
	.long	0			| tools/mkadev.py: where the relocation table starts
relocated:
	.word	0
1:	bra.w	atlk_write
2:	bra.w	atlk_call

| ---- the 'atlk' calls ----
atlk_call:
	movem.l	%d1-%d7/%a0-%a6,-(%sp)	| 56 bytes: D1 first, at (sp)
	moveq	#0,%d7
	move.w	%d0,%d7			| the call: a word (.MPP sets only the low half of D0)
	lea	relocated(%pc),%a2
	tst.w	(%a2)
	bne.s	5f
	move.w	#1,(%a2)
	lea	_start(%pc),%a3		| the image, where the Resource Manager put it
	move.l	_reloc_off(%pc),%d2
	lea	(%a3,%d2.l),%a4		| the table: a count, then the offsets
	move.l	(%a4)+,%d3
	move.l	%a3,%d5
	bra.s	4f
3:	move.l	(%a4)+,%d6
	add.l	%d5,(%a3,%d6.l)
4:	subq.l	#1,%d3
	bcc.s	3b
	movem.l	%d0-%d1/%a0-%a1,-(%sp)
	moveq	#1,%d0
	.short	0xA198			| _HWPriv 1: FlushInstructionCache (a 68040's data cache too)
	movem.l	(%sp)+,%d0-%d1/%a0-%a1
5:	move.l	%a1,-(%sp)
	move.l	%a0,-(%sp)
	moveq	#0,%d2
	move.b	%d4,%d2
	move.l	%d2,-(%sp)		| the port
	move.l	%d1,-(%sp)
	move.l	%d7,-(%sp)
	jsr	et_dispatch		| long et_dispatch(sel, d1, port, a0, a1)
	lea	20(%sp),%sp
	cmp.l	#1,%d7			| AInstall: D1 carries the parameter RAM value back
	bne.s	6f
	move.l	et_d1_out,(%sp)
6:	movem.l	(%sp)+,%d1-%d7/%a0-%a6
	tst.w	%d0
	rts

| ---- the LAP write hook ----
atlk_write:
	movem.l	%d0-%d7/%a0-%a6,-(%sp)	| 60 bytes: D0 first, at (sp)
	move.l	%d2,-(%sp)		| the next hop
	moveq	#0,%d3
	move.b	%d0,%d3
	move.l	%d3,-(%sp)		| ENQs?
	move.l	%a2,-(%sp)
	move.l	%a1,-(%sp)
	jsr	et_write		| long et_write(wds, mpp, enq, dest)
	lea	16(%sp),%sp
	move.l	%d0,(%sp)		| D0 = the result at the continuation
	movem.l	(%sp)+,%d0-%d7/%a0-%a6
	jmp	(%a0)

| ---- receiving: the LAP Manager's 802.2 dispatcher calls these ----
	.equ	RXBUF,	1536		| a whole Ethernet frame's worth
	.globl	et_ddp_ph
et_ddp_ph:
	movem.l	%d4-%d7/%a2/%a5-%a6,-(%sp)
	lea	rx_ddp(%pc),%a5		| the C routine
	bra.s	ph_common
	.globl	et_aarp_ph
et_aarp_ph:
	movem.l	%d4-%d7/%a2/%a5-%a6,-(%sp)
	lea	rx_aarp(%pc),%a5
ph_common:
	move.l	%a3,%d6			| the LAP Manager's read position: its header bytes are behind it
	lea	et_rxbuf,%a3
	move.l	#RXBUF,%d3
	jsr	2(%a4)			| ReadRest: the rest of the frame into et_rxbuf
	ext.l	%d3			| buffer size - bytes there were (IM II); negative: too long
	bmi.s	1f
	move.l	#RXBUF,%d0
	sub.l	%d3,%d0			| the bytes read
	move.l	%d0,-(%sp)
	pea	et_rxbuf
	move.l	%d6,-(%sp)
	jsr	(%a5)
	lea	12(%sp),%sp
1:	movem.l	(%sp)+,%d4-%d7/%a2/%a5-%a6
	rts
rx_ddp:	jmp	et_rx_ddp		| void et_rx_ddp(rha_next, pkt, len)
rx_aarp:
	jmp	et_rx_aarp		| void et_rx_aarp(rha_next, pkt, len)

| ---- delivering up: LRdDispatch, with our ReadPacket over a datagram held in memory ----
	.globl	et_deliver
et_deliver:				| long et_deliver(mpp, rha_next, data, left, d2): 0 = a handler took it
	movem.l	%d2-%d7/%a2-%a6,-(%sp)	| 44 bytes
	move.l	48(%sp),%a2
	move.l	52(%sp),%a3
	move.l	56(%sp),%a0		| A0: the next byte for ReadPacket
	move.l	60(%sp),%d1		| D1: bytes left
	move.l	64(%sp),%d2
	lea	readpacket(%pc),%a4
	moveq	#0,%d7			| handlers keep D4-D7: still 0 if one ran
	bsr.s	1f			| the handler's RTS lands after this
	move.l	%d7,%d0
	movem.l	(%sp)+,%d2-%d7/%a2-%a6
	rts
1:	move.l	0x0B18,%a1		| LAPMgrPtr
	moveq	#1,%d0			| LRdDispatch
	jsr	2(%a1)
	moveq	#1,%d7			| back here: nobody has the type
	rts

| ReadPacket (A4): D3 = bytes wanted, into (A3)+. Z set when done; more than there is: Z clear.
| Both keep every register but D0, D1, D3, A0 and A3, as .MPP's own do.
| ReadRest (2(A4)): A3 = buffer, D3 = its size; copies what fits, D3 = size - bytes there were
| (System 7.1's .MPP answers the same for its own intranode delivery). A0 and D1 are the state.
readpacket:
	bra.s	rp_packet
	bra.s	rp_rest
rp_packet:
	addq.w	#1,et_rp_calls
	cmp.w	%d1,%d3
	bhi.s	2f
	sub.w	%d3,%d1
	bra.s	1f
0:	move.b	(%a0)+,(%a3)+
1:	dbf	%d3,0b
	moveq	#0,%d3
	moveq	#0,%d0			| Z set
	rts
2:	moveq	#-92,%d0		| eLenErr; Z clear
	rts
rp_rest:				| only D0, D1, D3 change: .MPP's echo responder keeps its place
	addq.w	#1,et_rr_calls		| in D2 across this call (System 7.1's own ReadRest leaves D2;
	move.w	%d3,%d0			| the first version counted in D2, and echo replies went to 0.0:0)
	cmp.w	%d1,%d0
	bls.s	1f
	move.w	%d1,%d0			| the buffer is bigger: copy what there is
1:	sub.w	%d1,%d3
	bra.s	3f
2:	move.b	(%a0)+,(%a3)+
3:	dbf	%d0,2b
	moveq	#0,%d1
	moveq	#0,%d0			| Z set
	rts

| ---- the timer: a VBL task (A0 = the task), every AARP retry interval ----
	.globl	et_vbl
et_vbl:
	move.w	#12,10(%a0)		| vblCount again: 1/5 s (AARP_REQ_TICKS)
	movem.l	%d0-%d7/%a0-%a6,-(%sp)
	jsr	et_tick
	movem.l	(%sp)+,%d0-%d7/%a0-%a6
	rts

| ---- calls for C. OS traps change D0-D2/A0-A1; GCC wants D2 kept ----
	.globl	et_control, et_control_async, et_openslot, et_slotmgr, et_vinstall, et_vremove
et_control:
	move.l	4(%sp),%a0
	move.l	%d2,-(%sp)
	.short	0xA004			| _Control
	bra.s	trap_out
et_control_async:
	move.l	4(%sp),%a0
	move.l	%d2,-(%sp)
	.short	0xA404			| _Control ,ASYNC
	bra.s	trap_out
et_openslot:
	move.l	4(%sp),%a0
	move.l	%d2,-(%sp)
	.short	0xA200			| _Open with the slot bit: OpenSlot
	bra.s	trap_out
et_slotmgr:
	move.l	4(%sp),%d0
	move.l	8(%sp),%a0
	move.l	%d2,-(%sp)
	.short	0xA06E			| _SlotManager
	bra.s	trap_out
et_vinstall:
	move.l	4(%sp),%a0
	move.l	%d2,-(%sp)
	.short	0xA033			| _VInstall
	bra.s	trap_out
et_vremove:
	move.l	4(%sp),%a0
	move.l	%d2,-(%sp)
	.short	0xA034			| _VRemove
trap_out:
	move.l	(%sp)+,%d2
	ext.l	%d0
	rts

	.globl	et_lapmgr
et_lapmgr:				| long et_lapmgr(d0, d1, d2, d4, a0, a1)
	movem.l	%d2-%d7/%a2-%a6,-(%sp)
	move.l	48(%sp),%d0
	move.l	52(%sp),%d1
	move.l	56(%sp),%d2
	move.l	60(%sp),%d4
	move.l	64(%sp),%a0
	move.l	68(%sp),%a1
	move.l	0x0B18,%a2		| LAPMgrPtr
	jsr	2(%a2)
	movem.l	(%sp)+,%d2-%d7/%a2-%a6
	rts

	.globl	et_flush_caches, et_irq_off, et_irq_restore, et_ticks
et_flush_caches:
	move.l	%d2,-(%sp)
	moveq	#1,%d0
	.short	0xA198			| _HWPriv 1
	move.l	(%sp)+,%d2
	rts
et_irq_off:
	moveq	#0,%d0
	move.w	%sr,%d0
	ori.w	#0x0700,%sr
	rts
et_irq_restore:
	move.w	6(%sp),%sr
	rts
et_ticks:
	move.l	0x016A,%d0		| Ticks
	rts

| ---- the 802.2 protocol specifications for L802Attach (Inside Macintosh: Networking, 10-41):
|      length-prefixed fields, DSAP $AA, the SNAP type, for AARP its hardware/protocol types ----
	.globl	et_ddp_spec, et_aarp_spec
et_ddp_spec:
	.byte	1, 0xAA, 5, 0x08, 0x00, 0x07, 0x80, 0x9B, 0
et_aarp_spec:
	.byte	1, 0xAA, 5, 0x00, 0x00, 0x00, 0x80, 0xF3, 4, 0x00, 0x01, 0x80, 0x9B, 0
	.even
