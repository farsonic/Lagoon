| Lagoon on the classic Mac OS: the bridge thread's register-level parts (lm_bridge.c).
|
| The thread is a second stack in the application's heap with its own saved registers.
| lmb_switch saves the callee-saved registers and the stack pointer of one side and takes the
| other's: the host (a deferred task) switches to the thread, the thread switches back when it
| waits. The Time Manager task, the deferred task and the AppleTalk completion routine are
| called by the system at interrupt time with whatever A5 the program in front has: each entry
| saves the registers C may change, puts Lagoon's A5 back (lm_a5, mac_thunks.S) and calls C.
| The traps are fixed words (no self-modifying code as in riptide's mac_pb, which the program
| may be in the middle of when the thread interrupts it). Trap words from Inside Macintosh:
| _Open $A000, _Control $A004 (asynchronous with bit 10: $A404), _HFSDispatch $A260 (selector
| in D0), _InsTime $A058, _RmvTime $A059, _PrimeTime $A05A, _DTInstall $A082.
| SPDX-License-Identifier: GPL-2.0-only
	.text
	.even

| void lmb_switch(void **save_sp, void *load_sp)
	.globl	lmb_switch
lmb_switch:
	move.l	4(%sp),%a0
	move.l	8(%sp),%d0
	movem.l	%d2-%d7/%a2-%a6,-(%sp)
	move.l	%sp,(%a0)
	move.l	%d0,%sp
	movem.l	(%sp)+,%d2-%d7/%a2-%a6
	rts

| the thread's first switch "returns" here (lm_bridge.c builds the frame); lmb_thread_main never
| returns: at its end it waits for good
	.globl	lmb_thread_start
lmb_thread_start:
	jsr	lmb_thread_main
1:	bra.s	1b

| the Time Manager task (A1 = the task record), the deferred task (A1 = its parameter) and the
| completion routine of asynchronous AppleTalk calls (A0 = the parameter block, D0 = result)
	.globl	lmb_tm_entry
lmb_tm_entry:
	movem.l	%d0-%d2/%a0-%a1/%a5,-(%sp)
	move.l	lm_a5,%a5
	jsr	lmb_tm
	movem.l	(%sp)+,%d0-%d2/%a0-%a1/%a5
	rts
	.globl	lmb_dt_entry
lmb_dt_entry:
	movem.l	%d0-%d2/%a0-%a1/%a5,-(%sp)
	move.l	lm_a5,%a5
	jsr	lmb_dt
	movem.l	(%sp)+,%d0-%d2/%a0-%a1/%a5
	rts
	.globl	lmb_done_entry
lmb_done_entry:
	movem.l	%d0-%d2/%a0-%a1/%a5,-(%sp)
	move.l	lm_a5,%a5
	jsr	lmb_kick
	movem.l	(%sp)+,%d0-%d2/%a0-%a1/%a5
	rts

| short lmb_open(void *pb)            _Open, synchronous
| short lmb_control(void *pb)         _Control, synchronous
| short lmb_control_async(void *pb)   _Control, asynchronous
| short lmb_control_immed(void *pb)   _Control, immediate ($A204: AddNode must be, Technote NW 13)
| short lmb_volmount(void *pb)        _HFSDispatch PBVolumeMount ($41), synchronous
	.globl	lmb_open
lmb_open:
	move.l	4(%sp),%a0
	.short	0xA000
	ext.l	%d0
	rts
	.globl	lmb_control
lmb_control:
	move.l	4(%sp),%a0
	.short	0xA004
	ext.l	%d0
	rts
	.globl	lmb_control_async
lmb_control_async:
	move.l	4(%sp),%a0
	.short	0xA404
	ext.l	%d0
	rts
	.globl	lmb_control_immed
lmb_control_immed:
	move.l	4(%sp),%a0
	.short	0xA204
	ext.l	%d0
	rts
	.globl	lmb_volmount
lmb_volmount:
	move.l	4(%sp),%a0
	moveq	#0x41,%d0
	.short	0xA260
	ext.l	%d0
	rts

| void lmb_instime(void *tm), lmb_rmvtime(void *tm), lmb_primetime(void *tm, long ms),
| short lmb_dtinstall(void *dt)
	.globl	lmb_instime
lmb_instime:
	move.l	4(%sp),%a0
	.short	0xA058
	rts
	.globl	lmb_rmvtime
lmb_rmvtime:
	move.l	4(%sp),%a0
	.short	0xA059
	rts
	.globl	lmb_primetime
lmb_primetime:
	move.l	4(%sp),%a0
	move.l	8(%sp),%d0
	.short	0xA05A
	rts
	.globl	lmb_dtinstall
lmb_dtinstall:
	move.l	4(%sp),%a0
	.short	0xA082
	ext.l	%d0
	rts

| The multinode's receive routine. .MPP calls it at interrupt time with a socket listener's
| registers (Inside Macintosh: Networking 7-13, 12-10): A2 = .MPP's variables, whose Read Header
| Area starts at 1(A2) (toRHA), A3 = past the bytes already in it, A4 = ReadPacket (ReadRest at
| 2(A4)), D1 = the bytes still to read; A0, A1 and D1 belong to .MPP until ReadRest. The routine
| copies the header area and the rest of the datagram into the next slot of lmb_mn_ring
| (lm_bridge.c: MN_SLOTS slots of len, rha, then 620 bytes), marks it full and asks for the
| deferred task. With no free slot the datagram is read into nothing (D3 = 0), as the AppleTalk
| Manager wants.
	.equ	SLOT, 624
	.equ	ROOM, 620
	.globl	lmb_mn_recv
lmb_mn_recv:
	movem.l	%d2/%d4-%d7/%a5-%a6,-(%sp)
	move.l	lmb_mn_head,%d4
	mulu.w	#SLOT,%d4
	lea	lmb_mn_ring,%a5
	add.l	%d4,%a5			| A5: the slot
	tst.w	(%a5)
	bne.s	3f			| still full: drop this one
	lea	1(%a2),%a6		| the Read Header Area
	moveq	#0,%d6
1:	cmp.l	%a3,%a6
	bcc.s	2f
	move.b	(%a6)+,4(%a5,%d6.w)
	addq.w	#1,%d6
	cmp.w	#32,%d6
	bcs.s	1b
2:	move.w	%d6,2(%a5)
	lea	4(%a5,%d6.w),%a3	| the rest goes after it
	move.w	#ROOM,%d3
	sub.w	%d6,%d3
	jsr	2(%a4)			| ReadRest (its flags are not looked at: A3 says what came)
	move.l	%a3,%d0
	sub.l	%a5,%d0
	subq.l	#4,%d0
	move.w	%d0,(%a5)		| the length: the slot is full
	move.l	lmb_mn_head,%d0
	addq.l	#1,%d0
	and.l	#15,%d0		| MN_SLOTS - 1
	move.l	%d0,lmb_mn_head
	jsr	lmb_kick
	bra.s	4f
3:	moveq	#0,%d3
	jsr	2(%a4)			| ReadRest into nothing
4:	movem.l	(%sp)+,%d2/%d4-%d7/%a5-%a6
	rts

| unsigned short lmb_irq_off(void), void lmb_irq_restore(unsigned short sr)
	.globl	lmb_irq_off
lmb_irq_off:
	move.w	%sr,%d0
	ori.w	#0x0700,%sr
	rts
	.globl	lmb_irq_restore
lmb_irq_restore:
	move.w	6(%sp),%sr
	rts
	.section .note.GNU-stack,"",@progbits
