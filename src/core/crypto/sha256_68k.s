; Lagoon - SHA-256 compression function (FIPS 180-4) for the 68020+ (vasm,
; Motorola syntax), used by the Amiga build instead of the C sha256_block
; in hash.c (LN_CRYPTO_ASM): vbcc builds rotates from shift pairs, the
; 68020 has a barrel shifter. The message schedule is expanded into a
; 64-word frame first; the working variables a..d and e..h live in two
; downward-growing stacks, so each round writes the new a and e and moves
; one pointer instead of shifting eight variables. One round is about 100
; bytes and stays in the 68020's instruction cache. vbcc calling convention.
; SPDX-License-Identifier: GPL-2.0-only

	machine	68020
	section	code,code

	xref	_ln_sha256_k
	xdef	_ln_sha256_block

REGS	reg	d2-d7/a2-a5	; 40 bytes
W	equ	0		; w[64]
AS	equ	256		; a-stack: 68 words, a = (a5), b = 4(a5), c, d
OFS	equ	272		; e-stack offset from the a-stack: e = OFS(a5), f, g, h
FRAME	equ	256+2*272

; void ln_sha256_block(u32 s[8], const u8 *p)
	cnop	0,4
_ln_sha256_block:
	movem.l	REGS,-(sp)
	lea	-FRAME(sp),sp
	move.l	FRAME+48(sp),a0		; p
	lea	W(sp),a3
	moveq	#15,d1
.load:
	move.l	(a0)+,(a3)+		; big-endian words, as on the wire
	dbra	d1,.load
	moveq	#10,d5
	moveq	#9,d6
	moveq	#11,d7
	moveq	#47,d1
.sched:					; w[i] = w[i-16] + s0(w[i-15]) + w[i-7] + s1(w[i-2])
	move.l	-60(a3),d0
	move.l	d0,d3
	ror.l	d7,d3
	eor.l	d0,d3
	ror.l	#7,d3			; ror7 ^ ror18
	lsr.l	#3,d0
	eor.l	d0,d3
	move.l	-8(a3),d0
	move.l	d0,d4
	ror.l	#2,d4
	eor.l	d0,d4
	swap	d4
	ror.l	#1,d4			; ror17 ^ ror19
	lsr.l	d5,d0
	eor.l	d0,d4
	add.l	d4,d3
	add.l	-64(a3),d3
	add.l	-28(a3),d3
	move.l	d3,(a3)+
	dbra	d1,.sched

	move.l	FRAME+44(sp),a0		; s
	lea	AS+64*4(sp),a5
	movem.l	(a0),d0-d3
	movem.l	d0-d3,(a5)		; a b c d
	move.l	d0,d1			; d1 = a
	movem.l	16(a0),d0/d2-d4
	movem.l	d0/d2-d4,OFS(a5)	; e f g h, d0 = e
	lea	W(sp),a3
	lea	_ln_sha256_k,a4
	moveq	#63,d5
.round:
	move.l	OFS+4(a5),d2		; Ch(e,f,g) = g ^ (e & (f ^ g))
	move.l	OFS+8(a5),d3
	eor.l	d3,d2
	and.l	d0,d2
	eor.l	d3,d2
	add.l	OFS+12(a5),d2		; + h
	add.l	(a4)+,d2		; + K[i]
	add.l	(a3)+,d2		; + W[i]
	move.l	d0,d3			; S1(e) = ror6(e ^ ror5(e ^ ror14(e)))
	swap	d3
	rol.l	#2,d3
	eor.l	d0,d3
	ror.l	#5,d3
	eor.l	d0,d3
	ror.l	#6,d3
	add.l	d3,d2			; T1
	move.l	12(a5),d0
	add.l	d2,d0			; new e = d + T1
	move.l	4(a5),d3		; Maj(a,b,c) = (a & b) | (c & (a | b))
	move.l	d3,d4
	and.l	d1,d3
	or.l	d1,d4
	and.l	8(a5),d4
	or.l	d4,d3
	add.l	d3,d2
	move.l	d1,d3			; S0(a) = ror2(a ^ ror11(a ^ ror9(a)))
	ror.l	d6,d3
	eor.l	d1,d3
	ror.l	d7,d3
	eor.l	d1,d3
	ror.l	#2,d3
	add.l	d3,d2
	move.l	d2,d1			; new a = T1 + S0 + Maj
	move.l	d1,-(a5)
	move.l	d0,OFS(a5)
	dbra	d5,.round

	move.l	FRAME+44(sp),a0
	lea	OFS(a5),a1
	movem.l	(a5),d0/d2-d4
	add.l	d0,(a0)+
	add.l	d2,(a0)+
	add.l	d3,(a0)+
	add.l	d4,(a0)+
	movem.l	(a1),d0/d2-d4
	add.l	d0,(a0)+
	add.l	d2,(a0)+
	add.l	d3,(a0)+
	add.l	d4,(a0)+
	lea	FRAME(sp),sp
	movem.l	(sp)+,REGS
	rts
