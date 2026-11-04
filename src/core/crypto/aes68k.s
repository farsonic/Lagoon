; Lagoon - AES encryption rounds for the 68020+ (vasm, Motorola syntax),
; used by the Amiga build instead of the C in aes.c (LN_CRYPTO_ASM).
; Same T-table algorithm as aes.c (FIPS-197 with the usual four 1 KB
; tables, ln_aes_t): the state lives in a 16-byte stack buffer so each
; table index is one move.b into d7 (bits 8-15 of d7 stay zero) and each
; lookup one scaled-index load; one round fits the 68020's 256-byte
; instruction cache. The last round takes S-box bytes from byte 1 of the
; T0 entries. Calling convention: vbcc (arguments on the stack, d0-d1/a0-a1
; scratch).
; SPDX-License-Identifier: GPL-2.0-only

	machine	68020
	section	code,code

	xref	_ln_aes_t
	xdef	_ln_aes_encrypt
	xdef	_ln_aes_cbcmac
	xdef	_ln_aes_ctr32

ST	equ	4		; state bytes in the caller's scratch (+4: return address)
OB	equ	20		; last-round output bytes
NR	equ	240		; offsetof(LnAes, nr)
REGS	reg	d2-d7/a2-a6	; 44 bytes

; encrypt the block in d0-d3 (big-endian words) in place
; in: a6 = LnAes, a0-a3 = T0..T3, d7 = 0 in bits 8-15, 32 bytes scratch at 0(sp) of the caller
; uses d4, d6, a4
	cnop	0,4
aes_core:
	move.l	a6,a4
	move.l	(a4)+,d4
	eor.l	d4,d0
	move.l	(a4)+,d4
	eor.l	d4,d1
	move.l	(a4)+,d4
	eor.l	d4,d2
	move.l	(a4)+,d4
	eor.l	d4,d3
	move.l	NR(a6),d6
	subq.w	#2,d6		; nr-1 full rounds
.round:
	movem.l	d0-d3,ST(sp)
	movem.l	(a4)+,d0-d3	; round key
	; t0 = T0[b0] ^ T1[b5] ^ T2[b10] ^ T3[b15] ^ rk
	move.b	ST+0(sp),d7
	move.l	(a0,d7.w*4),d4
	eor.l	d4,d0
	move.b	ST+5(sp),d7
	move.l	(a1,d7.w*4),d4
	eor.l	d4,d0
	move.b	ST+10(sp),d7
	move.l	(a2,d7.w*4),d4
	eor.l	d4,d0
	move.b	ST+15(sp),d7
	move.l	(a3,d7.w*4),d4
	eor.l	d4,d0
	; t1 = T0[b4] ^ T1[b9] ^ T2[b14] ^ T3[b3] ^ rk
	move.b	ST+4(sp),d7
	move.l	(a0,d7.w*4),d4
	eor.l	d4,d1
	move.b	ST+9(sp),d7
	move.l	(a1,d7.w*4),d4
	eor.l	d4,d1
	move.b	ST+14(sp),d7
	move.l	(a2,d7.w*4),d4
	eor.l	d4,d1
	move.b	ST+3(sp),d7
	move.l	(a3,d7.w*4),d4
	eor.l	d4,d1
	; t2 = T0[b8] ^ T1[b13] ^ T2[b2] ^ T3[b7] ^ rk
	move.b	ST+8(sp),d7
	move.l	(a0,d7.w*4),d4
	eor.l	d4,d2
	move.b	ST+13(sp),d7
	move.l	(a1,d7.w*4),d4
	eor.l	d4,d2
	move.b	ST+2(sp),d7
	move.l	(a2,d7.w*4),d4
	eor.l	d4,d2
	move.b	ST+7(sp),d7
	move.l	(a3,d7.w*4),d4
	eor.l	d4,d2
	; t3 = T0[b12] ^ T1[b1] ^ T2[b6] ^ T3[b11] ^ rk
	move.b	ST+12(sp),d7
	move.l	(a0,d7.w*4),d4
	eor.l	d4,d3
	move.b	ST+1(sp),d7
	move.l	(a1,d7.w*4),d4
	eor.l	d4,d3
	move.b	ST+6(sp),d7
	move.l	(a2,d7.w*4),d4
	eor.l	d4,d3
	move.b	ST+11(sp),d7
	move.l	(a3,d7.w*4),d4
	eor.l	d4,d3
	dbra	d6,.round
	movem.l	d0-d3,ST(sp)
	; last round: SubBytes + ShiftRows, S-box byte = byte 1 of T0[x]
	move.b	ST+0(sp),d7
	move.b	(1,a0,d7.w*4),OB+0(sp)
	move.b	ST+5(sp),d7
	move.b	(1,a0,d7.w*4),OB+1(sp)
	move.b	ST+10(sp),d7
	move.b	(1,a0,d7.w*4),OB+2(sp)
	move.b	ST+15(sp),d7
	move.b	(1,a0,d7.w*4),OB+3(sp)
	move.b	ST+4(sp),d7
	move.b	(1,a0,d7.w*4),OB+4(sp)
	move.b	ST+9(sp),d7
	move.b	(1,a0,d7.w*4),OB+5(sp)
	move.b	ST+14(sp),d7
	move.b	(1,a0,d7.w*4),OB+6(sp)
	move.b	ST+3(sp),d7
	move.b	(1,a0,d7.w*4),OB+7(sp)
	move.b	ST+8(sp),d7
	move.b	(1,a0,d7.w*4),OB+8(sp)
	move.b	ST+13(sp),d7
	move.b	(1,a0,d7.w*4),OB+9(sp)
	move.b	ST+2(sp),d7
	move.b	(1,a0,d7.w*4),OB+10(sp)
	move.b	ST+7(sp),d7
	move.b	(1,a0,d7.w*4),OB+11(sp)
	move.b	ST+12(sp),d7
	move.b	(1,a0,d7.w*4),OB+12(sp)
	move.b	ST+1(sp),d7
	move.b	(1,a0,d7.w*4),OB+13(sp)
	move.b	ST+6(sp),d7
	move.b	(1,a0,d7.w*4),OB+14(sp)
	move.b	ST+11(sp),d7
	move.b	(1,a0,d7.w*4),OB+15(sp)
	movem.l	OB(sp),d0-d3
	move.l	(a4)+,d4
	eor.l	d4,d0
	move.l	(a4)+,d4
	eor.l	d4,d1
	move.l	(a4)+,d4
	eor.l	d4,d2
	move.l	(a4)+,d4
	eor.l	d4,d3
	rts

; set up a0-a3 = T0..T3, d7 = 0
tables	macro
	lea	_ln_aes_t,a0
	lea	1024(a0),a1
	lea	2048(a0),a2
	lea	3072(a0),a3
	moveq	#0,d7
	endm

; void ln_aes_encrypt(const LnAes *a, const u8 in[16], u8 out[16])
	cnop	0,4
_ln_aes_encrypt:
	movem.l	REGS,-(sp)
	lea	-32(sp),sp
	move.l	80(sp),a6
	move.l	84(sp),a5
	tables
	move.l	(a5)+,d0
	move.l	(a5)+,d1
	move.l	(a5)+,d2
	move.l	(a5),d3
	bsr	aes_core
	move.l	88(sp),a5
	move.l	d0,(a5)+
	move.l	d1,(a5)+
	move.l	d2,(a5)+
	move.l	d3,(a5)
	lea	32(sp),sp
	movem.l	(sp)+,REGS
	rts

; void ln_aes_cbcmac(const LnAes *a, u8 x[16], const u8 *p, size_t nblk)
	cnop	0,4
_ln_aes_cbcmac:
	movem.l	REGS,-(sp)
	lea	-32(sp),sp
	move.l	92(sp),d5
	beq.s	.done
	move.l	80(sp),a6
	tables
	move.l	84(sp),a5
	movem.l	(a5),d0-d3
	move.l	88(sp),a5
.blk:
	move.l	(a5)+,d4
	eor.l	d4,d0
	move.l	(a5)+,d4
	eor.l	d4,d1
	move.l	(a5)+,d4
	eor.l	d4,d2
	move.l	(a5)+,d4
	eor.l	d4,d3
	bsr	aes_core
	subq.l	#1,d5
	bne.s	.blk
	move.l	84(sp),a5
	movem.l	d0-d3,(a5)
.done:
	lea	32(sp),sp
	movem.l	(sp)+,REGS
	rts

; void ln_aes_ctr32(const LnAes *a, u8 ctr[16], u8 *data, size_t nblk)
CTR	equ	32		; counter copy in the frame
	cnop	0,4
_ln_aes_ctr32:
	movem.l	REGS,-(sp)
	lea	-48(sp),sp
	move.l	108(sp),d5
	beq.s	.done
	move.l	96(sp),a6
	tables
	move.l	100(sp),a5
	move.l	(a5)+,CTR(sp)
	move.l	(a5)+,CTR+4(sp)
	move.l	(a5)+,CTR+8(sp)
	move.l	(a5),CTR+12(sp)
	move.l	104(sp),a5
.blk:
	addq.l	#1,CTR+12(sp)
	movem.l	CTR(sp),d0-d3
	bsr	aes_core
	eor.l	d0,(a5)+
	eor.l	d1,(a5)+
	eor.l	d2,(a5)+
	eor.l	d3,(a5)+
	subq.l	#1,d5
	bne.s	.blk
	move.l	100(sp),a5
	move.l	CTR+12(sp),12(a5)
.done:
	lea	48(sp),sp
	movem.l	(sp)+,REGS
	rts
