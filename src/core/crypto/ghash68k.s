; Lagoon - GHASH for the 68020+ (vasm, Motorola syntax), used by the Amiga
; build instead of the C ln_ghash_blocks in gcm.c (LN_CRYPTO_ASM). Same
; method (Shoup's 8-bit table, Horner from the last byte): Z in d0-d3, the
; 128-bit byte shift is three move.b/ror.l pairs and an lsr.l, the byte
; shifted out indexes ln_gcm_red8, the next input byte the two 8-byte-stride
; halves of the per-key table (LnGcm.mh/ml). vbcc calling convention.
; SPDX-License-Identifier: GPL-2.0-only

	machine	68020
	section	code,code

	xref	_ln_gcm_red8
	xdef	_ln_ghash_blocks

MH	equ	244		; offsetof(LnGcm, mh) = sizeof(LnAes)
REGS	reg	d2-d7/a2-a5	; 40 bytes

; void ln_ghash_blocks(const LnGcm *g, u32 y[4], const u8 *p, size_t nblk)
	cnop	0,4
_ln_ghash_blocks:
	movem.l	REGS,-(sp)
	lea	-16(sp),sp
	move.l	72(sp),d5
	beq	.done
	move.l	60(sp),a2
	lea	MH(a2),a2		; mh
	lea	2048(a2),a3		; ml
	lea	_ln_gcm_red8,a1
	move.l	64(sp),a0
	movem.l	(a0),d0-d3
	move.l	68(sp),a4
	moveq	#0,d7
.blk:
	move.l	(a4)+,d4		; x = y ^ block
	eor.l	d4,d0
	move.l	(a4)+,d4
	eor.l	d4,d1
	move.l	(a4)+,d4
	eor.l	d4,d2
	move.l	(a4)+,d4
	eor.l	d4,d3
	movem.l	d0-d3,(sp)
	lea	15(sp),a5
	move.b	(a5),d7			; Z = M[x15]
	move.l	(0,a2,d7.w*8),d0
	move.l	(4,a2,d7.w*8),d1
	move.l	(0,a3,d7.w*8),d2
	move.l	(4,a3,d7.w*8),d3
	moveq	#14,d6
.byte:
	move.b	d3,d7			; Z = Z * x^8: shift right a byte ...
	move.b	d2,d3
	ror.l	#8,d3
	move.b	d1,d2
	ror.l	#8,d2
	move.b	d0,d1
	ror.l	#8,d1
	lsr.l	#8,d0
	move.l	(a1,d7.w*4),d4		; ... and fold the byte back in
	eor.l	d4,d0
	move.b	-(a5),d7		; Z ^= M[x_i]
	move.l	(0,a2,d7.w*8),d4
	eor.l	d4,d0
	move.l	(4,a2,d7.w*8),d4
	eor.l	d4,d1
	move.l	(0,a3,d7.w*8),d4
	eor.l	d4,d2
	move.l	(4,a3,d7.w*8),d4
	eor.l	d4,d3
	dbra	d6,.byte
	subq.l	#1,d5
	bne	.blk
	move.l	64(sp),a0
	movem.l	d0-d3,(a0)
.done:
	lea	16(sp),sp
	movem.l	(sp)+,REGS
	rts
