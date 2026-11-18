| Lagoon on the classic Mac OS: the calls back into the program. MUI's dispatchers are called
| BOOPSI's way (a0 = class hook, a2 = object, a1 = message: rp_hook_call, which riptide's
| src/amiga/prefs/mui_util.c uses for DoMethodA). Riptide's socket interface calls the
| program's yield and break_pending while a call waits (src/mac/net_mac.c); the driver uses A5
| freely, and the Toolbox needs the program's A5 world, so the two thunks put it back.
| SPDX-License-Identifier: GPL-2.0-only
	.text
	.even
	.globl	rp_hook_call
rp_hook_call:				| ULONG rp_hook_call(struct Hook *h, Object *obj, Msg msg)
	movem.l	%d2-%d7/%a2-%a6,-(%sp)
	move.l	48(%sp),%a0
	move.l	52(%sp),%a2
	move.l	56(%sp),%a1
	move.l	8(%a0),%a3
	jsr	(%a3)
	movem.l	(%sp)+,%d2-%d7/%a2-%a6
	rts

	.globl	lm_yield_thunk
	.globl	lm_break_thunk
	.globl	lm_a5
lm_yield_thunk:
	move.l	%a5,-(%sp)
	move.l	lm_a5,%a5
	move.l	8(%sp),-(%sp)
	jsr	lm_yield
	addq.l	#4,%sp
	move.l	(%sp)+,%a5
	rts
lm_break_thunk:
	move.l	%a5,-(%sp)
	move.l	lm_a5,%a5
	move.l	8(%sp),-(%sp)
	jsr	lm_break
	addq.l	#4,%sp
	move.l	(%sp)+,%a5
	rts
	.data
	.align	2
lm_a5:
	.long	0
	.section .note.GNU-stack,"",@progbits
