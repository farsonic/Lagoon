| Lagoon EtherTalk - the 'adev' resource: what the Network control panel shows.
|
| Backstory. The Network control panel (System 7.1's, version 2.3.3) opens every file of type
| 'adev', loads its 'adev' resource into the application heap and calls its first byte, D0 being
| the call (the 1988 "EtherTalk and Alternate AppleTalk Connections Reference", chapter 3):
|   101 GetADEV    D1 = the parameter RAM long naming the connection in use, D2 = 0 the first
|                  time, then what we answered last. Back: D0.B -1 "here is one, and it is the
|                  one in use", 0 "here is one", 1 "no more"; D2 = our cookie for it; A0 -> the
|                  name to put under the icon.
|   102 SelectADEV D2 = the cookie of the icon chosen. Back: D1, whose high three bytes go into
|                  parameter RAM and to the 'atlk' at AInstall. The panel's code sends 103 when
|                  the chosen icon is the one already in use; it is answered the same way.
| One icon per Ethernet card (Slot Manager category catNetwork, type typeEtherNet), so a Mac with
| two cards, or Aurora68 with its wired and Wi-Fi units, shows two. The cookie and the parameter
| RAM bytes are the card's slot and sResource ID. The panel draws "Name (x)" as two lines, as it
| does Apple's own: "Name", then "Slot #x" ("Built-In" for 0, "Alternate" for A: its STR# -4048
| 14-16); "Lagoon EtherTalk" on one line is wider than an icon's label. So the labels read
| "Lagoon / Slot #9" and "Lagoon Wi-Fi / Slot #9", the slot as a hex digit, lower case so that
| slot $A does not read as "Alternate". The words are the product's, not translated.
| Only PC-relative addressing: the 'adev' is not relocated. Pascal rules: D3-D7/A2-A6 kept.
| SPDX-License-Identifier: GPL-2.0-only

	.equ	ET_RSRC_ID,	168	| ethertalk.h: the 'adev' and 'atlk' ID
	.equ	_SlotManager,	0xA06E
	.equ	sGetTypeSRsrc,	0x0C
	.equ	DRHW_WIFI,	0x5054	| Aurora68's Wi-Fi unit (its declaration ROM, tools/mac/mkdeclrom.py)

	.text
	.globl	_start
_start:
	cmp.w	#101,%d0
	beq.s	getadev
	cmp.w	#102,%d0
	beq.s	select
	cmp.w	#103,%d0
	beq.s	select
	moveq	#1,%d0			| not ours to answer
	rts

| SelectADEV: the card's slot and sResource ID become the high bytes of the parameter RAM long
select:
	move.l	%d2,%d1
	lsl.l	#8,%d1
	lsl.l	#8,%d1			| slot << 24 | id << 16
	move.b	#ET_RSRC_ID,%d1
	moveq	#0,%d0
	rts

| GetADEV: the next Ethernet card after the one named by D2 (slot << 8 | id; 0 = from the start)
getadev:
	link	%a6,#-56		| an SpBlock (Slots.h), cleared
	movem.l	%d3-%d4/%a2,-(%sp)
	move.l	%d1,%d4			| parameter RAM
	lea	-56(%a6),%a2
	moveq	#13,%d0
1:	clr.l	(%a2)+
	dbf	%d0,1b
	lea	-56(%a6),%a0
	move.w	#4,40(%a0)		| spCategory: catNetwork
	move.w	#1,42(%a0)		| spCType: typeEtherNet
	move.b	#3,48(%a0)		| spTBMask: any driver, any hardware
	move.l	#1,24(%a0)		| spParamData: disabled sResources too
	move.w	%d2,%d3
	lsr.w	#8,%d3
	move.b	%d3,49(%a0)		| spSlot: after this one
	move.b	%d2,50(%a0)		| spID
	moveq	#sGetTypeSRsrc,%d0
	.short	_SlotManager
	tst.w	%d0
	bne.s	none
	lea	-56(%a6),%a0
	moveq	#0,%d2
	move.b	49(%a0),%d2
	lsl.w	#8,%d2
	move.b	50(%a0),%d2		| the cookie
	cmp.w	#DRHW_WIFI,46(%a0)	| spDrvrHW
	bne.s	2f
	lea	name_wifi(%pc),%a1
	bra.s	3f
2:	lea	name_wired(%pc),%a1
3:	moveq	#0,%d0
	move.b	(%a1),%d0
	moveq	#0,%d3
	move.b	49(%a0),%d3		| the slot, as one hex digit before the closing parenthesis
	move.b	hexdigits(%pc,%d3.w),-1(%a1,%d0.w)
	moveq	#0,%d0			| one, not the one in use ...
	cmp.b	#ET_RSRC_ID,%d4
	bne.s	4f
	move.l	%d4,%d3
	swap	%d3			| the high word: slot, id
	cmp.w	%d2,%d3
	bne.s	4f
	moveq	#-1,%d0			| ... unless parameter RAM names it
4:	move.l	%a1,%a0
	bra.s	5f
none:	moveq	#1,%d0
5:	movem.l	(%sp)+,%d3-%d4/%a2
	unlk	%a6
	rts

hexdigits:
	.ascii	"0123456789abcdef"
name_wired:				| (the adev is in RAM: the slot digit is written in place)
	.byte	10
	.ascii	"Lagoon (9)"
name_wifi:
	.byte	16
	.ascii	"Lagoon Wi-Fi (9)"
	.even
