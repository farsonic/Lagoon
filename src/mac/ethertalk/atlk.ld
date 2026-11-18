/* Lagoon EtherTalk - the 'atlk' image: linked at 0, atlk_glue.o first (its first two branches
 * are the resource's two entry points), the zeroed data inside the image; tools/mkadev.py
 * appends the relocation table the first call applies. SPDX-License-Identifier: GPL-2.0-only */
OUTPUT_FORMAT("elf32-m68k")
ENTRY(_start)
SECTIONS
{
	. = 0;
	.text : {
		KEEP(*atlk_glue.o(.text))
		*(.text .text.*)
		*(.rodata .rodata.*)
	}
	.data ALIGN(4) : { *(.data .data.*) *(.sdata .sdata.*) }
	.bss ALIGN(4) : { *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON) }
	_image_end = .;
	/DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame .eh_frame_hdr) *(.gnu.attributes) }
}
