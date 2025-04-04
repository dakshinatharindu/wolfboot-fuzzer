	.global _start
	.section .text.bios

_start:	lui t0, 0x20010
	jr t0
