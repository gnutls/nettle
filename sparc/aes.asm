	! Benchmarks on my slow sparcstation:	
	! C code	
	! aes128 (ECB encrypt): 14.36s, 0.696MB/s
	! aes128 (ECB decrypt): 17.19s, 0.582MB/s
	! aes128 (CBC encrypt): 16.08s, 0.622MB/s
	! aes128 ((CBC decrypt)): 18.79s, 0.532MB/s
	! 
	! aes192 (ECB encrypt): 16.85s, 0.593MB/s
	! aes192 (ECB decrypt): 19.64s, 0.509MB/s
	! aes192 (CBC encrypt): 18.43s, 0.543MB/s
	! aes192 ((CBC decrypt)): 20.76s, 0.482MB/s
	! 
	! aes256 (ECB encrypt): 19.12s, 0.523MB/s
	! aes256 (ECB decrypt): 22.57s, 0.443MB/s
	! aes256 (CBC encrypt): 20.92s, 0.478MB/s
	! aes256 ((CBC decrypt)): 23.22s, 0.431MB/s

	.file	"aes.i"
	.section	".debug_abbrev"
.LLdebug_abbrev0:
	.section	".text"
.LLtext0:
	.section	".debug_info"
.LLdebug_info0:
	.section	".debug_line"
.LLdebug_line0:
	.section	".text"
	.align 4
	.type	key_addition_8to32,#function
	.proc	020
key_addition_8to32:
.LLFB1:
.LLM1:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
.LLM2:
.LLBB2:
	mov	0, %o5
.LL13:
.LLM3:
	mov	0, %o4
.LLM4:
	mov	0, %o3
.LL17:
.LLM5:
	ldub	[%o0], %g3
	sll	%o3, 3, %g2
	sll	%g3, %g2, %g3
.LLM6:
	add	%o3, 1, %o3
.LLM7:
	or	%o4, %g3, %o4
.LLM8:
	cmp	%o3, 3
.LLM9:
	bleu	.LL17
	add	%o0, 1, %o0
.LLM10:
	sll	%o5, 2, %g3
	ld	[%o1+%g3], %g2
.LLM11:
	add	%o5, 1, %o5
.LLM12:
	xor	%g2, %o4, %g2
.LLM13:
	cmp	%o5, 3
	bleu	.LL13
	st	%g2, [%o2+%g3]
.LLBE2:
	retl
	nop
.LLFE1:
.LLfe1:
	.size	key_addition_8to32,.LLfe1-key_addition_8to32
	.align 4
	.type	key_addition32,#function
	.proc	020
key_addition32:
.LLFB2:
.LLM14:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
.LLBB3:
	mov	%o0, %o4
.LLM15:
	mov	0, %o3
.LL26:
.LLM16:
	sll	%o3, 2, %g2
	ld	[%o1+%g2], %g3
.LLM17:
	add	%o3, 1, %o3
.LLM18:
	ld	[%o4+%g2], %o0
.LLM19:
	cmp	%o3, 3
.LLM20:
	xor	%g3, %o0, %g3
.LLM21:
	bleu	.LL26
	st	%g3, [%o2+%g2]
.LLBE3:
	retl
	nop
.LLFE2:
.LLfe2:
	.size	key_addition32,.LLfe2-key_addition32
	.align 4
	.type	key_addition32to8,#function
	.proc	020
key_addition32to8:
.LLFB3:
.LLM22:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
.LLBB4:
	mov	%o0, %o5
.LLM23:
	mov	0, %o4
.LLM24:
	sll	%o4, 2, %g2
.LL42:
	ld	[%o1+%g2], %o0
.LLM25:
	mov	0, %o3
.LLM26:
	ld	[%o5+%g2], %g3
	xor	%g3, %o0, %g3
.LL37:
.LLM27:
	sll	%o3, 3, %g2
	srl	%g3, %g2, %g2
	stb	%g2, [%o2]
.LLM28:
	add	%o3, 1, %o3
	cmp	%o3, 3
.LLM29:
	bleu	.LL37
	add	%o2, 1, %o2
.LLM30:
	add	%o4, 1, %o4
	cmp	%o4, 3
	bleu	.LL42
	sll	%o4, 2, %g2
.LLBE4:
	retl
	nop
.LLFE3:
.LLfe3:
	.size	key_addition32to8,.LLfe3-key_addition32to8
	.section	".rodata"
	.align 4
	.type	idx,#object
	.size	idx,64
idx:
	.long	0
	.long	1
	.long	2
	.long	3
	.long	1
	.long	2
	.long	3
	.long	0
	.long	2
	.long	3
	.long	0
	.long	1
	.long	3
	.long	0
	.long	1
	.long	2
	.align 8
.LLC0:
	.asciz	"!(length % 16)"
	.align 8
.LLC1:
	.asciz	"aes.c"
	.align 8
.LLC2:
	.asciz	"aes_encrypt"
	.section	".text"
	.align 4
	.global aes_encrypt
	.type	aes_encrypt,#function
	.proc	020
aes_encrypt:
.LLFB4:
.LLM31:
	!#PROLOGUE# 0
	save	%sp, -136, %sp
.LLCFI0:
	!#PROLOGUE# 1
.LLM32:
.LLBB5:
	andcc	%i1, 15, %g0
	bne	.LL76
	cmp	%i1, 0
.LLM33:
	be	.LL71
	sethi	%hi(idx), %i4
	add	%fp, -24, %l6
	add	%fp, -40, %l5
	or	%i4, %lo(idx), %i5
.LL49:
.LLM34:
	mov	%i3, %o0
	mov	%i0, %o1
	call	key_addition_8to32, 0
	mov	%l6, %o2
.LLM35:
	ld	[%i0+480], %o0
	mov	1, %l3
	cmp	%l3, %o0
	bgeu	.LL77
	sethi	%hi(64512), %o0
	sethi	%hi(_aes_dtbl), %o0
	or	%o0, %lo(_aes_dtbl), %l1
	mov	%l5, %l4
	mov	%l6, %l0
	or	%i4, %lo(idx), %l7
	add	%i0, 16, %l2
.LL53:
.LLM36:
	mov	0, %o7
	add	%l7, 48, %g3
.LL57:
.LLM37:
	ld	[%g3], %o0
	sll	%o7, 2, %g2
	ld	[%g3-16], %o1
	sll	%o0, 2, %o0
	ldub	[%l0+%o0], %o3
	sll	%o1, 2, %o1
	lduh	[%l0+%o1], %o4
	sll	%o3, 2, %o3
	ld	[%g3-32], %o0
	and	%o4, 255, %o4
	ld	[%l1+%o3], %o2
	sll	%o0, 2, %o0
	srl	%o2, 24, %o3
	sll	%o4, 2, %o4
	add	%l0, %o0, %o0
	ld	[%l1+%o4], %o1
	sll	%o2, 8, %o2
	ldub	[%o0+2], %o5
	or	%o2, %o3, %o2
	xor	%o1, %o2, %o1
	srl	%o1, 24, %o3
	sll	%o5, 2, %o5
	ld	[%l0+%g2], %o2
	sll	%o1, 8, %o1
	ld	[%l1+%o5], %o0
	or	%o1, %o3, %o1
	xor	%o0, %o1, %o0
	and	%o2, 255, %o2
	srl	%o0, 24, %o3
	sll	%o2, 2, %o2
	ld	[%l1+%o2], %o1
	sll	%o0, 8, %o0
	or	%o0, %o3, %o0
	xor	%o1, %o0, %o1
.LLM38:
	add	%o7, 1, %o7
.LLM39:
	st	%o1, [%l4+%g2]
.LLM40:
	cmp	%o7, 3
	bleu	.LL57
	add	%g3, 4, %g3
.LLM41:
	mov	%l2, %o1
	mov	%l5, %o0
	call	key_addition32, 0
	mov	%l6, %o2
.LLM42:
	ld	[%i0+480], %o0
	add	%l3, 1, %l3
	cmp	%l3, %o0
	blu	.LL53
	add	%l2, 16, %l2
.LLM43:
	sethi	%hi(64512), %o0
.LL77:
	or	%o0, 768, %l3
	mov	0, %o7
	mov	%l6, %g3
	sethi	%hi(16711680), %l2
	sethi	%hi(-16777216), %l1
	mov	%l5, %l0
	add	%i5, 48, %g2
.LL63:
.LLM44:
	ld	[%g2-32], %o0
.LLM45:
	sll	%o7, 2, %o5
.LLM46:
	ld	[%g2-16], %o2
.LLM47:
	sll	%o0, 2, %o0
	ld	[%g3+%o0], %o3
.LLM48:
	sll	%o2, 2, %o2
.LLM49:
	ld	[%g2], %o4
.LLM50:
	and	%o3, %l3, %o3
.LLM51:
	ld	[%g3+%o2], %o1
.LLM52:
	sll	%o4, 2, %o4
.LLM53:
	ld	[%g3+%o5], %o0
.LLM54:
	and	%o1, %l2, %o1
.LLM55:
	ld	[%g3+%o4], %o2
.LLM56:
	and	%o0, 255, %o0
.LLM57:
	or	%o0, %o3, %o0
.LLM58:
	or	%o0, %o1, %o0
.LLM59:
	and	%o2, %l1, %o2
	or	%o0, %o2, %o0
.LLM60:
	add	%o7, 1, %o7
.LLM61:
	st	%o0, [%l0+%o5]
.LLM62:
	cmp	%o7, 3
	bleu	.LL63
	add	%g2, 4, %g2
.LLM63:
	sethi	%hi(_aes_sbox), %o0
	or	%o0, %lo(_aes_sbox), %g3
	mov	0, %o7
	mov	%l5, %g2
.LL68:
.LLM64:
	sll	%o7, 2, %o5
	ld	[%g2+%o5], %o3
.LLM65:
	add	%o7, 1, %o7
.LLM66:
	srl	%o3, 8, %o0
	and	%o0, 255, %o0
	ldub	[%g3+%o0], %o4
	srl	%o3, 16, %o2
	and	%o3, 255, %o0
	ldub	[%g3+%o0], %o1
	and	%o2, 255, %o2
	ldub	[%g3+%o2], %o0
	srl	%o3, 24, %o3
	sll	%o4, 8, %o4
	ldub	[%g3+%o3], %o2
	or	%o1, %o4, %o1
	sll	%o0, 16, %o0
	or	%o1, %o0, %o1
	sll	%o2, 24, %o2
	or	%o1, %o2, %o1
.LLM67:
	cmp	%o7, 3
	bleu	.LL68
	st	%o1, [%g2+%o5]
.LLM68:
	ld	[%i0+480], %o1
	mov	%i2, %o2
	sll	%o1, 4, %o1
	add	%i0, %o1, %o1
	call	key_addition32to8, 0
	mov	%l5, %o0
.LLM69:
	add	%i3, 16, %i3
	addcc	%i1, -16, %i1
	bne	.LL49
	add	%i2, 16, %i2
	b,a	.LL71
.LL76:
	sethi	%hi(.LLC0), %o0
	sethi	%hi(.LLC1), %o1
	sethi	%hi(.LLC2), %o3
	or	%o0, %lo(.LLC0), %o0
	or	%o1, %lo(.LLC1), %o1
	or	%o3, %lo(.LLC2), %o3
	call	__assert_fail, 0
	mov	92, %o2
.LL71:
.LLBE5:
	ret
	restore
.LLFE4:
.LLfe4:
	.size	aes_encrypt,.LLfe4-aes_encrypt
	.section	".rodata"
	.align 4
	.type	iidx,#object
	.size	iidx,64
iidx:
	.long	0
	.long	1
	.long	2
	.long	3
	.long	3
	.long	0
	.long	1
	.long	2
	.long	2
	.long	3
	.long	0
	.long	1
	.long	1
	.long	2
	.long	3
	.long	0
	.align 8
.LLC3:
	.asciz	"aes_decrypt"
	.section	".text"
	.align 4
	.global aes_decrypt
	.type	aes_decrypt,#function
	.proc	020
aes_decrypt:
.LLFB5:
.LLM70:
	!#PROLOGUE# 0
	save	%sp, -136, %sp
.LLCFI1:
	!#PROLOGUE# 1
.LLM71:
.LLBB6:
	andcc	%i1, 15, %g0
	bne	.LL111
	cmp	%i1, 0
.LLM72:
	be	.LL106
	sethi	%hi(iidx), %i4
	add	%fp, -24, %l6
	add	%fp, -40, %l5
	add	%i0, 240, %i5
.LL84:
.LLM73:
	ld	[%i0+480], %o1
	mov	%i3, %o0
	sll	%o1, 4, %o1
	add	%i0, %o1, %o1
	add	%o1, 240, %o1
	call	key_addition_8to32, 0
	mov	%l6, %o2
.LLM74:
	ld	[%i0+480], %o0
	addcc	%o0, -1, %l2
	be	.LL107
	sll	%l2, 4, %o1
	add	%o1, %i0, %o1
	sethi	%hi(_aes_itbl), %o0
	or	%o0, %lo(_aes_itbl), %l1
	add	%o1, 240, %l3
	mov	%l5, %l4
	mov	%l6, %l0
	or	%i4, %lo(iidx), %l7
.LL88:
.LLM75:
	mov	0, %o7
	add	%l7, 48, %g3
.LL92:
.LLM76:
	ld	[%g3], %o0
	sll	%o7, 2, %g2
	ld	[%g3-16], %o1
	sll	%o0, 2, %o0
	ldub	[%l0+%o0], %o3
	sll	%o1, 2, %o1
	lduh	[%l0+%o1], %o4
	sll	%o3, 2, %o3
	ld	[%g3-32], %o0
	and	%o4, 255, %o4
	ld	[%l1+%o3], %o2
	sll	%o0, 2, %o0
	srl	%o2, 24, %o3
	sll	%o4, 2, %o4
	add	%l0, %o0, %o0
	ld	[%l1+%o4], %o1
	sll	%o2, 8, %o2
	ldub	[%o0+2], %o5
	or	%o2, %o3, %o2
	xor	%o1, %o2, %o1
	srl	%o1, 24, %o3
	sll	%o5, 2, %o5
	ld	[%l0+%g2], %o2
	sll	%o1, 8, %o1
	ld	[%l1+%o5], %o0
	or	%o1, %o3, %o1
	xor	%o0, %o1, %o0
	and	%o2, 255, %o2
	srl	%o0, 24, %o3
	sll	%o2, 2, %o2
	ld	[%l1+%o2], %o1
	sll	%o0, 8, %o0
	or	%o0, %o3, %o0
	xor	%o1, %o0, %o1
.LLM77:
	add	%o7, 1, %o7
.LLM78:
	st	%o1, [%l4+%g2]
.LLM79:
	cmp	%o7, 3
	bleu	.LL92
	add	%g3, 4, %g3
.LLM80:
	mov	%l3, %o1
	mov	%l5, %o0
	call	key_addition32, 0
	mov	%l6, %o2
.LLM81:
	addcc	%l2, -1, %l2
	bne	.LL88
	add	%l3, -16, %l3
.LL107:
.LLM82:
	sethi	%hi(64512), %o0
	or	%o0, 768, %l3
	sethi	%hi(iidx), %o0
	or	%o0, %lo(iidx), %o0
	mov	0, %o7
	mov	%l6, %g3
	sethi	%hi(16711680), %l2
	sethi	%hi(-16777216), %l1
	mov	%l5, %l0
	add	%o0, 48, %g2
.LL98:
.LLM83:
	ld	[%g2-32], %o0
.LLM84:
	sll	%o7, 2, %o5
.LLM85:
	ld	[%g2-16], %o2
.LLM86:
	sll	%o0, 2, %o0
	ld	[%g3+%o0], %o3
.LLM87:
	sll	%o2, 2, %o2
.LLM88:
	ld	[%g2], %o4
.LLM89:
	and	%o3, %l3, %o3
.LLM90:
	ld	[%g3+%o2], %o1
.LLM91:
	sll	%o4, 2, %o4
.LLM92:
	ld	[%g3+%o5], %o0
.LLM93:
	and	%o1, %l2, %o1
.LLM94:
	ld	[%g3+%o4], %o2
.LLM95:
	and	%o0, 255, %o0
.LLM96:
	or	%o0, %o3, %o0
.LLM97:
	or	%o0, %o1, %o0
.LLM98:
	and	%o2, %l1, %o2
	or	%o0, %o2, %o0
.LLM99:
	add	%o7, 1, %o7
.LLM100:
	st	%o0, [%l0+%o5]
.LLM101:
	cmp	%o7, 3
	bleu	.LL98
	add	%g2, 4, %g2
.LLM102:
	sethi	%hi(_aes_isbox), %o0
	or	%o0, %lo(_aes_isbox), %g3
	mov	0, %o7
	mov	%l5, %g2
.LL103:
.LLM103:
	sll	%o7, 2, %o5
	ld	[%g2+%o5], %o3
.LLM104:
	add	%o7, 1, %o7
.LLM105:
	srl	%o3, 8, %o0
	and	%o0, 255, %o0
	ldub	[%g3+%o0], %o4
	srl	%o3, 16, %o2
	and	%o3, 255, %o0
	ldub	[%g3+%o0], %o1
	and	%o2, 255, %o2
	ldub	[%g3+%o2], %o0
	srl	%o3, 24, %o3
	sll	%o4, 8, %o4
	ldub	[%g3+%o3], %o2
	or	%o1, %o4, %o1
	sll	%o0, 16, %o0
	or	%o1, %o0, %o1
	sll	%o2, 24, %o2
	or	%o1, %o2, %o1
.LLM106:
	cmp	%o7, 3
	bleu	.LL103
	st	%o1, [%g2+%o5]
.LLM107:
	mov	%i2, %o2
	mov	%l5, %o0
	call	key_addition32to8, 0
	mov	%i5, %o1
.LLM108:
	add	%i3, 16, %i3
	addcc	%i1, -16, %i1
	bne	.LL84
	add	%i2, 16, %i2
	b,a	.LL106
.LL111:
	sethi	%hi(.LLC0), %o0
	sethi	%hi(.LLC1), %o1
	sethi	%hi(.LLC3), %o3
	or	%o0, %lo(.LLC0), %o0
	or	%o1, %lo(.LLC1), %o1
	or	%o3, %lo(.LLC3), %o3
	call	__assert_fail, 0
	mov	142, %o2
.LL106:
.LLBE6:
	ret
	restore
.LLFE5:
.LLfe5:
	.size	aes_decrypt,.LLfe5-aes_decrypt
	.section	".debug_frame"
.LLframe0:
	.uaword	.LLECIE0-.LLSCIE0
.LLSCIE0:
	.uaword	0xffffffff
	.byte	0x1
	.asciz	""
	.byte	0x1
	.byte	0x7c
	.byte	0xf
	.byte	0xc
	.byte	0xe
	.byte	0x0
	.align 4
.LLECIE0:
.LLSFDE0:
	.uaword	.LLEFDE0-.LLASFDE0
.LLASFDE0:
	.uaword	.LLframe0
	.uaword	.LLFB1
	.uaword	.LLFE1-.LLFB1
	.align 4
.LLEFDE0:
.LLSFDE2:
	.uaword	.LLEFDE2-.LLASFDE2
.LLASFDE2:
	.uaword	.LLframe0
	.uaword	.LLFB2
	.uaword	.LLFE2-.LLFB2
	.align 4
.LLEFDE2:
.LLSFDE4:
	.uaword	.LLEFDE4-.LLASFDE4
.LLASFDE4:
	.uaword	.LLframe0
	.uaword	.LLFB3
	.uaword	.LLFE3-.LLFB3
	.align 4
.LLEFDE4:
.LLSFDE6:
	.uaword	.LLEFDE6-.LLASFDE6
.LLASFDE6:
	.uaword	.LLframe0
	.uaword	.LLFB4
	.uaword	.LLFE4-.LLFB4
	.byte	0x4
	.uaword	.LLCFI0-.LLFB4
	.byte	0xd
	.byte	0x1e
	.byte	0x2d
	.byte	0x9
	.byte	0xf
	.byte	0x1f
	.align 4
.LLEFDE6:
.LLSFDE8:
	.uaword	.LLEFDE8-.LLASFDE8
.LLASFDE8:
	.uaword	.LLframe0
	.uaword	.LLFB5
	.uaword	.LLFE5-.LLFB5
	.byte	0x4
	.uaword	.LLCFI1-.LLFB5
	.byte	0xd
	.byte	0x1e
	.byte	0x2d
	.byte	0x9
	.byte	0xf
	.byte	0x1f
	.align 4
.LLEFDE8:
	.section	".text"
.LLetext0:
	.section	".debug_line"
	.uaword	.LLELT0-.LLSLT0
.LLSLT0:
	.uahalf	0x2
	.uaword	.LLELTP0-.LLASLTP0
.LLASLTP0:
	.byte	0x4
	.byte	0x1
	.byte	0xf6
	.byte	0xf5
	.byte	0xa
	.byte	0x0
	.byte	0x1
	.byte	0x1
	.byte	0x1
	.byte	0x1
	.byte	0x0
	.byte	0x0
	.byte	0x0
	.byte	0x1
	.ascii	"/usr/include"
	.byte	0
	.ascii	"/usr/local/lib/gcc-lib/sparc-unknown-linux-gnu/3.0.3/include"
	.byte	0
	.byte	0x0
	.asciz	"aes.i"
	.byte	0x0
	.byte	0x0
	.byte	0x0
	.asciz	"inttypes.h"
	.byte	0x1
	.byte	0x0
	.byte	0x0
	.asciz	"aes.h"
	.byte	0x0
	.byte	0x0
	.byte	0x0
	.asciz	"aes.c"
	.byte	0x0
	.byte	0x0
	.byte	0x0
	.asciz	"stddef.h"
	.byte	0x2
	.byte	0x0
	.byte	0x0
	.asciz	"stdint.h"
	.byte	0x1
	.byte	0x0
	.byte	0x0
	.asciz	"aes-internal.h"
	.byte	0x0
	.byte	0x0
	.byte	0x0
	.byte	0x0
.LLELTP0:
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM1
	.byte	0x4
	.byte	0x4
	.byte	0x36
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM2
	.byte	0x1a
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM3
	.byte	0x17
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM4
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM5
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM6
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM7
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM8
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM9
	.byte	0x1
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM10
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM11
	.byte	0xe
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM12
	.byte	0x1a
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM13
	.byte	0xe
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM14
	.byte	0x20
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM15
	.byte	0x17
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM16
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM17
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM18
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM19
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM20
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM21
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM22
	.byte	0x1a
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM23
	.byte	0x1a
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM24
	.byte	0x17
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM25
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM26
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM27
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM28
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM29
	.byte	0x1
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM30
	.byte	0x10
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM31
	.byte	0x27
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM32
	.byte	0x19
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM33
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM34
	.byte	0x17
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM35
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM36
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM37
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM38
	.byte	0x12
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM39
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM40
	.byte	0x12
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM41
	.byte	0x1b
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM42
	.byte	0xb
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM43
	.byte	0x22
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM44
	.byte	0x17
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM45
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM46
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM47
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM48
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM49
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM50
	.byte	0x12
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM51
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM52
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM53
	.byte	0x11
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM54
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM55
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM56
	.byte	0x11
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM57
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM58
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM59
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM60
	.byte	0xf
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM61
	.byte	0x1a
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM62
	.byte	0xe
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM63
	.byte	0x1c
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM64
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM65
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM66
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM67
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM68
	.byte	0x17
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM69
	.byte	0x3
	.byte	0x63
	.byte	0x1
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM70
	.byte	0x3f
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM71
	.byte	0x19
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM72
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM73
	.byte	0x17
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM74
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM75
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM76
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM77
	.byte	0x12
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM78
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM79
	.byte	0x12
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM80
	.byte	0x1b
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM81
	.byte	0xb
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM82
	.byte	0x21
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM83
	.byte	0x17
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM84
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM85
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM86
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM87
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM88
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM89
	.byte	0x12
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM90
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM91
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM92
	.byte	0x11
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM93
	.byte	0x16
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM94
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM95
	.byte	0x11
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM96
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM97
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM98
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM99
	.byte	0xf
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM100
	.byte	0x1a
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM101
	.byte	0xe
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM102
	.byte	0x1c
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM103
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM104
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM105
	.byte	0x15
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM106
	.byte	0x13
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM107
	.byte	0x17
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLM108
	.byte	0x3
	.byte	0x64
	.byte	0x1
	.byte	0x0
	.byte	0x5
	.byte	0x2
	.uaword	.LLetext0
	.byte	0x0
	.byte	0x1
	.byte	0x1
.LLELT0:
	.section	".debug_info"
	.uaword	0x729
	.uahalf	0x2
	.uaword	.LLdebug_abbrev0
	.byte	0x4
	.byte	0x1
	.uaword	.LLdebug_line0
	.uaword	.LLetext0
	.uaword	.LLtext0
	.asciz	"aes.i"
	.asciz	"/home/nisse/hack/lsh/src/nettle"
	.asciz	"GNU C 3.0.3"
	.byte	0x1
	.byte	0x2
	.uaword	0x74
	.byte	0x10
	.byte	0x2
	.uahalf	0x11f
	.byte	0x3
	.asciz	"quot"
	.byte	0x2
	.uahalf	0x11d
	.uaword	0x74
	.byte	0x2
	.byte	0x23
	.byte	0x0
	.byte	0x3
	.asciz	"rem"
	.byte	0x2
	.uahalf	0x11e
	.uaword	0x74
	.byte	0x2
	.byte	0x23
	.byte	0x8
	.byte	0x0
	.byte	0x4
	.asciz	"long long int"
	.byte	0x8
	.byte	0x5
	.byte	0x5
	.uaword	0xca
	.asciz	"aes_ctx"
	.uahalf	0x1e4
	.byte	0x3
	.byte	0x29
	.byte	0x6
	.asciz	"keys"
	.byte	0x3
	.byte	0x2a
	.uaword	0xca
	.byte	0x2
	.byte	0x23
	.byte	0x0
	.byte	0x6
	.asciz	"ikeys"
	.byte	0x3
	.byte	0x2b
	.uaword	0xca
	.byte	0x3
	.byte	0x23
	.byte	0xf0,0x1
	.byte	0x6
	.asciz	"nrounds"
	.byte	0x3
	.byte	0x2c
	.uaword	0xf6
	.byte	0x3
	.byte	0x23
	.byte	0xe0,0x3
	.byte	0x0
	.byte	0x7
	.uaword	0xda
	.uaword	0xea
	.byte	0x8
	.uaword	0xda
	.byte	0x3b
	.byte	0x0
	.byte	0x4
	.asciz	"unsigned int"
	.byte	0x4
	.byte	0x7
	.byte	0x4
	.asciz	"uint32_t"
	.byte	0x4
	.byte	0x7
	.byte	0x4
	.asciz	"unsigned int"
	.byte	0x4
	.byte	0x7
	.byte	0x9
	.uaword	0x184
	.asciz	"key_addition_8to32"
	.byte	0x4
	.byte	0x23
	.byte	0x1
	.uaword	.LLFB1
	.uaword	.LLFE1
	.byte	0x1
	.byte	0x5e
	.byte	0xa
	.asciz	"txt"
	.byte	0x4
	.byte	0x22
	.uaword	0x184
	.byte	0x1
	.byte	0x58
	.byte	0xa
	.asciz	"keys"
	.byte	0x4
	.byte	0x22
	.uaword	0x19a
	.byte	0x1
	.byte	0x59
	.byte	0xa
	.asciz	"out"
	.byte	0x4
	.byte	0x22
	.uaword	0x1a5
	.byte	0x1
	.byte	0x5a
	.byte	0xb
	.asciz	"ptr"
	.byte	0x4
	.byte	0x24
	.uaword	0x184
	.byte	0x1
	.byte	0x58
	.byte	0xb
	.asciz	"i"
	.byte	0x4
	.byte	0x25
	.uaword	0xf6
	.byte	0x1
	.byte	0x5d
	.byte	0xb
	.asciz	"j"
	.byte	0x4
	.byte	0x25
	.uaword	0xf6
	.byte	0x1
	.byte	0x5b
	.byte	0xb
	.asciz	"val"
	.byte	0x4
	.byte	0x26
	.uaword	0xea
	.byte	0x1
	.byte	0x5c
	.byte	0x0
	.byte	0xc
	.byte	0x4
	.uaword	0x18a
	.byte	0xd
	.uaword	0x18f
	.byte	0x4
	.asciz	"uint8_t"
	.byte	0x1
	.byte	0x7
	.byte	0xc
	.byte	0x4
	.uaword	0x1a0
	.byte	0xd
	.uaword	0xea
	.byte	0xc
	.byte	0x4
	.uaword	0xea
	.byte	0x9
	.uaword	0x200
	.asciz	"key_addition32"
	.byte	0x4
	.byte	0x35
	.byte	0x1
	.uaword	.LLFB2
	.uaword	.LLFE2
	.byte	0x1
	.byte	0x5e
	.byte	0xa
	.asciz	"txt"
	.byte	0x4
	.byte	0x34
	.uaword	0x19a
	.byte	0x1
	.byte	0x5c
	.byte	0xa
	.asciz	"keys"
	.byte	0x4
	.byte	0x34
	.uaword	0x19a
	.byte	0x1
	.byte	0x59
	.byte	0xa
	.asciz	"out"
	.byte	0x4
	.byte	0x34
	.uaword	0x1a5
	.byte	0x1
	.byte	0x5a
	.byte	0xb
	.asciz	"i"
	.byte	0x4
	.byte	0x36
	.uaword	0xf6
	.byte	0x1
	.byte	0x5b
	.byte	0x0
	.byte	0x9
	.uaword	0x27d
	.asciz	"key_addition32to8"
	.byte	0x4
	.byte	0x3e
	.byte	0x1
	.uaword	.LLFB3
	.uaword	.LLFE3
	.byte	0x1
	.byte	0x5e
	.byte	0xa
	.asciz	"txt"
	.byte	0x4
	.byte	0x3d
	.uaword	0x19a
	.byte	0x1
	.byte	0x5d
	.byte	0xa
	.asciz	"keys"
	.byte	0x4
	.byte	0x3d
	.uaword	0x19a
	.byte	0x1
	.byte	0x59
	.byte	0xa
	.asciz	"out"
	.byte	0x4
	.byte	0x3d
	.uaword	0x27d
	.byte	0x1
	.byte	0x5a
	.byte	0xb
	.asciz	"ptr"
	.byte	0x4
	.byte	0x3f
	.uaword	0x27d
	.byte	0x1
	.byte	0x5a
	.byte	0xb
	.asciz	"i"
	.byte	0x4
	.byte	0x40
	.uaword	0xf6
	.byte	0x1
	.byte	0x5c
	.byte	0xb
	.asciz	"j"
	.byte	0x4
	.byte	0x40
	.uaword	0xf6
	.byte	0x1
	.byte	0x5b
	.byte	0xb
	.asciz	"val"
	.byte	0x4
	.byte	0x41
	.uaword	0xea
	.byte	0x1
	.byte	0x53
	.byte	0x0
	.byte	0xc
	.byte	0x4
	.uaword	0x18f
	.byte	0xe
	.uaword	0x316
	.byte	0x1
	.asciz	"aes_encrypt"
	.byte	0x4
	.byte	0x57
	.byte	0x1
	.uaword	.LLFB4
	.uaword	.LLFE4
	.byte	0x1
	.byte	0x6e
	.byte	0xa
	.asciz	"ctx"
	.byte	0x4
	.byte	0x54
	.uaword	0x316
	.byte	0x1
	.byte	0x68
	.byte	0xa
	.asciz	"length"
	.byte	0x4
	.byte	0x55
	.uaword	0xf6
	.byte	0x1
	.byte	0x69
	.byte	0xa
	.asciz	"dst"
	.byte	0x4
	.byte	0x55
	.uaword	0x27d
	.byte	0x1
	.byte	0x6a
	.byte	0xa
	.asciz	"src"
	.byte	0x4
	.byte	0x56
	.uaword	0x184
	.byte	0x1
	.byte	0x6b
	.byte	0xb
	.asciz	"r"
	.byte	0x4
	.byte	0x58
	.uaword	0xf6
	.byte	0x1
	.byte	0x63
	.byte	0xb
	.asciz	"j"
	.byte	0x4
	.byte	0x58
	.uaword	0xf6
	.byte	0x1
	.byte	0x5f
	.byte	0xb
	.asciz	"wtxt"
	.byte	0x4
	.byte	0x59
	.uaword	0x31c
	.byte	0x2
	.byte	0x91
	.byte	0x68
	.byte	0xb
	.asciz	"t"
	.byte	0x4
	.byte	0x59
	.uaword	0x31c
	.byte	0x2
	.byte	0x91
	.byte	0x58
	.byte	0xb
	.asciz	"e"
	.byte	0x4
	.byte	0x5a
	.uaword	0xea
	.byte	0x1
	.byte	0x58
	.byte	0x0
	.byte	0xc
	.byte	0x4
	.uaword	0x85
	.byte	0x7
	.uaword	0x32c
	.uaword	0xea
	.byte	0x8
	.uaword	0xda
	.byte	0x3
	.byte	0x0
	.byte	0xe
	.uaword	0x3bf
	.byte	0x1
	.asciz	"aes_decrypt"
	.byte	0x4
	.byte	0x89
	.byte	0x1
	.uaword	.LLFB5
	.uaword	.LLFE5
	.byte	0x1
	.byte	0x6e
	.byte	0xa
	.asciz	"ctx"
	.byte	0x4
	.byte	0x86
	.uaword	0x316
	.byte	0x1
	.byte	0x68
	.byte	0xa
	.asciz	"length"
	.byte	0x4
	.byte	0x87
	.uaword	0xf6
	.byte	0x1
	.byte	0x69
	.byte	0xa
	.asciz	"dst"
	.byte	0x4
	.byte	0x87
	.uaword	0x27d
	.byte	0x1
	.byte	0x6a
	.byte	0xa
	.asciz	"src"
	.byte	0x4
	.byte	0x88
	.uaword	0x184
	.byte	0x1
	.byte	0x6b
	.byte	0xb
	.asciz	"r"
	.byte	0x4
	.byte	0x8a
	.uaword	0xf6
	.byte	0x1
	.byte	0x62
	.byte	0xb
	.asciz	"j"
	.byte	0x4
	.byte	0x8a
	.uaword	0xf6
	.byte	0x1
	.byte	0x5f
	.byte	0xb
	.asciz	"wtxt"
	.byte	0x4
	.byte	0x8b
	.uaword	0x31c
	.byte	0x2
	.byte	0x91
	.byte	0x68
	.byte	0xb
	.asciz	"t"
	.byte	0x4
	.byte	0x8b
	.uaword	0x31c
	.byte	0x2
	.byte	0x91
	.byte	0x58
	.byte	0xb
	.asciz	"e"
	.byte	0x4
	.byte	0x8c
	.uaword	0xea
	.byte	0x1
	.byte	0x58
	.byte	0x0
	.byte	0xf
	.asciz	"wchar_t"
	.byte	0x5
	.uahalf	0x11f
	.uaword	0x3cf
	.byte	0x4
	.asciz	"int"
	.byte	0x4
	.byte	0x5
	.byte	0x10
	.asciz	"int8_t"
	.byte	0x6
	.byte	0x26
	.uaword	0x3e4
	.byte	0x4
	.asciz	"signed char"
	.byte	0x1
	.byte	0x6
	.byte	0x10
	.asciz	"int16_t"
	.byte	0x6
	.byte	0x27
	.uaword	0x402
	.byte	0x4
	.asciz	"short int"
	.byte	0x2
	.byte	0x5
	.byte	0x10
	.asciz	"int32_t"
	.byte	0x6
	.byte	0x28
	.uaword	0x3cf
	.byte	0x10
	.asciz	"int64_t"
	.byte	0x6
	.byte	0x2d
	.uaword	0x74
	.byte	0x10
	.asciz	"uint8_t"
	.byte	0x6
	.byte	0x32
	.uaword	0x43c
	.byte	0x4
	.asciz	"unsigned char"
	.byte	0x1
	.byte	0x8
	.byte	0x10
	.asciz	"uint16_t"
	.byte	0x6
	.byte	0x33
	.uaword	0x45d
	.byte	0x4
	.asciz	"short unsigned int"
	.byte	0x2
	.byte	0x7
	.byte	0x10
	.asciz	"uint32_t"
	.byte	0x6
	.byte	0x34
	.uaword	0xf6
	.byte	0x10
	.asciz	"uint64_t"
	.byte	0x6
	.byte	0x39
	.uaword	0x493
	.byte	0x4
	.asciz	"long long unsigned int"
	.byte	0x8
	.byte	0x7
	.byte	0x10
	.asciz	"int_least8_t"
	.byte	0x6
	.byte	0x40
	.uaword	0x3e4
	.byte	0x10
	.asciz	"int_least16_t"
	.byte	0x6
	.byte	0x41
	.uaword	0x402
	.byte	0x10
	.asciz	"int_least32_t"
	.byte	0x6
	.byte	0x42
	.uaword	0x3cf
	.byte	0x10
	.asciz	"int_least64_t"
	.byte	0x6
	.byte	0x47
	.uaword	0x74
	.byte	0x10
	.asciz	"uint_least8_t"
	.byte	0x6
	.byte	0x4b
	.uaword	0x43c
	.byte	0x10
	.asciz	"uint_least16_t"
	.byte	0x6
	.byte	0x4c
	.uaword	0x45d
	.byte	0x10
	.asciz	"uint_least32_t"
	.byte	0x6
	.byte	0x4d
	.uaword	0xf6
	.byte	0x10
	.asciz	"uint_least64_t"
	.byte	0x6
	.byte	0x52
	.uaword	0x493
	.byte	0x10
	.asciz	"int_fast8_t"
	.byte	0x6
	.byte	0x59
	.uaword	0x3e4
	.byte	0x10
	.asciz	"int_fast16_t"
	.byte	0x6
	.byte	0x5f
	.uaword	0x3cf
	.byte	0x10
	.asciz	"int_fast32_t"
	.byte	0x6
	.byte	0x60
	.uaword	0x3cf
	.byte	0x10
	.asciz	"int_fast64_t"
	.byte	0x6
	.byte	0x62
	.uaword	0x74
	.byte	0x10
	.asciz	"uint_fast8_t"
	.byte	0x6
	.byte	0x66
	.uaword	0x43c
	.byte	0x10
	.asciz	"uint_fast16_t"
	.byte	0x6
	.byte	0x6c
	.uaword	0xf6
	.byte	0x10
	.asciz	"uint_fast32_t"
	.byte	0x6
	.byte	0x6d
	.uaword	0xf6
	.byte	0x10
	.asciz	"uint_fast64_t"
	.byte	0x6
	.byte	0x6f
	.uaword	0x493
	.byte	0x10
	.asciz	"intptr_t"
	.byte	0x6
	.byte	0x7c
	.uaword	0x3cf
	.byte	0x10
	.asciz	"uintptr_t"
	.byte	0x6
	.byte	0x7f
	.uaword	0xf6
	.byte	0x10
	.asciz	"intmax_t"
	.byte	0x6
	.byte	0x89
	.uaword	0x74
	.byte	0x10
	.asciz	"uintmax_t"
	.byte	0x6
	.byte	0x8b
	.uaword	0x493
	.byte	0xf
	.asciz	"lldiv_t"
	.byte	0x2
	.uahalf	0x11f
	.uaword	0x4b
	.byte	0xf
	.asciz	"imaxdiv_t"
	.byte	0x2
	.uahalf	0x124
	.uaword	0x63b
	.byte	0x7
	.uaword	0x668
	.uaword	0x1a0
	.byte	0x11
	.byte	0x0
	.byte	0x12
	.asciz	"_aes_dtbl"
	.byte	0x7
	.byte	0x2e
	.uaword	0x67b
	.byte	0x1
	.byte	0x1
	.byte	0xd
	.uaword	0x65d
	.byte	0x7
	.uaword	0x68b
	.uaword	0x1a0
	.byte	0x11
	.byte	0x0
	.byte	0x12
	.asciz	"_aes_itbl"
	.byte	0x7
	.byte	0x2f
	.uaword	0x69e
	.byte	0x1
	.byte	0x1
	.byte	0xd
	.uaword	0x680
	.byte	0x7
	.uaword	0x6b3
	.uaword	0x18a
	.byte	0x8
	.uaword	0xda
	.byte	0xff
	.byte	0x0
	.byte	0x12
	.asciz	"_aes_sbox"
	.byte	0x7
	.byte	0x30
	.uaword	0x6c6
	.byte	0x1
	.byte	0x1
	.byte	0xd
	.uaword	0x6a3
	.byte	0x12
	.asciz	"_aes_isbox"
	.byte	0x7
	.byte	0x31
	.uaword	0x6df
	.byte	0x1
	.byte	0x1
	.byte	0xd
	.uaword	0x6c6
	.byte	0x7
	.uaword	0x6fa
	.uaword	0x6fa
	.byte	0x8
	.uaword	0xda
	.byte	0x3
	.byte	0x8
	.uaword	0xda
	.byte	0x3
	.byte	0x0
	.byte	0xd
	.uaword	0xf6
	.byte	0xb
	.asciz	"idx"
	.byte	0x4
	.byte	0x4d
	.uaword	0x710
	.byte	0x5
	.byte	0x3
	.uaword	idx
	.byte	0xd
	.uaword	0x6e4
	.byte	0xb
	.asciz	"iidx"
	.byte	0x4
	.byte	0x7f
	.uaword	0x727
	.byte	0x5
	.byte	0x3
	.uaword	iidx
	.byte	0xd
	.uaword	0x710
	.byte	0x0
	.section	".debug_abbrev"
	.byte	0x1
	.byte	0x11
	.byte	0x1
	.byte	0x10
	.byte	0x6
	.byte	0x12
	.byte	0x1
	.byte	0x11
	.byte	0x1
	.byte	0x3
	.byte	0x8
	.byte	0x1b
	.byte	0x8
	.byte	0x25
	.byte	0x8
	.byte	0x13
	.byte	0xb
	.byte	0x0
	.byte	0x0
	.byte	0x2
	.byte	0x13
	.byte	0x1
	.byte	0x1
	.byte	0x13
	.byte	0xb
	.byte	0xb
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0x5
	.byte	0x0
	.byte	0x0
	.byte	0x3
	.byte	0xd
	.byte	0x0
	.byte	0x3
	.byte	0x8
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0x5
	.byte	0x49
	.byte	0x13
	.byte	0x38
	.byte	0xa
	.byte	0x0
	.byte	0x0
	.byte	0x4
	.byte	0x24
	.byte	0x0
	.byte	0x3
	.byte	0x8
	.byte	0xb
	.byte	0xb
	.byte	0x3e
	.byte	0xb
	.byte	0x0
	.byte	0x0
	.byte	0x5
	.byte	0x13
	.byte	0x1
	.byte	0x1
	.byte	0x13
	.byte	0x3
	.byte	0x8
	.byte	0xb
	.byte	0x5
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x0
	.byte	0x0
	.byte	0x6
	.byte	0xd
	.byte	0x0
	.byte	0x3
	.byte	0x8
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x49
	.byte	0x13
	.byte	0x38
	.byte	0xa
	.byte	0x0
	.byte	0x0
	.byte	0x7
	.byte	0x1
	.byte	0x1
	.byte	0x1
	.byte	0x13
	.byte	0x49
	.byte	0x13
	.byte	0x0
	.byte	0x0
	.byte	0x8
	.byte	0x21
	.byte	0x0
	.byte	0x49
	.byte	0x13
	.byte	0x2f
	.byte	0xb
	.byte	0x0
	.byte	0x0
	.byte	0x9
	.byte	0x2e
	.byte	0x1
	.byte	0x1
	.byte	0x13
	.byte	0x3
	.byte	0x8
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x27
	.byte	0xc
	.byte	0x11
	.byte	0x1
	.byte	0x12
	.byte	0x1
	.byte	0x40
	.byte	0xa
	.byte	0x0
	.byte	0x0
	.byte	0xa
	.byte	0x5
	.byte	0x0
	.byte	0x3
	.byte	0x8
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x49
	.byte	0x13
	.byte	0x2
	.byte	0xa
	.byte	0x0
	.byte	0x0
	.byte	0xb
	.byte	0x34
	.byte	0x0
	.byte	0x3
	.byte	0x8
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x49
	.byte	0x13
	.byte	0x2
	.byte	0xa
	.byte	0x0
	.byte	0x0
	.byte	0xc
	.byte	0xf
	.byte	0x0
	.byte	0xb
	.byte	0xb
	.byte	0x49
	.byte	0x13
	.byte	0x0
	.byte	0x0
	.byte	0xd
	.byte	0x26
	.byte	0x0
	.byte	0x49
	.byte	0x13
	.byte	0x0
	.byte	0x0
	.byte	0xe
	.byte	0x2e
	.byte	0x1
	.byte	0x1
	.byte	0x13
	.byte	0x3f
	.byte	0xc
	.byte	0x3
	.byte	0x8
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x27
	.byte	0xc
	.byte	0x11
	.byte	0x1
	.byte	0x12
	.byte	0x1
	.byte	0x40
	.byte	0xa
	.byte	0x0
	.byte	0x0
	.byte	0xf
	.byte	0x16
	.byte	0x0
	.byte	0x3
	.byte	0x8
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0x5
	.byte	0x49
	.byte	0x13
	.byte	0x0
	.byte	0x0
	.byte	0x10
	.byte	0x16
	.byte	0x0
	.byte	0x3
	.byte	0x8
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x49
	.byte	0x13
	.byte	0x0
	.byte	0x0
	.byte	0x11
	.byte	0x21
	.byte	0x0
	.byte	0x0
	.byte	0x0
	.byte	0x12
	.byte	0x34
	.byte	0x0
	.byte	0x3
	.byte	0x8
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x49
	.byte	0x13
	.byte	0x3f
	.byte	0xc
	.byte	0x3c
	.byte	0xc
	.byte	0x0
	.byte	0x0
	.byte	0x0
	.section	".debug_pubnames"
	.uaword	0x2e
	.uahalf	0x2
	.uaword	.LLdebug_info0
	.uaword	0x72d
	.uaword	0x283
	.asciz	"aes_encrypt"
	.uaword	0x32c
	.asciz	"aes_decrypt"
	.uaword	0x0
	.section	".debug_aranges"
	.uaword	0x1c
	.uahalf	0x2
	.uaword	.LLdebug_info0
	.byte	0x4
	.byte	0x0
	.uahalf	0x0
	.uahalf	0x0
	.uaword	.LLtext0
	.uaword	.LLetext0-.LLtext0
	.uaword	0x0
	.uaword	0x0
	.section	".data"
	.ident	"GCC: (GNU) 3.0.3"
