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

	.file	"aes.asm"
	.section	".text"
	.align 4
	.type	key_addition_8to32,#function
	.proc	020
! /* Key addition that also packs every byte in the key to a word rep. */
! static void
! key_addition_8to32(const uint8_t *txt, const uint32_t *keys, uint32_t *out)
key_addition_8to32:
	! %o0:	txt
	! %o1:	keys
	! %o2:	out
	! i:	%o5
	mov	0, %o5
.Liloop: 
	! val:	%o4
	mov	0, %o4
	! j:	%o3
	mov	0, %o3
.Lshiftloop:
	ldub	[%o0], %g3
	! %g2 = j << 3
	sll	%o3, 3, %g2
	! %g3 << 0
	sll	%g3, %g2, %g3
	add	%o3, 1, %o3
	or	%o4, %g3, %o4
	cmp	%o3, 3
	bleu	.Lshiftloop
	add	%o0, 1, %o0
	! val in %o4 now

	! out[i] = keys[i] ^ val;  i++
	sll	%o5, 2, %g3
	ld	[%o1+%g3], %g2
	add	%o5, 1, %o5
	xor	%g2, %o4, %g2
	cmp	%o5, 3
	bleu	.Liloop
	st	%g2, [%o2+%g3]

	retl
	nop

! key_addition32(const uint32_t *txt, const uint32_t *keys, uint32_t *out)

	.size	key_addition_8to32,.LLfe1-key_addition_8to32
	.align 4
	.type	key_addition32,#function
	.proc	020
key_addition32:
	! Unrolled version
	ld	[%o0], %g2
	ld	[%o1], %g3
	xor	%g2, %g3, %g3
	st	%g3, [%o2]

	ld	[%o0+4], %g2
	ld	[%o1+4], %g3
	xor	%g2, %g3, %g3
	st	%g3, [%o2+4]

	ld	[%o0+8], %g2
	ld	[%o1+8], %g3
	xor	%g2, %g3, %g3
	st	%g3, [%o2+8]

	ld	[%o0+12], %g2
	ld	[%o1+12], %g3
	xor	%g2, %g3, %g3
	retl
	st	%g3, [%o2+12]


.LLfe2:
	.size	key_addition32,.LLfe2-key_addition32
	.align 4
	.type	key_addition32to8,#function
	.proc	020
key_addition32to8:
	mov	%o0, %o5
	mov	0, %o4
	sll	%o4, 2, %g2
.LL42:
	ld	[%o1+%g2], %o0
	mov	0, %o3
	ld	[%o5+%g2], %g3
	xor	%g3, %o0, %g3
	! FIXME:	Unroll inner loop
.LL37:
	sll	%o3, 3, %g2
	srl	%g3, %g2, %g2
	stb	%g2, [%o2]

	add	%o3, 1, %o3
	cmp	%o3, 3

	bleu	.LL37
	add	%o2, 1, %o2

	add	%o4, 1, %o4
	cmp	%o4, 3
	bleu	.LL42
	sll	%o4, 2, %g2

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
	.asciz	"aes.asm"
	.align 8
.LLC2:
	.asciz	"aes_encrypt"
	.section	".text"
	.align 4
	.global aes_encrypt
	.type	aes_encrypt,#function
	.proc	020

! input parameters
define(ctx,	%i0)
define(length,	%i1)
define(dst,	%i2)
define(src,	%i3)

! locals
define(g_idx, %i5)
	
define(dtbl,	%l1)
define(round,	%l3)
define(txt,	%l5)
define(wtxt,	%l6)

aes_encrypt:
	save	%sp, -136, %sp

	andcc	length, 15, %g0
	bne	.Lencrypt_fail
	cmp	length, 0
	be	.Lencrypt_end
	sethi	%hi(idx), %i4
	add	%fp, -24, wtxt
	add	%fp, -40, txt
	or	%i4, %lo(idx), g_idx
.Lencrypt_block:
	! key_addition_8to32(src, ctx->keys, wtxt);
	mov	src, %o0
	mov	ctx, %o1
	call	key_addition_8to32, 0
	mov	wtxt, %o2

	! get nrounds
	ld	[ctx+480], %o0
	mov	1, round
	cmp	round, %o0
	bgeu	.Lencrypt_final
	sethi	%hi(64512), %o0

	sethi	%hi(_aes_dtbl), %o0
	or	%o0, %lo(_aes_dtbl), dtbl

	mov	txt, %l4
	mov	wtxt, %l0
	! FIXME:	%l7 = idx, seems redundant? 
	! or	%i4, %lo(idx), %l7
	add	ctx, 16, %l2
.Lencrypt_round:
	! j:	%o7
	! 4j:	%g2
	mov	0, %o7
	! %g3 = &idx[3][0]
	add	g_idx, 48, %g3
.Lencrypt_inner:
	! %o0 = idx[3][0]
	ld	[%g3], %o0
	! %g2 = 4j
	sll	%o7, 2, %g2
	! %o1 = idx[2][0]
	ld	[%g3-16], %o1
	! %o2 = 4 idx[3][0]
	sll	%o0, 2, %o0
	! %o3 = wtxt[idx[3][0]], byte => bits 24-31
	ldub	[%l0+%o0], %o3
	sll	%o1, 2, %o1
	! %o4 = wtxt[idx[2][0]], half-word???
	lduh	[%l0+%o1], %o4
	sll	%o3, 2, %o3
	! %o0 = idx[1][0]
	ld	[%g3-32], %o0
	! %o4 = (wtxt[idx[2][0]] >> 16) & 0xff => bits 16-23
	and	%o4, 255, %o4
	! %o2 = dtbl[wtxt[idx[3][0]] >> 24]
	ld	[dtbl+%o3], %o2
	! %o0 = 4 idx[1][0]
	sll	%o0, 2, %o0
	! %o3 = dtbl[wtxt[idx[3][0]] >> 24] >> 24
	srl	%o2, 24, %o3
	! %o4 = 4 ((wtxt[idx[2][0]] >> 16) & 0xff)
	sll	%o4, 2, %o4
	! %o0 = &wtxt[idx[1][0]]
	add	%l0, %o0, %o0
	! %o1 = dtbl[(wtxt[idx[2][0]] >> 16) & 0xff]
	ld	[dtbl+%o4], %o1
	! %o2 = dtbl[wtxt[idx[3][0]] >> 24] << 8
	sll	%o2, 8, %o2
	! %o5 = (wtxt[idx[1][0]] >> 8) & 0xff
	ldub	[%o0+2], %o5
	! %o2 = ROL(dtbl[wtxt[idx[3][0]] >> 24])
	or	%o2, %o3, %o2
	! %o1 = dtbl[(wtxt[idx[2][0]] >> 16) & 0xff] 
	!       ^ ROL(dtbl[wtxt[idx[3][0]] >> 24])  = XX1
	xor	%o1, %o2, %o1
	! %o3 = XX1 >> 24
	srl	%o1, 24, %o3
	! %o5 = 4 ((wtxt[idx[1][0]] >> 8) & 0xff)
	sll	%o5, 2, %o5
	! %o2 = wtxt[j]
	ld	[%l0+%g2], %o2
	! %o1 = XX1 << 8
	sll	%o1, 8, %o1
	! %o0 = dtbl[(wtxt[idx[1][0]] >> 8) & 0xff]
	ld	[dtbl+%o5], %o0
	! %o1 = ROL(XX1)
	or	%o1, %o3, %o1
	! %o0 = dtbl[(wtxt[idx[1][0]] >> 8) & 0xff] ^ ROL(XX1) = XX2
	xor	%o0, %o1, %o0
	! %o2 = wtxt[j] & 0xff
	and	%o2, 255, %o2
	! %03 = XX2 >> 24
	srl	%o0, 24, %o3
	! %o2 = 4 (wtxt[j] & 0xff)
	sll	%o2, 2, %o2
	! %o1 = dtbl[wtxt[j] & 0xff]
	ld	[dtbl+%o2], %o1
	! %o0 = XX2 << 8
	sll	%o0, 8, %o0
	! %o0 = ROL(XX2)
	or	%o0, %o3, %o0
	! %o1 = dtbl[wtxt[j] & 0xff] ^ ROL(XX2 = XX3
	xor	%o1, %o0, %o1
	! j++
	add	%o7, 1, %o7
	! txt[j] (old j) = XX3 
	st	%o1, [%l4+%g2]
	! j <= 3?
	cmp	%o7, 3
	bleu	.Lencrypt_inner
	! %g3 = &idx[3][j]
	add	%g3, 4, %g3

	! key_addition32(txt, ctx + 16, wtxt)
	mov	%l2, %o1
	mov	txt, %o0
	call	key_addition32, 0
	mov	wtxt, %o2

	! %o0 = nrounds
	! FIXME:	Keep in some register?
	ld	[ctx+480], %o0
	add	round, 1, round
	cmp	round, %o0
	! round < nrounds?
	blu	.Lencrypt_round
	! %l2 = ctx->keys + r*4 
	add	%l2, 16, %l2
	
	sethi	%hi(64512), %o0
.Lencrypt_final:
	! %l3 = 0xff00 ???
	or	%o0, 768, %l3
	! %o7 = j = 0
	mov	0, %o7
	! %g3 = wtxt
	mov	wtxt, %g3
	! %l2 = 0xff0000
	sethi	%hi(16711680), %l2
	! %l1 = 0xff000000
	sethi	%hi(-16777216), %l1
	! %l0 = txt 
	mov	txt, %l0
	! %g2 = &idx[3][0]
	add	g_idx, 48, %g2
.LL63:
	! %o0 = idx[1][0]
	ld	[%g2-32], %o0
	! %o5 = 4 j
	sll	%o7, 2, %o5
	! %o2 = idx[2][0]
	ld	[%g2-16], %o2
	! %o0 = 4(idx[1][0])
	sll	%o0, 2, %o0
	! %o3 = wtxt[idx[1][0]]
	ld	[%g3+%o0], %o3
	! %o2 = 4 idx[2][0]
	sll	%o2, 2, %o2
	! %o4 = idx[3][0]
	ld	[%g2], %o4
	! %o3 = wtxt[idx[1][0]] & 0xff00 
	and	%o3, %l3, %o3
	! %o1 = wtxt[idx[2][0]]
	ld	[%g3+%o2], %o1
	! %o4 = 4 idx[3][0]
	sll	%o4, 2, %o4
	! %o0 = wtxt[idx[1][0]]
	ld	[%g3+%o5], %o0
	! %o1 = wtxt[idx[2][0]] & 0xff0000
	and	%o1, %l2, %o1
	! %o2 = wtxt[idx[3][0]]
	ld	[%g3+%o4], %o2
	! %o0 = wtxt[idx[1][0]] & 0xff
	and	%o0, 255, %o0

	! % o0 = wtxt[idx[1][0]] & 0xff
	!        | wtxt[idx[1][0]] & 0xff00
	!        | wtxt[idx[2][0]] & 0xff0000
	or	%o0, %o3, %o0
	or	%o0, %o1, %o0
	! %o2 = wtxt[idx[3][0]] & 0xff000000
	and	%o2, %l1, %o2
	or	%o0, %o2, %o0
	! j++
	add	%o7, 1, %o7
	! txt[j] = ... | ... | ... | ... (old j)
	st	%o0, [%l0+%o5]
	! j <= 3?
	cmp	%o7, 3
	bleu	.LL63
	! %g2 = &idx[3][j]
	add	%g2, 4, %g2
	
	sethi	%hi(_aes_sbox), %o0
	or	%o0, %lo(_aes_sbox), %g3
	
	! %o7 = j = 0
	mov	0, %o7
	! %g2 = txt
	mov	%l5, %g2
.Lencrypt_sbox:
	! %o5 = 4 j
	sll	%o7, 2, %o5
	! %o3 = txt[j]
	ld	[%g2+%o5], %o3
	! j++
	add	%o7, 1, %o7
	! %o0 = (txt[j] >> 8) & 0xff (old j) 
	srl	%o3, 8, %o0
	and	%o0, 255, %o0
	! %o4 = sbox[(txt[j] >> 8) & 0xff]
	ldub	[%g3+%o0], %o4
	! %o2 = (txt[j] >> 16) (old j)
	srl	%o3, 16, %o2
	! %o0 = txt[j] & 0xff
	and	%o3, 255, %o0
	! %o1 = sbox[txt[j] & 0xff]
	ldub	[%g3+%o0], %o1
	! %o2 = (txt[j] >> 16) & 0xff (old j)
	and	%o2, 255, %o2
	! %o0 = sbox[(txt[j] >> 16) & 0xff]
	ldub	[%g3+%o2], %o0
	! %o3 = txt[j] >> 24
	srl	%o3, 24, %o3
	! %o4 = sbox[txt[j] & 0xff] << 8
	sll	%o4, 8, %o4
	! %o2 = sbox[txt[j] >> 24]
	ldub	[%g3+%o3], %o2
	! %o1 = sbox[txt[j] & 0xff] 
	!	| sbox[(txt[j] >> 8) & 0xff] << 8
	or	%o1, %o4, %o1
	!	| sbox[(txt[j] >> 16) & 0xff] << 16
	sll	%o0, 16, %o0
	or	%o1, %o0, %o1
	!	| sbox[txt[j] >> 24] << 24
	sll	%o2, 24, %o2
	or	%o1, %o2, %o1
	! j < 3 
	cmp	%o7, 3
	bleu	.Lencrypt_sbox
	! txt[j] = ... | ... | ... | ...
	st	%o1, [%g2+%o5]

	! key_addition32to8(txt, ctx + nrounds * 4, dst,
	ld	[ctx+480], %o1
	mov	dst, %o2
	sll	%o1, 4, %o1
	add	ctx, %o1, %o1
	call	key_addition32to8, 0
	mov	%l5, %o0

	add	src, 16, src
	addcc	length, -16, length
	bne	.Lencrypt_block
	add	dst, 16, dst
	b,a	.Lencrypt_end
.Lencrypt_fail:
	sethi	%hi(.LLC0), %o0
	sethi	%hi(.LLC1), %o1
	sethi	%hi(.LLC2), %o3
	or	%o0, %lo(.LLC0), %o0
	or	%o1, %lo(.LLC1), %o1
	or	%o3, %lo(.LLC2), %o3
	call	__assert_fail, 0
	mov	92, %o2
.Lencrypt_end:
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
	!#PROLOGUE# 0
	save	%sp, -136, %sp
.LLCFI1:
	!#PROLOGUE# 1
.LLBB6:
	andcc	%i1, 15, %g0
	bne	.LL111
	cmp	%i1, 0
	be	.LL106
	sethi	%hi(iidx), %i4
	add	%fp, -24, %l6
	add	%fp, -40, %l5
	add	%i0, 240, %i5
.LL84:
	ld	[%i0+480], %o1
	mov	%i3, %o0
	sll	%o1, 4, %o1
	add	%i0, %o1, %o1
	add	%o1, 240, %o1
	call	key_addition_8to32, 0
	mov	%l6, %o2
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
	mov	0, %o7
	add	%l7, 48, %g3
.LL92:
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
	add	%o7, 1, %o7
	st	%o1, [%l4+%g2]
	cmp	%o7, 3
	bleu	.LL92
	add	%g3, 4, %g3
	mov	%l3, %o1
	mov	%l5, %o0
	call	key_addition32, 0
	mov	%l6, %o2
	addcc	%l2, -1, %l2
	bne	.LL88
	add	%l3, -16, %l3
.LL107:
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
	ld	[%g2-32], %o0
	sll	%o7, 2, %o5
	ld	[%g2-16], %o2
	sll	%o0, 2, %o0
	ld	[%g3+%o0], %o3
	sll	%o2, 2, %o2
	ld	[%g2], %o4
	and	%o3, %l3, %o3
	ld	[%g3+%o2], %o1
	sll	%o4, 2, %o4
	ld	[%g3+%o5], %o0
	and	%o1, %l2, %o1
	ld	[%g3+%o4], %o2
	and	%o0, 255, %o0
	or	%o0, %o3, %o0
	or	%o0, %o1, %o0
	and	%o2, %l1, %o2
	or	%o0, %o2, %o0
	add	%o7, 1, %o7
	st	%o0, [%l0+%o5]
	cmp	%o7, 3
	bleu	.LL98
	add	%g2, 4, %g2
	sethi	%hi(_aes_isbox), %o0
	or	%o0, %lo(_aes_isbox), %g3
	mov	0, %o7
	mov	%l5, %g2
.LL103:
	sll	%o7, 2, %o5
	ld	[%g2+%o5], %o3
	add	%o7, 1, %o7
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
	cmp	%o7, 3
	bleu	.LL103
	st	%o1, [%g2+%o5]
	mov	%i2, %o2
	mov	%l5, %o0
	call	key_addition32to8, 0
	mov	%i5, %o1
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
