include(`asm.m4')
	
	.file	"aes.asm"
	
	.section	".text"
	.align 4
	.global _aes_crypt
	.type	_aes_crypt,#function
	.proc	020

define(ctx, %o5)
define(T, %o0)
define(length, %o4)
define(dst, %o3)
define(src, %o2)

define(wtxt, %l2)
define(tmp, %o1)
_aes_crypt:
! Why -136?
	save	%sp, -136, %sp

! Why this moving around of the input parameters?
	mov	%i2, length
	mov	%i0, ctx
	mov	%i1, T
	mov	%i3, dst
	cmp	length, 0
	be	.Lend
	mov	%i4, src
	! wtxt
	add	%fp, -24, %l1
	mov	%l1, wtxt
.Lblock_loop:
	! Read src, and add initial subkey
	mov	0, %i3
.Lsource_loop:
	sll	%i3, 2, %i2
	add	%i2, src, %i0
	ldub	[%i0+3], %g2
	add	%i3, 1, %i3
	ldub	[%i0+2], %g3
	sll	%g2, 24, %g2
	ldub	[%i0+1], %i1
	sll	%g3, 16, %g3
	or	%g2, %g3, %g2
	ldub	[src+%i2], %i0
	sll	%i1, 8, %i1
	ld	[ctx+%i2], %g3
	or	%g2, %i1, %g2
	or	%g2, %i0, %g2
	xor	%g2, %g3, %g2
	cmp	%i3, 3
	bleu	.Lsource_loop
	st	%g2, [wtxt+%i2]

	ld	[ctx + AES_NROUNDS], %g2
	mov	1, %g1

	add	%fp, -40, tmp
	mov	%g2, %o7
	mov	tmp, %l0

	! wtxt
	mov	%l1, %g4

	! 4*i:	%i3
	mov	0, %i3
.Lround_loop:
	add	T, AES_SIDX3, %i4
.Linner_loop:
	! AES_IDX1
	ld	[%i4-32], %g3

	! AES_IDX2
	ld	[%i4-16], %i2
	! wtxt[IDX1...]
	add	%g4, %g3, %g3
	ldub	[%g3+2], %i1

	! AES_IDX3
	ld	[%i4], %g2
	sll	%i1, 2, %i1
	ld	[%g4+%i3], %i0

	lduh	[%g4+%i2], %g3
	and	%i0, 255, %i0
	ldub	[%g4+%g2], %i2
	sll	%i0, 2, %i0
	add	%i0, AES_TABLE0, %i0
	ld	[T+%i0], %g2

	add	%i1, AES_TABLE1, %i1
	and	%g3, 255, %g3
	ld	[T+%i1], %i0
	sll	%g3, 2, %g3
	add	%g3, AES_TABLE2, %g3
	ld	[T+%g3], %i1
	sll	%i2, 2, %i2
	add	%i2, AES_TABLE3, %i2
	ld	[T+%i2], %g3
	xor	%g2, %i0, %g2
	xor	%g2, %i1, %g2

	add	%i4, 4, %i4
	
	xor	%g2, %g3, %g2
	st	%g2, [%l0+%i3]

	cmp	%i3, 8

	bleu	.Linner_loop
	add	%i3, 4, %i3
	
	sll	%g1, 4, %g2
	add	%g2, ctx, %i1
	mov	0, %i5
	mov	%l1, %i3
	mov	tmp, %i2
.Lroundkey_loop:
	sll	%i5, 2, %g2
	ld	[%i1], %i0
	add	%i5, 1, %i5
	ld	[%i2+%g2], %g3
	cmp	%i5, 3
	xor	%g3, %i0, %g3
	st	%g3, [%i3+%g2]
	bleu	.Lroundkey_loop
	add	%i1, 4, %i1
	add	%g1, 1, %g1
	cmp	%g1, %o7
	blu	.Lround_loop
	mov	0, %i3

	sll	%g1, 4, %g2
	
	! final round
	add	%g2, ctx, %o7
	mov	0, %o1
	mov	%l1, %g1
	add	T, 288, %g4
.Lfinal_loop:
	ld	[%g4-32], %g2
	sll	%o1, 2, %i5
	sll	%g2, 2, %g2
	add	%g1, %g2, %g2
	ldub	[%g2+2], %i3
	add	%i5, dst, %i4
	ld	[%g4-16], %g3
	add	%o1, 1, %o1
	ld	[%g1+%i5], %g2
	sll	%g3, 2, %g3
	lduh	[%g1+%g3], %i2
	and	%g2, 255, %g2
	ld	[%g4], %i0
	and	%i2, 255, %i2
	ldub	[T+%i3], %i1
	sll	%i0, 2, %i0
	ldub	[T+%g2], %g3
	sll	%i1, 8, %i1
	ldub	[%g1+%i0], %i3
	or	%g3, %i1, %g3
	ldub	[T+%i2], %g2
	cmp	%o1, 3
	ldub	[T+%i3], %i0
	sll	%g2, 16, %g2
	or	%g3, %g2, %g3
	ld	[%o7], %g2
	sll	%i0, 24, %i0
	or	%g3, %i0, %g3
	xor	%g3, %g2, %g3
	srl	%g3, 24, %i0
	srl	%g3, 16, %i1
	srl	%g3, 8, %g2
	stb	%g2, [%i4+1]
	stb	%i0, [%i4+3]
	stb	%i1, [%i4+2]
	stb	%g3, [dst+%i5]
	add	%o7, 4, %o7
	bleu	.Lfinal_loop
	add	%g4, 4, %g4
	
	add	dst, 16, dst
	addcc	length, -16, length
	bne	.Lblock_loop
	add	src, 16, src
.Lend:
	ret
	restore
.LLFE1:
.LLfe1:
	.size	_aes_crypt,.LLfe1-_aes_crypt

	! Benchmarks on my slow sparcstation:	
	! Original C code	
	! aes128 (ECB encrypt): 14.36s, 0.696MB/s
	! aes128 (ECB decrypt): 17.19s, 0.582MB/s
	! aes128 (CBC encrypt): 16.08s, 0.622MB/s
	! aes128 ((CBC decrypt)): 18.79s, 0.532MB/s
	! 
	! aes192 (ECB encrypt): 16.85s, 0.593MB/s
	! aes192 (ECB decrypt): 19.64s, 0.509MB/s
	! aes192 (CBC encrypt): 18.43s, 0.543MB/s
	! aes192 (CBC decrypt): 20.76s, 0.482MB/s
	! 
	! aes256 (ECB encrypt): 19.12s, 0.523MB/s
	! aes256 (ECB decrypt): 22.57s, 0.443MB/s
	! aes256 (CBC encrypt): 20.92s, 0.478MB/s
	! aes256 (CBC decrypt): 23.22s, 0.431MB/s

	! After unrolling key_addition32, and getting rid of
	! some sll x, 2, x, encryption speed is 0.760 MB/s.

	! Next, the C code was optimized to use larger tables and
	! no rotates. New timings:
	! aes128 (ECB encrypt): 13.10s, 0.763MB/s
	! aes128 (ECB decrypt): 11.51s, 0.869MB/s
	! aes128 (CBC encrypt): 15.15s, 0.660MB/s
	! aes128 (CBC decrypt): 13.10s, 0.763MB/s
	! 
	! aes192 (ECB encrypt): 15.68s, 0.638MB/s
	! aes192 (ECB decrypt): 13.59s, 0.736MB/s
	! aes192 (CBC encrypt): 17.65s, 0.567MB/s
	! aes192 (CBC decrypt): 15.31s, 0.653MB/s
	! 
	! aes256 (ECB encrypt): 17.95s, 0.557MB/s
	! aes256 (ECB decrypt): 15.90s, 0.629MB/s
	! aes256 (CBC encrypt): 20.16s, 0.496MB/s
	! aes256 (CBC decrypt): 17.47s, 0.572MB/s

	! After optimization using pre-shifted indices
	! (AES_SIDX[1-3]): 
	! aes128 (ECB encrypt): 12.46s, 0.803MB/s
	! aes128 (ECB decrypt): 10.74s, 0.931MB/s
	! aes128 (CBC encrypt): 17.74s, 0.564MB/s
	! aes128 (CBC decrypt): 12.43s, 0.805MB/s
	! 
	! aes192 (ECB encrypt): 14.59s, 0.685MB/s
	! aes192 (ECB decrypt): 12.76s, 0.784MB/s
	! aes192 (CBC encrypt): 19.97s, 0.501MB/s
	! aes192 (CBC decrypt): 14.46s, 0.692MB/s
	! 
	! aes256 (ECB encrypt): 17.00s, 0.588MB/s
	! aes256 (ECB decrypt): 14.81s, 0.675MB/s
	! aes256 (CBC encrypt): 22.65s, 0.442MB/s
	! aes256 (CBC decrypt): 16.46s, 0.608MB/s
