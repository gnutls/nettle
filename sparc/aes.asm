	! Used registers:	%l0,1,2
	!			%i0,1,2,3,4,5 (%i6=%fp, %i7 = return)
	!			%o0,1,2,3,4,7 (%o6=%sp)
	!			%g1,2,3,4
include(`asm.m4')
	
	.file	"aes.asm"
	
	.section	".text"
	.align 4
	.global _aes_crypt
	.type	_aes_crypt,#function
	.proc	020

define(ctx, %i0)
define(T, %i1)
define(length, %i2)
define(dst, %i3)
define(src, %i4)

define(wtxt, %l2)
define(tmp, %o1)
_aes_crypt:
! Why -136?
	save	%sp, -136, %sp

! Why this moving around of the input parameters?
	cmp	length, 0
	be	.Lend

	! wtxt
	add	%fp, -24, %l1
	mov	%l1, wtxt
.Lblock_loop:
	! Read src, and add initial subkey
	mov	-4, %o4
.Lsource_loop:
	add	%o4, 4, %o4
		
	add	%o4, src, %o5
	ldub	[%o5+3], %g2

	ldub	[%o5+2], %g3
	sll	%g2, 24, %g2
	ldub	[%o5+1], %o0
	sll	%g3, 16, %g3
	or	%g2, %g3, %g2
	ldub	[src+%o4], %o5
	sll	%o0, 8, %o0
	ld	[ctx+%o4], %g3
	or	%g2, %o0, %g2
	or	%g2, %o5, %g2
	xor	%g2, %g3, %g2

	cmp	%o4, 12
	bleu	.Lsource_loop
	st	%g2, [wtxt+%o4]

	! ! Read a little-endian word
	! ldub	[src+3], %g2
	! sll	%g2, 8, %g2
	! 
	! ldub	[src+2], %g3
	! or	%g3, %g2, %g2
	! sll	%g2, 8, %g2
	! 
	! ldub	[src+1], %g3
	! or	%g3, %g2, %g2
	! sll	%g2, 8, %g2
	! 
	! ldub	[src+0], %g3
	! or	%g3, %g2, %g2
	! sll	%g2, 8, %g2
	! 
	! ld	[ctx+%o3], %g3
	! xor	%g3, %g2, %g2
	! 
	! add	src, 4, src
	! st	%g2, [wtxt+%o4]
	! 
	! cmp	%o3, 8
	! bleu	.Lsource_loop
	! add	%o3, 4, %o3

	ld	[ctx + AES_NROUNDS], %g2
	mov	1, %g1

	add	%fp, -40, tmp
	mov	%g2, %o7
	mov	tmp, %l0

	! wtxt
	mov	%l1, %g4

	! 4*i:	%o3
	mov	0, %o3
.Lround_loop:
	add	T, AES_SIDX3, %o2
.Linner_loop:
	! AES_SIDX1
	ld	[%o2-32], %g3

	! AES_SIDX2
	ld	[%o2-16], %o4
	! wtxt[IDX1...]
	add	%g4, %g3, %g3
	ldub	[%g3+2], %o0

	! AES_SIDX3
	ld	[%o2], %g2
	sll	%o0, 2, %o0
	
	! wtxt[j]
	ld	[%g4+%o3], %o5
	
	! wtxt[IDX2...]
	lduh	[%g4+%o4], %g3
	
	and	%o5, 255, %o5

	! wtxt[IDX3...]
	ldub	[%g4+%g2], %o4
	
	sll	%o5, 2, %o5
	add	%o5, AES_TABLE0, %o5
	ld	[T+%o5], %g2

	add	%o0, AES_TABLE1, %o0
	and	%g3, 255, %g3
	ld	[T+%o0], %o5
	sll	%g3, 2, %g3
	add	%g3, AES_TABLE2, %g3
	ld	[T+%g3], %o0
	sll	%o4, 2, %o4
	add	%o4, AES_TABLE3, %o4
	ld	[T+%o4], %g3
	xor	%g2, %o5, %g2
	xor	%g2, %o0, %g2

	add	%o2, 4, %o2
	
	xor	%g2, %g3, %g2
	st	%g2, [%l0+%o3]

	cmp	%o3, 8

	bleu	.Linner_loop
	add	%o3, 4, %o3
	
	sll	%g1, 4, %g2
	add	%g2, ctx, %o0
	mov	0, %i5
	mov	%l1, %o3
	mov	tmp, %o4
.Lroundkey_loop:
	sll	%i5, 2, %g2
	ld	[%o0], %o5
	add	%i5, 1, %i5
	ld	[%o4+%g2], %g3
	cmp	%i5, 3
	xor	%g3, %o5, %g3
	st	%g3, [%o3+%g2]
	bleu	.Lroundkey_loop
	add	%o0, 4, %o0
	add	%g1, 1, %g1
	cmp	%g1, %o7
	blu	.Lround_loop
	mov	0, %o3

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
	ldub	[%g2+2], %o3
	add	%i5, dst, %o2
	ld	[%g4-16], %g3
	add	%o1, 1, %o1
	ld	[%g1+%i5], %g2
	sll	%g3, 2, %g3
	lduh	[%g1+%g3], %o4
	and	%g2, 255, %g2
	ld	[%g4], %o5
	and	%o4, 255, %o4
	ldub	[T+%o3], %o0
	sll	%o5, 2, %o5
	ldub	[T+%g2], %g3
	sll	%o0, 8, %o0
	ldub	[%g1+%o5], %o3
	or	%g3, %o0, %g3
	ldub	[T+%o4], %g2
	cmp	%o1, 3
	ldub	[T+%o3], %o5
	sll	%g2, 16, %g2
	or	%g3, %g2, %g3
	ld	[%o7], %g2
	sll	%o5, 24, %o5
	or	%g3, %o5, %g3
	xor	%g3, %g2, %g3
	srl	%g3, 24, %o5
	srl	%g3, 16, %o0
	srl	%g3, 8, %g2
	stb	%g2, [%o2+1]
	stb	%o5, [%o2+3]
	stb	%o0, [%o2+2]
	stb	%g3, [dst+%i5]
	add	%o7, 4, %o7
	bleu	.Lfinal_loop
	add	%g4, 4, %g4
	
	add	src, 16, src
	addcc	length, -16, length
	bne	.Lblock_loop
	add	dst, 16, dst
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
