! -*- mode: asm; asm-comment-char: ?!; -*-  
	! Used registers:	%l0,1,2,3,4,5,6,7
	!			%i0,1,2,3,4,5 (%i6=%fp, %i7 = return)
	!			%o0,1,2,3,4,5,7 (%o6=%sp)
	!			%g2,3,4,5,6
include(`asm.m4')
	
	.file	"aes.asm"
	
	.section	".text"
	.align 16
	.global _aes_crypt
	.type	_aes_crypt,#function
	.proc	020

! Arguments
define(ctx, %i0)
define(T, %i1)
define(length, %i2)
define(dst, %i3)
define(src, %i4)

! Loop invariants
define(wtxt, %l0)
define(tmp, %l1)
define(diff, %l2)
define(nrounds, %l3)

! Loop variables
define(round, %l4) ! Really 16 * round
define(i, %l5)

! Further loop invariants
define(T0, %l6)
define(T1, %l7)
define(T2, %g5)
define(T3, %g6)
define(key, %g7)

! Teporaries
define(t0, %o0)
define(t1, %o1)
define(t2, %o2)
define(t3, %o3)
define(idx, %o4)

_aes_crypt:
! Why -136?
	save	%sp, -136, %sp
	cmp	length, 0
	be	.Lend
	! wtxt
	add	%fp, -24, wtxt
	
	add	%fp, -40, tmp
	ld	[ctx + AES_NROUNDS], nrounds
	! Compute xor, so that we can swap efficiently.
	xor	wtxt, tmp, diff
	! The loop variable will be multiplied by 16.
	sll	nrounds, 4, nrounds
	
	! More loop invariants
	add	T, AES_TABLE0, T0
	add	T, AES_TABLE1, T1
	add	T, AES_TABLE2, T2
	add	T, AES_TABLE3, T3
		
.Lblock_loop:
	! Read src, and add initial subkey
	! Difference between ctx and src
	sub	ctx, src, %g2
	! Difference between wtxt and src
	sub	wtxt, src, %g3
	! For stop condition. Note that src is incremented in the
	! delay slot
	add	src, 8, %g4
	nop
	
.Lsource_loop:
	ldub	[src+3], t3
	ldub	[src+2], t2
	sll	t3, 24, t3
	ldub	[src+1], t1
	
	sll	t2, 16, t2
	or	t3, t2, t3
	ldub	[src], t0
	sll	t1, 8, t1
	
	! Get subkey
	ld	[src+%g2], t2
	or	t3, t1, t3
	or	t3, t0, t3
	xor	t3, t2, t3
	
	cmp	src, %g4
	st	t3, [src+%g3]
	bleu	.Lsource_loop
	add	src, 4, src

	mov	16, round
	add	ctx, 16, key

.Lround_loop:
	! 4*i
	mov	0, i
	add	T, AES_SIDX3, idx
.Linner_loop:
	! The comments mark which j in T->table[j][ Bj(wtxt[IDXi(i)]) ]
	! the instruction is a part of. 
	!
	! The code uses the register %o[j], aka tj, as the primary 
	! register for that sub-expression. True for j==1,3.
	
	! AES_SIDX1
	ld	[idx-32], t1		! 1
	! AES_SIDX2
	! IDX2(j) = j XOR 2
	xor	i, 8, t2
	! wtxt[IDX1...]
	add	wtxt, t1, t1		! 1
	ldub	[t1+2], t1		! 1

	! AES_SIDX3
	ld	[idx], t3		! 3
	sll	t1, 2, t1		! 1
	! wtxt[i]
	ld	[wtxt+i], t0		! 0
	! wtxt[IDX2...]
	lduh	[wtxt+t2], t2		! 2
	
	and	t0, 255, t0		! 0
	! wtxt[IDX3...]
	ldub	[wtxt+t3], t3		! 3
	sll	t0, 2, t0		! 0
	ld	[T0+t0], t0		! 0

	and	t2, 255, t2		! 2
	ld	[T1+t1], t1		! 1
	sll	t2, 2, t2		! 2
	ld	[T2+t2], t2		! 2

	sll	t3, 2, t3		! 3
	ld	[T3+t3], t3		! 3
	xor	t0, t1, t0		! 0, 1
	xor	t0, t2, t0		! 0, 1, 2

	add	idx, 4, idx		
	! Fetch roundkey
	ld	[key+i], t1
	xor	t0, t3, t0		! 0, 1, 2, 3
	xor	t0, t1, t0

	st	t0, [tmp+i]
	cmp	i, 8
	bleu	.Linner_loop
	add	i, 4, i
	
	! switch roles for tmp and wtxt
	xor	wtxt, diff, wtxt
	add	round, 16, round
	add	key, 16, key
	cmp	round, nrounds

	blu	.Lround_loop
	xor	tmp, diff, tmp

	! final round
	mov	0, i
	! SIDX3
	add	T, AES_SIDX3, %g4
.Lfinal_loop:
	! Comments mark which j in T->sbox[Bj(wtxt[IDXj(i)])]
	! the instruction is part of
	ld	[%g4-32], %g2 	! 1
	sll	i, 2, %i5

	add	wtxt, %g2, %g2	! 1
	ldub	[%g2+2], %o3	! 1
	add	%i5, dst, %o2	
	ld	[%g4-16], %g3	! 2
	add	i, 1, i
	ld	[wtxt+%i5], %g2	! 0

	lduh	[wtxt+%g3], %o4	! 2
	and	%g2, 255, %g2	! 0
	ld	[%g4], %o5	! 3
	and	%o4, 255, %o4	! 2
	ldub	[T+%o3], %o0	! 1

	ldub	[T+%g2], %g3	! 0
	sll	%o0, 8, %o0	! 1
	ldub	[wtxt+%o5], %o3	! 3
	or	%g3, %o0, %g3	! 0, 1
	ldub	[T+%o4], %g2	! 2
	cmp	i, 3
	ldub	[T+%o3], %o5	! 3
	sll	%g2, 16, %g2	! 2
	or	%g3, %g2, %g3	! 0, 1, 2
	ld	[ctx + round], %g2
	sll	%o5, 24, %o5	! 3
	or	%g3, %o5, %g3	! 0, 1, 2, 3
	xor	%g3, %g2, %g3
	srl	%g3, 24, %o5
	srl	%g3, 16, %o0
	srl	%g3, 8, %g2
	stb	%g2, [%o2+1]
	stb	%o5, [%o2+3]
	stb	%o0, [%o2+2]
	stb	%g3, [dst+%i5]
	add	round, 4, round
	bleu	.Lfinal_loop
	add	%g4, 4, %g4
	
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

	! After implementing double buffering
	! aes128 (ECB encrypt): 12.59s, 0.794MB/s
	! aes128 (ECB decrypt): 10.56s, 0.947MB/s
	! aes128 (CBC encrypt): 17.91s, 0.558MB/s
	! aes128 (CBC decrypt): 12.30s, 0.813MB/s
	! 
	! aes192 (ECB encrypt): 15.03s, 0.665MB/s
	! aes192 (ECB decrypt): 12.56s, 0.796MB/s
	! aes192 (CBC encrypt): 20.30s, 0.493MB/s
	! aes192 (CBC decrypt): 14.26s, 0.701MB/s
	! 
	! aes256 (ECB encrypt): 17.30s, 0.578MB/s
	! aes256 (ECB decrypt): 14.51s, 0.689MB/s
	! aes256 (CBC encrypt): 22.75s, 0.440MB/s
	! aes256 (CBC decrypt): 16.35s, 0.612MB/s
	
	! After reordering aes-encrypt.c and aes-decypt.c
	! (the order probably causes strange cache-effects):
	! aes128 (ECB encrypt): 9.21s, 1.086MB/s
	! aes128 (ECB decrypt): 11.13s, 0.898MB/s
	! aes128 (CBC encrypt): 14.12s, 0.708MB/s
	! aes128 (CBC decrypt): 13.77s, 0.726MB/s
	! 
	! aes192 (ECB encrypt): 10.86s, 0.921MB/s
	! aes192 (ECB decrypt): 13.17s, 0.759MB/s
	! aes192 (CBC encrypt): 15.74s, 0.635MB/s
	! aes192 (CBC decrypt): 15.91s, 0.629MB/s
	! 
	! aes256 (ECB encrypt): 12.71s, 0.787MB/s
	! aes256 (ECB decrypt): 15.38s, 0.650MB/s
	! aes256 (CBC encrypt): 17.49s, 0.572MB/s
	! aes256 (CBC decrypt): 17.87s, 0.560MB/s
