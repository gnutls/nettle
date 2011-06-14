C nettle, low-level cryptographics library
C 
C Copyright (C) 2011 Niels Möller
C  
C The nettle library is free software; you can redistribute it and/or modify
C it under the terms of the GNU Lesser General Public License as published by
C the Free Software Foundation; either version 2.1 of the License, or (at your
C option) any later version.
C 
C The nettle library is distributed in the hope that it will be useful, but
C WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
C or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
C License for more details.
C 
C You should have received a copy of the GNU Lesser General Public License
C along with the nettle library; see the file COPYING.LIB.  If not, write to
C the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
C MA 02111-1307, USA.
	
C Register usage:

C Single block serpent state, two copies
define(<x0>, <%eax>)
define(<x1>, <%ebx>)
define(<x2>, <%ebp>)
define(<x3>, <%r8d>)

define(<y0>, <%r9d>)
define(<y1>, <%r10d>)
define(<y2>, <%r11d>)
define(<y3>, <%r12d>)

C Quadruple block serpent state, two copies
define(<X0>, <%xmm0>)
define(<X1>, <%xmm1>)
define(<X2>, <%xmm2>)
define(<X3>, <%xmm3>)

define(<Y0>, <%xmm4>)
define(<Y1>, <%xmm5>)
define(<Y2>, <%xmm6>)
define(<Y3>, <%xmm7>)

C Arguments
define(<CTX>, <%rdi>)
define(<N>, <%rsi>)
define(<DST>, <%rdx>)
define(<SRC>, <%rcx>)

define(<CNT>, <%r13>)
define(<TMP>, <%r14d>)	C 32-bit temporary

C Sbox macros. Inputs $1 - $4 (destroyed), outputs $5 - $8

define(<SBOX0>, <
	mov	$2, $8	C y3  = x1 ^ x2
	xor 	$3, $8
	mov	$1, $5	C y0  = x0 | x3
	or	$4, $5
	mov	$1, $6	C y1  = x0 ^ x1
	xor	$2, $6
	xor	$5, $8	C y3 ^= y0
	mov	$3, $7	C y2  = x2 | y3
	or	$8, $7
	xor	$4, $1	C x0 ^= x3
	and	$4, $7	C y2 &= x3
	xor	$3, $4	C x3 ^= x2
	or	$2, $3	C x2 |= x1
	mov	$6, $5	C y0  = y1 & x2
	and	$3, $5
	xor	$5, $7	C y2 ^= y0
	and	$7, $5	C y0 &= y2
	xor	$3, $5	C y0 ^= x2
	and	$1, $2	C x1 &= x0
	xor	$1, $5	C y0 ^= x0
	not	$5	C y0  = ~y0
	mov	$5, $6	C y1  = y0 ^ x1
	xor	$2, $6
	xor	$4, $6	C y1 ^= x3
>)

define(<SBOX1>, <
	mov	$1, $6	C y1  = x0 | x3
	or	$4, $6 
	mov	$3, $7	C y2  = x2 ^ x3
	xor	$4, $7
	mov	$2, $5	C y0  = ~x1
	not	$5
	mov	$1, $8	C y3  = x0 ^ x2
	xor	$3, $8
	or	$1, $5	C y0 |= x0
	and	$4, $8	C y3 &= x3
	mov	$6, $1	C x0  = y1 & y2
	and	$7, $1
	or	$2, $8	C y3 |= x1
	xor	$5, $7	C y2 ^= y0
	xor	$1, $8	C y3 ^= x0
	mov	$6, $1	C x0  = y1 ^ y3
	xor	$8, $1
	xor	$7, $1	C x0 ^= y2
	mov	$2, $6	C y1  = x1 & x3
	and	$4, $6
	xor	$1, $6	C y1 ^= x0
	mov	$6, $4	C x3  = y1 | y3
	or	$8, $4
	not	$8	C y3  = ~y3
	and 	$4, $5	C y0 &= x3
	xor	$3, $5	C y0 ^= x2
>)

define(<SBOX2>, <
	mov	$1, $7	C y2 = x1 | x2
	or	$3, $7
	mov	$1, $6
	xor	$2, $6
	mov	$4, $8
	xor	$7, $8
	mov	$6, $5
	xor	$8, $5
	or	$1, $4
	xor	$5, $3
	mov	$2, $1
	xor	$3, $1
	or	$2, $3
	and	$7, $1
	xor	$3, $8
	or	$8, $6
	xor	$1, $6
	mov	$8, $7
	xor	$6, $7
	xor	$2, $7
	not	$8
	xor	$4, $7
>)

define(<SBOX3>, <
	mov	$1, $6
	xor	$3, $6
	mov	$1, $5
	or	$4, $5
	mov	$1, $8
	and	$4, $8
	and	$5, $6
	or	$2, $8
	mov	$1, $7
	and	$2, $7
	or	$3, $7
	mov	$4, $3
	xor	$6, $3
	xor	$8, $6
	or	$3, $1
	xor	$2, $3
	and	$4, $8
	xor	$8, $5
	mov	$7, $8
	xor	$3, $8
	xor	$5, $7
	or	$8, $4
	and	$4, $2
	mov	$1, $5
	xor	$2, $5
>)
define(<SBOX4>, <
	mov	$1, $8
	or	$2, $8
	mov	$2, $7
	or	$3, $7
	xor	$1, $7
	and	$4, $8
	mov	$2, $5
	xor	$4, $5
	or	$7, $4
	and	$4, $1
	and	$3, $2
	xor	$8, $3
	xor	$7, $8
	or	$2, $7
	mov	$8, $6
	and	$5, $6
	xor	$6, $7
	xor	$5, $6
	or	$2, $6
	xor	$1, $6
	and	$4, $5
	xor	$3, $5
	not	$5
>)

define(<SBOX5>, <
	mov	$2, $5
	or	$4, $5
	xor	$3, $5
	mov	$2, $3
	xor	$4, $3
	mov	$1, $7
	xor	$3, $7
	and	$3, $1
	xor	$1, $5
	mov	$2, $8
	or	$7, $8
	or	$5, $2
	not	$5
	or	$5, $1
	xor	$3, $8
	xor	$1, $8
	mov	$4, $6
	or	$5, $6
	xor	$6, $4
	xor	$7, $6
	or	$4, $7
	xor	$2, $7
>)

define(<SBOX6>, <
	mov	$1, $5
	xor	$4, $5
	mov	$1, $6
	and	$4, $6
	mov	$1, $7
	or	$3, $7
	or	$2, $4
	xor	$3, $4
	xor	$2, $1
	mov	$2, $8
	or	$3, $8
	xor	$2, $3
	and	$5, $8
	xor	$3, $6
	not	$6
	and	$6, $5
	and	$6, $2
	xor	$8, $2
	xor	$4, $8
	xor	$2, $7
	not	$7
	xor	$7, $5
	xor	$1, $5
>)

define(<SBOX7>, <
	mov	$1, $5
	and	$3, $5
	mov	$2, $8
	or	$5, $8	C t04
	xor	$3, $8
	mov	$4, $6
	not	$6	C t02	
	and	$1, $6
	xor	$6, $8
	mov	$3, $6
	or	$8, $6
	xor	$1, $6
	mov	$1, $7
	and	$2, $7
	xor	$7, $3
	or	$4, $7
	xor	$7, $6
	mov	$2, $7
	or	$5, $7	C t04
	and	$8, $7
	xor	$6, $2
	or	$2, $7
	xor	$1, $7
	xor	$6, $5
	not	$4	C t02
	or	$4, $5
	xor	$3, $5
>)

define(<LT>, <
	rol	<$>13, $1
	rol	<$>3, $3
	xor	$1, $2
	xor	$3, $2
	mov	$1, TMP
	shl	<$>3, TMP
	xor	$3, $4
	xor	TMP, $4
	rol	$2
	rol	<$>7, $4
	xor	$2, $1
	xor	$4, $1
	mov	$2, TMP
	shl	<$>7, TMP
	xor	$4, $3
	xor	TMP, $3
	rol	<$>5, $1
	rol	<$>22, $3
>)

	.file "aes-serpent-encrypt.asm"
	
	C serpent_encrypt(struct serpent_context *ctx, 
	C	          unsigned length, uint8_t *dst,
	C	          const uint8_t *src)
	.text
	ALIGN(4)
PROLOGUE(nettle_serpent_encrypt)
	test	N, N
	jz	.Lend

        C save all registers that need to be saved
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14

	lea	(SRC, N), SRC
	lea	(DST, N), DST
	neg	N
	
C The single-block loop here is slightly slower than the double-block
C loop in serpent-encrypt.c.

.Lblock_loop:
	movl	(SRC, N), x0
	movl	4(SRC, N), x1
	movl	8(SRC, N), x2
	movl	12(SRC, N), x3

	xor	CNT, CNT
.Lround_loop:
	xor	  (CTX, CNT), x0
	xor	 4(CTX, CNT), x1
	xor	 8(CTX, CNT), x2
	xor	12(CTX, CNT), x3
	SBOX0(x0,x1,x2,x3, y0,y1,y2,y3)
	LT(y0,y1,y2,y3)
	
	xor	16(CTX, CNT), y0
	xor	20(CTX, CNT), y1
	xor	24(CTX, CNT), y2
	xor	28(CTX, CNT), y3
	SBOX1(y0,y1,y2,y3, x0,x1,x2,x3)
	LT(x0,x1,x2,x3)

	xor	32(CTX, CNT), x0
	xor	36(CTX, CNT), x1
	xor	40(CTX, CNT), x2
	xor	44(CTX, CNT), x3
	SBOX2(x0,x1,x2,x3, y0,y1,y2,y3)
	LT(y0,y1,y2,y3)

	xor	48(CTX, CNT), y0
	xor	52(CTX, CNT), y1
	xor	56(CTX, CNT), y2
	xor	60(CTX, CNT), y3
	SBOX3(y0,y1,y2,y3, x0,x1,x2,x3)
	LT(x0,x1,x2,x3)

	xor	64(CTX, CNT), x0
	xor	68(CTX, CNT), x1
	xor	72(CTX, CNT), x2
	xor	76(CTX, CNT), x3
	SBOX4(x0,x1,x2,x3, y0,y1,y2,y3)
	LT(y0,y1,y2,y3)

	xor	80(CTX, CNT), y0
	xor	84(CTX, CNT), y1
	xor	88(CTX, CNT), y2
	xor	92(CTX, CNT), y3
	SBOX5(y0,y1,y2,y3, x0,x1,x2,x3)
	LT(x0,x1,x2,x3)

	xor	96(CTX, CNT), x0
	xor	100(CTX, CNT), x1
	xor	104(CTX, CNT), x2
	xor	108(CTX, CNT), x3
	SBOX6(x0,x1,x2,x3, y0,y1,y2,y3)
	LT(y0,y1,y2,y3)

	xor	112(CTX, CNT), y0
	xor	116(CTX, CNT), y1
	xor	120(CTX, CNT), y2
	xor	124(CTX, CNT), y3
	SBOX7(y0,y1,y2,y3, x0,x1,x2,x3)
	add	$128, CNT
	C FIXME: Offset CTX and CNT, so we can jump out when CNT == 0
	cmp	$512, CNT
	je	.Lfinal_round
	LT(x0,x1,x2,x3)
	jmp	.Lround_loop

.Lfinal_round:
	xor	  (CTX, CNT), x0
	xor	 4(CTX, CNT), x1
	xor	 8(CTX, CNT), x2
	xor	12(CTX, CNT), x3

	movl	x0, (DST, N)
	movl	x1, 4(DST, N)
	movl	x2, 8(DST, N)
	movl	x3, 12(DST, N)
	add	$16, N
	jnc	.Lblock_loop
	

	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
.Lend:
	ret
