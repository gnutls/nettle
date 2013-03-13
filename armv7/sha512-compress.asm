C nettle, low-level cryptographics library
C
C Copyright (C) 2013 Niels Möller
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
C the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
C MA 02111-1301, USA.

	.file "sha512-compress.asm"
	.fpu	neon

define(<STATE>, <r0>)
define(<INPUT>, <r1>)
define(<K>, <r2>)
define(<SA>, <d16>)
define(<SB>, <d17>)
define(<SC>, <d18>)
define(<SD>, <d19>)
define(<SE>, <d20>)
define(<SF>, <d21>)
define(<SG>, <d22>)
define(<SH>, <d23>)
define(<W>, <d24>)
define(<T0>, <d25>)

define(<COUNT>, <r3>)

C Used for data load
define(<I0>, <r4>)
define(<I1>, <r5>)
define(<I2>, <r6>)
define(<I3>, <r7>)
define(<I4>, <r8>)
define(<DST>, <r10>)
define(<SHIFT>, <r12>)
define(<IT>, <r14>)

C FIXME: More opportunities for parallelism, at least do s0 and s1 xors,
C or expand two words at a time.
define(<EXPN>, <
	vldr		W, [sp, #+eval(8*$1)]
	vldr		T0, [sp, #+eval(8*(($1 + 14) % 16))]
	vshl.i64	d0, T0, #45
	vshr.u64	d2, T0, #19
	vshl.i64	d1, T0, #3
	vshr.u64	d3, T0, #61
	vadd.i64	q0, q0, q1
	vshr.u64	T0, T0, #6
	veor		T0, T0, d0
	veor		T0, T0, d1
	vadd.i64	W, W, T0
	vldr		T0, [sp, #+eval(8*(($1 + 9) % 16))]
	vadd.i64	W, W, T0
	vldr		T0, [sp, #+eval(8*(($1 + 1) % 16))]
	vshl.i64	d0, T0, #63
	vshr.u64	d2, T0, #1
	vshl.i64	d1, T0, #56
	vshr.u64	d3, T0, #8
	vadd.i64	q0, q0, q1
	vshr.u64	T0, T0, #7
	veor		T0, T0, d0
	veor		T0, T0, d1
	vadd.i64	W, W, T0
	vstr		W, [sp, #+eval(8*$1)]
>)

C ROUND(A,B,C,D,E,F,G,H,i)
C
C H += S1(E) + Choice(E,F,G) + K + W
C D += H
C H += S0(A) + Majority(A,B,C)
C
C Where
C
C S1(E) = E<<<50 ^ E<<<46 ^ E<<<23
C S0(A) = A<<<36 ^ A<<<30 ^ A<<<25
C Choice (E, F, G) = G^(E&(F^G))
C Majority (A,B,C) = (A&B) + (C&(A^B))

C FIXME: More opportunities for parallelism, at least do S0 and S1 xors.
define(<ROUND>, <
	vshl.i64	d0, $5, #50
	vshr.u64	d2, $5, #14
	vshl.i64	d1, $5, #46
	vshr.u64	d3, $5, #18
	vadd.i64	q0, q0, q1
	vshl.i64	d2, $5, #23
	vshr.u64	d3, $5, #41
	vadd.i64	d2, d2, d3
	veor		d0, d0, d1
	veor		d0, d0, d2
	vadd.i64	$8, $8, d0
	veor		d0, $6, $7
	vand		d0, d0, $5
	veor		d0, d0, $7
	vadd.i64	$8,$8, d0
	vldr		d0, [K,#eval(8*$9)]
	vadd.i64	$8, $8, W
	vadd.i64	$8, $8, d0
	vadd.i64	$4, $4, $8

	vshl.i64	d0, $1, #36
	vshr.u64	d2, $1, #28
	vshl.i64	d1, $1, #30
	vshr.u64	d3, $1, #34
	vadd.i64	q0, q0, q1
	vshl.i64	d2, $1, #25
	vshr.u64	d3, $1, #39
	vadd.i64	d2, d2, d3
	veor		d0, d0, d1
	veor		d0, d0, d2
	vadd.i64	$8, $8, d0
	vand		d0, $1, $2
	veor		d1, $1, $2
	vadd.i64	$8, $8, d0
	vand		d1, d1, $3
	vadd.i64	$8, $8, d1
>)

define(<NOEXPN>, <
	vldr	W, [INPUT, #eval(8*$1)]
>)

	C void
	C _nettle_sha512_compress(uint64_t *state, const uint8_t *input, const uint64_t *k)

	.text
	.align 2

PROLOGUE(_nettle_sha512_compress)
	push	{r4,r5,r6,r7,r8,r10,r14}
	sub	sp, sp, #128

	C Load data up front. FIXME: Use aligned vld1, and vshl.

	ands	SHIFT, INPUT, #3
	and	INPUT, INPUT, $-4
	lsl	SHIFT, SHIFT, #3
	mov	I0, #0
	movne	I0, #-1
	lsl	I1, I0, SHIFT
	uadd8	I0, I0, I1		C Sets APSR.GE bits
	ldr	I0, [INPUT]
	addne	INPUT, INPUT, #4

	mov	DST, sp
	mov	COUNT, #8
.Lcopy:
	ldm	INPUT!, {I1,I2,I3,I4}
	sel	IT, I0, I1
	ror	IT, IT, SHIFT
	sel	I0, I1, I2
	ror	I0, I0, SHIFT
	rev	I0, I0
	rev	I1, IT
	sel	IT, I2, I3
	ror	IT, IT, SHIFT
	sel	I2, I3, I4
	ror	I2, I2, SHIFT
	rev	I2, I2
	rev	I3, IT
	subs	COUNT, COUNT, #1
	stm	DST!, {I0,I1,I2,I3}
	mov	I0, I4
	bne	.Lcopy

	mov	COUNT,#2
	mov	INPUT, sp

	vldm	STATE, {SA,SB,SC,SD,SE,SF,SG,SH}

.Loop1:
	NOEXPN(0) ROUND(SA,SB,SC,SD,SE,SF,SG,SH, 0)
	NOEXPN(1) ROUND(SH,SA,SB,SC,SD,SE,SF,SG, 1)
	NOEXPN(2) ROUND(SG,SH,SA,SB,SC,SD,SE,SF, 2)
	NOEXPN(3) ROUND(SF,SG,SH,SA,SB,SC,SD,SE, 3)
	NOEXPN(4) ROUND(SE,SF,SG,SH,SA,SB,SC,SD, 4)
	NOEXPN(5) ROUND(SD,SE,SF,SG,SH,SA,SB,SC, 5)
	NOEXPN(6) ROUND(SC,SD,SE,SF,SG,SH,SA,SB, 6)
	NOEXPN(7) ROUND(SB,SC,SD,SE,SF,SG,SH,SA, 7)
	subs	COUNT,#1
	add	INPUT, INPUT, #64
	add	K, K, #64
	bne	.Loop1

	mov	COUNT, #4
.Loop2:

	EXPN( 0) ROUND(SA,SB,SC,SD,SE,SF,SG,SH,  0)
	EXPN( 1) ROUND(SH,SA,SB,SC,SD,SE,SF,SG,  1)
	EXPN( 2) ROUND(SG,SH,SA,SB,SC,SD,SE,SF,  2)
	EXPN( 3) ROUND(SF,SG,SH,SA,SB,SC,SD,SE,  3)
	EXPN( 4) ROUND(SE,SF,SG,SH,SA,SB,SC,SD,  4)
	EXPN( 5) ROUND(SD,SE,SF,SG,SH,SA,SB,SC,  5)
	EXPN( 6) ROUND(SC,SD,SE,SF,SG,SH,SA,SB,  6)
	EXPN( 7) ROUND(SB,SC,SD,SE,SF,SG,SH,SA,  7)
	EXPN( 8) ROUND(SA,SB,SC,SD,SE,SF,SG,SH,  8)
	EXPN( 9) ROUND(SH,SA,SB,SC,SD,SE,SF,SG,  9)
	EXPN(10) ROUND(SG,SH,SA,SB,SC,SD,SE,SF, 10)
	EXPN(11) ROUND(SF,SG,SH,SA,SB,SC,SD,SE, 11)
	EXPN(12) ROUND(SE,SF,SG,SH,SA,SB,SC,SD, 12)
	EXPN(13) ROUND(SD,SE,SF,SG,SH,SA,SB,SC, 13)
	EXPN(14) ROUND(SC,SD,SE,SF,SG,SH,SA,SB, 14)
	subs	COUNT, COUNT, #1
	EXPN(15) ROUND(SB,SC,SD,SE,SF,SG,SH,SA, 15)
	add	K, K, #128
	bne	.Loop2

	vld1.64		{d24,d25,d26,d27}, [STATE]
	vadd.i64	SA, SA, d24
	vadd.i64	SB, SB, d25
	vadd.i64	SC, SC, d26
	vadd.i64	SD, SD, d27
	vst1.64		{SA,SB,SC,SD}, [STATE]!
	vld1.64		{d24,d25,d26,d27}, [STATE]
	vadd.i64	SE, SE, d24
	vadd.i64	SF, SF, d25
	vadd.i64	SG, SG, d26
	vadd.i64	SH, SH, d27
	vst1.64		{SE,SF,SG,SH}, [STATE]!

	add		sp, sp, #128
	pop		{r4,r5,r6,r7,r8,r10,pc}
EPILOGUE(_nettle_sha512_compress)

divert(-1)
define shastate
p/x $d16.u64
p/x $d17.u64
p/x $d18.u64
p/x $d19.u64
p/x $d20.u64
p/x $d21.u64
p/x $d22.u64
p/x $d23.u64
end
