C x86_64/skein256-internal.asm

ifelse(<
   Copyright (C) 2016 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
>)

	define(<DST>, <%rdi>)
	define(<KEYS>, <%rsi>)
	define(<TWEAK>, <%rdx>)
	define(<SRC>, <%rcx>)

	define(<W0>, <%r8>)
	define(<W1>, <%r9>)
	define(<W2>, <%r10>)
	define(<W3>, <%r11>)

	define(<COUNT>, <%rcx>) C Overlaps SRC
	define(<T0>, <%rbx>)
	define(<T1>, <%rdx>) C Overlaps TWEAK
	define(<K0>, <%r12>)
	define(<K1>, <%r13>)
	define(<K2>, <%r14>)
	define(<K3>, <%r15>)
	define(<K4>, <%rsi>) C Overlaps KEYS
	define(<TMP>, <%rax>)

C ROUND(W0, W1, W2, W3, C0, C1)
define(<ROUND>, <
	add	$2, $1
	add	$4, $3
	rol	<$>$5, $2
	rol	<$>$6, $4
	xor	$1, $2
	xor	$3, $4
	>)

	.file "skein256-internal.asm"

	C _skein256_block(uint64_t *dst, const uint64_t *keys,
	C                 const uint64_t *tweak, const uint8_t *src)
	.text
	ALIGN(16)
PROLOGUE(_nettle_skein256_block)
	W64_ENTRY(4, 0)
	C Save registers, %rcx (SRC) last
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	SRC

	C Unaligned read of source data.
	mov	(SRC), W0
	mov	8(SRC), W1
	mov	16(SRC), W2
	mov	24(SRC), W3

	C Read subkeys.
	mov	(KEYS), K0
	mov	8(KEYS), K1
	mov	16(KEYS), K2
	mov	24(KEYS), K3
	mov	32(KEYS), K4

	C Read and add in tweak words.
	mov	(TWEAK), T0
	mov	8(TWEAK), T1
	add	T0, K1
	add	T1, K2

	mov	$0, XREG(COUNT)

	ALIGN(16)
.Loop:
	C Add subkeys
	add	K0, W0
	add	K1, W1
	add	K2, W2
	add	K3, W3
	add	COUNT, W3

	ROUND(W0, W1, W2, W3, 14, 16)
	ROUND(W0, W3, W2, W1, 52, 57)
	ROUND(W0, W1, W2, W3, 23, 40)
	ROUND(W0, W3, W2, W1, 5, 37)

	mov	K1, TMP
	sub	T0, TMP		C New value for K4
	add	TMP, W0

	add	K2, W1
	add	K4, W3
	lea	1(W3, COUNT), W3

	xor	T1, T0	C Next tweak word always xor of preceeding ones

	lea	(K3, T0), K1
	add	K1, W2

	mov	K0, K3
	mov	K2, K0
	sub	T1, K0
	xor	T0, T1
	lea	(K4, T1), K2

	mov	TMP, K4

	ROUND(W0, W1, W2, W3, 25, 33)
	ROUND(W0, W3, W2, W1, 46, 12)
	ROUND(W0, W1, W2, W3, 58, 22)
	ROUND(W0, W3, W2, W1, 32, 32)

	add	$2, XREG(COUNT)
	cmp	$18, XREG(COUNT)
	jne	.Loop

	pop	SRC

	add	K0, W0
	add	K1, W1
	add	K2, W2
	lea	18(K3, W3), W3

	C Repeats the unaligned reads. Keep in registers,
	C if we get any spare registers. Or consider copying
	C to stack?
	xor	(SRC), W0
	mov	W0, (DST)
	xor	8(SRC), W1
	mov	W1, 8(DST)
	xor	16(SRC), W2
	mov	W2, 16(DST)
	xor	24(SRC), W3
	mov	W3, 24(DST)

	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx

	W64_EXIT(4, 0)
	ret
EPILOGUE(_nettle_skein256_block)
