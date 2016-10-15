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
	define(<CMOD5>, <%rdi>) C Overlaps DST
	define(<CP2MOD5>, <%rax>)
	define(<CMOD3>, <%rbx>)
	define(<S0>, <%r12>)
	define(<S1>, <%r13>)
	define(<S2>, <%r14>)
	define(<S3>, <%r15>)
	define(<TMP>, <%rbp>)

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
	C Save registers, %rdi (DST) last
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	DST

	C Unaligned read of source data.
	mov	(SRC), S0
	mov	8(SRC), S1
	mov	16(SRC), S2
	mov	24(SRC), S3

	C Read and add in first subkeys.
	mov	(KEYS), W0
	mov	8(KEYS), W1
	mov	16(KEYS), W2
	mov	24(KEYS), W3
	add	S0, W0
	add	S1, W1
	add	S2, W2
	add	S3, W3

	C Add tweak words
	add	(TWEAK), W1
	add	8(TWEAK), W2

	mov	$1, XREG(CMOD5)
	mov	$1, XREG(CMOD3)
	mov	$3, XREG(CP2MOD5)
	mov	$1, XREG(COUNT)

	ALIGN(16)
.Loop:
	ROUND(W0, W1, W2, W3, 14, 16)
	ROUND(W0, W3, W2, W1, 52, 57)
	ROUND(W0, W1, W2, W3, 23, 40)
	ROUND(W0, W3, W2, W1, 5, 37)

	add	(KEYS, CMOD5, 8), W0
	add	8(KEYS, CMOD5, 8), W1
	add	(KEYS, CP2MOD5, 8), W2
	add	8(KEYS, CP2MOD5, 8), W3
	add	(TWEAK, CMOD3, 8), W1
	add	8(TWEAK, CMOD3, 8), W2
	add	COUNT, W3

	ROUND(W0, W1, W2, W3, 25, 33)
	ROUND(W0, W3, W2, W1, 46, 12)
	ROUND(W0, W1, W2, W3, 58, 22)
	ROUND(W0, W3, W2, W1, 32, 32)

	add	8(KEYS, CMOD5, 8), W0
	add	(KEYS, CP2MOD5, 8), W1
	add	8(KEYS, CP2MOD5, 8), W2
	lea	4(CMOD5), TMP
	sub	$1, XREG(CMOD5)
	cmovnc	XREG(CMOD5), XREG(TMP)
	add	(KEYS, TMP, 8), W3
	mov	XREG(CP2MOD5), XREG(CMOD5)
	mov	XREG(TMP), XREG(CP2MOD5)

	add	8(TWEAK, CMOD3, 8), W1
	lea	2(CMOD3), TMP
	sub	$1, XREG(CMOD3)
	cmovc	XREG(TMP), XREG(CMOD3)
	add	(TWEAK, CMOD3, 8), W2
	lea	1(W3, COUNT), W3

	add	$2, XREG(COUNT)
	cmp	$19, XREG(COUNT)
	jne	.Loop

	pop	DST
	xor	S0, W0
	mov	W0, (DST)
	xor	S1, W1
	mov	W1, 8(DST)
	xor	S2, W2
	mov	W2, 16(DST)
	xor	S3, W3
	mov	W3, 24(DST)

	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx

	W64_EXIT(4, 0)
	ret
EPILOGUE(_nettle_skein256_block)
