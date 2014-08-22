C x86_64/ecc-25519-modp.asm

ifelse(<
   Copyright (C) 2014 Niels Möller

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

	.file "ecc-25519-modp.asm"

define(<RP>, <%rsi>)
define(<U0>, <%rdi>) C Overlaps unused ecc input
define(<U1>, <%rcx>)
define(<U2>, <%r8>)
define(<V1>, <%r9>)
define(<V2>, <%r10>)
define(<V3>, <%r11>)
define(<M>, <%r12>)

PROLOGUE(nettle_ecc_25519_modp)
	W64_ENTRY(2, 0)
	push	%r12
	
	mov	$38, M
	mov	32(RP), %rax	
	mul	M
	mov	%rax, U0
	mov	%rdx, V1

	mov	40(RP), %rax
	mul	M
	mov	%rax, U1
	mov	%rdx, V2
	
	mov	48(RP), %rax
	mul	M
	mov	%rax, U2
	mov	%rdx, V3
	
	mov	56(RP), %rax
	mul	M
	
	add	V1, U1
	adc	V2, U2
	adc	V3, %rax
	adc	$0, %rdx

	shr 	M
	C FIXME: Load and add earlier?
	add	(RP), U0
	adc	8(RP), U1
	adc	16(RP), U2
	adc	24(RP), %rax
	adc	$0, %rdx

	add	%rax, %rax	C Copy high bit to carry
	adc	%rdx, %rdx
	shr	%rax		C Undo shift, clear high bit
	imul	M, %rdx

	add	%rdx, U0
	mov	U0, (RP)
	adc	$0, U1
	mov	U1, 8(RP)
	adc	$0, U2
	mov	U2, 16(RP)
	adc	$0, %rax
	mov	%rax, 24(RP)

	pop	%r12
	W64_EXIT(2, 0)
	ret
EPILOGUE(nettle_ecc_25519_modp)
