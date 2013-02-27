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

	.file "ecc-192-modp.asm"

define(<RP>, <%rsi>)
define(<T1>, <%rdi>) C Overlaps unused ecc input
define(<T2>, <%rcx>)
define(<T3>, <%rdx>)
define(<T4>, <%r8>)
define(<T5>, <%r9>)
define(<T6>, <%r10>)

	C ecc_192_modp (const struct ecc_curve *ecc, mp_limb_t *rp)
	.text
	ALIGN(4)
PROLOGUE(nettle_ecc_192_modp)
	W64_ENTRY(2, 0)
	C First: (B+1)*{r5, r4} < B^3 + B^2 - B
	mov	32(RP), T1
	mov	40(RP), T2
	mov	T2, T3
	xor	T4, T4
	add	T1, T2
	adc	$0, T3
	adc	$0, T4

	add	8(RP), T1
	adc	16(RP), T2
	adc	24(RP), T3
	adc	$0, T4
	C Sum is < 2B^4 + B^3 - B - 1, so {T4, T3} < 3B

	C Next: (B+1) * {T4, T3} < 3B^2 + 2B
	mov	T4, T5
	add	T3, T4
	adc	$0, T5

	xor	T6, T6
	add	(RP), T3
	adc	T4, T1
	adc	T5, T2
	adc	$0, T6

	C Fold in final carry.
	add	T6, T3
	adc	T6, T1
	adc	$0, T2

	mov	T3, (RP)
	mov	T1, 8(RP)
	mov	T2, 16(RP)

	W64_EXIT(2, 0)
	ret
EPILOGUE(nettle_ecc_192_modp)
