C arm64/ecc-secp256r1-redc.asm

ifelse(`
   Copyright (C) 2013, 2021 Niels Möller

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
')

	.file "ecc-secp256r1-redc.asm"

define(`RP', `x1')
define(`XP', `x2')

define(`U0', `x0') C Overlaps unused modulo input
define(`U1', `x3')
define(`U2', `x4')
define(`U3', `x5')
define(`U4', `x6')
define(`U5', `x7')
define(`U6', `x8')
define(`U7', `x9')
define(`F0', `x10')
define(`F1', `x11')
define(`F2', `x12')
define(`F3', `x13')
define(`ZERO', `x14')

C FOLD(x), sets (F3, F2,F1,F0 )  <--  (x << 192) - (x << 160) + (x << 128) + (x << 32)
define(`FOLD', `
	lsl	F0, $1, #32
	lsr	F1, $1, #32
	subs	F2, $1, F0
	sbc	F3, $1, F1
')

C FOLDC(x), sets (F3, F2,F1,F0)  <--  ((x+c) << 192) - (x << 160) + (x << 128) + (x << 32)
define(`FOLDC', `
	lsl	F0, $1, #32
	lsr	F1, $1, #32
	adc	F3, $1, ZERO	C May overflow, but final result will not.
	subs	F2, $1, F0
	sbc	F3, F3, F1
')

PROLOGUE(_nettle_ecc_secp256r1_redc)
	ldr	U0, [XP]
	ldr	U1, [XP, #8]
	ldr	U2, [XP, #16]
	ldr	U3, [XP, #24]
	ldr	U4, [XP, #32]
	ldr	U5, [XP, #40]
	ldr	U6, [XP, #48]
	ldr	U7, [XP, #56]
	mov	ZERO, #0

	FOLD(U0)
	adds	U1, U1, F0
	adcs	U2, U2, F1
	adcs	U3, U3, F2
	adcs	U4, U4, F3

	FOLDC(U1)
	adds	U2, U2, F0
	adcs	U3, U3, F1
	adcs	U4, U4, F2
	adcs	U5, U5, F3

	FOLDC(U2)
	adds	U3, U3, F0
	adcs	U4, U4, F1
	adcs	U5, U5, F2
	adcs	U6, U6, F3

	FOLDC(U3)
	adds	U4, U4, F0
	adcs	U5, U5, F1
	adcs	U6, U6, F2
	adcs	U7, U7, F3

	C Sum, including carry, is < 2^{256} + p.
	C If carry, we need to add in 2^{256} mod p = 2^{256} - p
	C     = <0xfffffffe, 0xff..ff, 0xffffffff00000000, 1>
	C and this addition can not overflow.
	adc	F0, ZERO, ZERO
	neg	F2, F0
	lsl	F1, F2, #32
	lsr	F3, F2, #32
	and	F3, F3, #-2

	adds	U0, F0, U4
	adcs	U1, F1, U5
	adcs	U2, F2, U6
	adc	U3, F3, U7

	str	U0, [RP]
	str	U1, [RP, #8]
	str	U2, [RP, #16]
	str	U3, [RP, #24]

	ret
EPILOGUE(_nettle_ecc_secp256r1_redc)
