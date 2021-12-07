C powerpc64/ecc-secp256r1-redc.asm

ifelse(`
   Copyright (C) 2021 Amitay Isaacs & Martin Schwenke, IBM Corporation

   Based on x86_64/ecc-secp256r1-redc.asm

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

C Register usage:

define(`SP', `r1')

define(`RP', `r4')
define(`XP', `r5')

define(`F0', `r3')
define(`F1', `r6')
define(`F2', `r7')
define(`F3', `r8')

define(`U0', `r9')
define(`U1', `r10')
define(`U2', `r11')
define(`U3', `r12')
define(`U4', `r14')
define(`U5', `r15')
define(`U6', `r16')
define(`U7', `r17')

	.file "ecc-secp256r1-redc.asm"

C FOLD(x), sets (F3,F2,F1,F0)  <-- [(x << 192) - (x << 160) + (x << 128) + (x <<32)]
define(`FOLD', `
	sldi	F0, $1, 32
	srdi	F1, $1, 32
	subfc	F2, F0, $1
	subfe	F3, F1, $1
')

C FOLDC(x), sets (F3,F2,F1,F0)  <-- [((x+c) << 192) - (x << 160) + (x << 128) + (x <<32)]
define(`FOLDC', `
	sldi	F0, $1, 32
	srdi	F1, $1, 32
	addze	F3, $1
	subfc	F2, F0, $1
	subfe	F3, F1, F3
')

	C void ecc_secp256r1_redc (const struct ecc_modulo *p, mp_limb_t *rp, mp_limb_t *xp)
	.text
define(`FUNC_ALIGN', `5')
PROLOGUE(_nettle_ecc_secp256r1_redc)

	std	U4,-32(SP)
	std	U5,-24(SP)
	std	U6,-16(SP)
	std	U7,-8(SP)

	ld	U0, 0(XP)
	ld	U1, 8(XP)
	ld	U2, 16(XP)
	ld	U3, 24(XP)
	ld	U4, 32(XP)
	ld	U5, 40(XP)
	ld	U6, 48(XP)
	ld	U7, 56(XP)

	FOLD(U0)
	addc	U1, F0, U1
	adde	U2, F1, U2
	adde	U3, F2, U3
	adde	U4, F3, U4

	FOLDC(U1)
	addc	U2, F0, U2
	adde	U3, F1, U3
	adde	U4, F2, U4
	adde	U5, F3, U5

	FOLDC(U2)
	addc	U3, F0, U3
	adde	U4, F1, U4
	adde	U5, F2, U5
	adde	U6, F3, U6

	FOLDC(U3)
	addc	U4, F0, U4
	adde	U5, F1, U5
	adde	U6, F2, U6
	adde	U7, F3, U7

	C If carry, we need to add in
	C 2^256 - p = <0xfffffffe, 0xff..ff, 0xffffffff00000000, 1>
	li	F0, 0
	addze	F0, F0
	neg	F2, F0
	sldi	F1, F2, 32
	srdi	F3, F2, 32
	li	XP, -2
	and	F3, F3, XP

	addc	U0, F0, U4
	adde	U1, F1, U5
	adde	U2, F2, U6
	adde	U3, F3, U7

	std	U0, 0(RP)
	std	U1, 8(RP)
	std	U2, 16(RP)
	std	U3, 24(RP)

	ld	U4,-32(SP)
	ld	U5,-24(SP)
	ld	U6,-16(SP)
	ld	U7,-8(SP)

	blr
EPILOGUE(_nettle_ecc_secp256r1_redc)
