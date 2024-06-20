C x86_64/sha512-compress.asm

ifelse(`
   Copyright (C) 2024 Eric Richter, IBM Corporation

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

.file "sha512-compress.asm"

C Parameters in
define(`SP', `r1')
define(`STATE', `r3')
define(`INPUT', `r4')
define(`K', `r5')

define(`T0', `r6')
define(`T1', `r7')
define(`TK', `r8')
define(`COUNT', `r9')
define(`TC0', `0')	C Index instructions allow literal 0 instead of a GPR
define(`TC8', `r10')
define(`TC16', `r11')
define(`TC24', `r12')
define(`TC32', `r14')
define(`TC48', `r15')

C State registers
define(`VSA', `v0')
define(`VSB', `v1')
define(`VSC', `v2')
define(`VSD', `v3')
define(`VSE', `v4')
define(`VSF', `v5')
define(`VSG', `v6')
define(`VSH', `v7')

C Previous state value registers stored in VSX
define(`VSXAB', `vs0')
define(`VSXCD', `vs1')
define(`VSXEF', `vs2')
define(`VSXGH', `vs3')

C Current K values
define(`VK', `v8')

C Temp registers for math
define(`VT0', `v9')
define(`VT1', `v10')
define(`VT2', `v11')
define(`VT3', `v12')
define(`VT4', `v13')

C Convenience named registers for sigma(a) and sigma(e)
define(`SIGA', `v14')
define(`SIGE', `v15')

C Registers v16-v31 are used for input words W[0] through W[15]

C Convert an index for W[i] to the corresponding vector register v[16 + i]
define(`IV', `m4_unquote(v`'eval((($1) % 16) + 16))')

C ROUND(A B C D E F G H R)
define(`ROUND', `

	vaddudm	VT1, VK, IV($9)               C VT1: k+W
	vaddudm	VT4, $8, VT1                  C VT4: H+k+W

	lxvd2x	VSR(VK), TK, K                C Load Key
	addi	TK, TK, 8	              C Increment Pointer to next key

	vaddudm	VT2, $4, $8	              C VT2: H+D
	vaddudm	VT2, VT2, VT1                 C VT2: H+D+k+W

	vshasigmad	SIGE, $5, 1, 0b1111   C Sigma(E)  Se
	vshasigmad	SIGA, $1, 1, 0        C Sigma(A)  Sa

	vxor	VT3, $2, $3                   C VT3: b^c
	vsel	VT0, $7, $6, $5	              C VT0: Ch.
	vsel	VT3, $3, $1, VT3              C VT3: Maj(a,b,c)

	vaddudm	VT4, VT4, VT0                 C VT4: Hkw + Ch.
	vaddudm	VT3, VT3, VT4                 C VT3: HkW + Ch. + Maj.

	vaddudm	VT0, VT0, VT2                 C VT0: Ch. + DHKW
	vaddudm	$8, SIGE, SIGA                C Anext: Se + Sa
	vaddudm	$4, VT0, SIGE                 C Dnext: Ch. + DHKW + Se
	vaddudm	$8, $8, VT3                   C Anext: Se+Sa+HkW+Ch.+Maj.
')

C Extend W[i]
define(`EXTEND', `
	vshasigmad	SIGE, IV($1 + 14), 0, 0b1111
	vshasigmad	SIGA, IV($1 + 1), 0, 0b0000
	vaddudm		IV($1), IV($1), SIGE
	vaddudm		IV($1), IV($1), SIGA
	vaddudm		IV($1), IV($1), IV($1 + 9)
')

define(`EXTENDROUND',	`
	ROUND($1, $2, $3, $4, $5, $6, $7, $8, $9)
	C Schedule (data) for 16th round in future
	EXTEND($9)
')
define(`NOEXTENDROUND',	`ROUND($1, $2, $3, $4, $5, $6, $7, $8, $9)')

define(`NOEXTENDROUNDS', `
	NOEXTENDROUND(VSA, VSB, VSC, VSD, VSE, VSF, VSG, VSH, 0)
	NOEXTENDROUND(VSH, VSA, VSB, VSC, VSD, VSE, VSF, VSG, 1)
	NOEXTENDROUND(VSG, VSH, VSA, VSB, VSC, VSD, VSE, VSF, 2)
	NOEXTENDROUND(VSF, VSG, VSH, VSA, VSB, VSC, VSD, VSE, 3)

	NOEXTENDROUND(VSE, VSF, VSG, VSH, VSA, VSB, VSC, VSD, 4)
	NOEXTENDROUND(VSD, VSE, VSF, VSG, VSH, VSA, VSB, VSC, 5)
	NOEXTENDROUND(VSC, VSD, VSE, VSF, VSG, VSH, VSA, VSB, 6)
	NOEXTENDROUND(VSB, VSC, VSD, VSE, VSF, VSG, VSH, VSA, 7)

	NOEXTENDROUND(VSA, VSB, VSC, VSD, VSE, VSF, VSG, VSH, 8)
	NOEXTENDROUND(VSH, VSA, VSB, VSC, VSD, VSE, VSF, VSG, 9)
	NOEXTENDROUND(VSG, VSH, VSA, VSB, VSC, VSD, VSE, VSF, 10)
	NOEXTENDROUND(VSF, VSG, VSH, VSA, VSB, VSC, VSD, VSE, 11)

	NOEXTENDROUND(VSE, VSF, VSG, VSH, VSA, VSB, VSC, VSD, 12)
	NOEXTENDROUND(VSD, VSE, VSF, VSG, VSH, VSA, VSB, VSC, 13)
	NOEXTENDROUND(VSC, VSD, VSE, VSF, VSG, VSH, VSA, VSB, 14)
	NOEXTENDROUND(VSB, VSC, VSD, VSE, VSF, VSG, VSH, VSA, 15)
')

define(`EXTENDROUNDS', `
	EXTENDROUND(VSA, VSB, VSC, VSD, VSE, VSF, VSG, VSH, 0)
	EXTENDROUND(VSH, VSA, VSB, VSC, VSD, VSE, VSF, VSG, 1)
	EXTENDROUND(VSG, VSH, VSA, VSB, VSC, VSD, VSE, VSF, 2)
	EXTENDROUND(VSF, VSG, VSH, VSA, VSB, VSC, VSD, VSE, 3)

	EXTENDROUND(VSE, VSF, VSG, VSH, VSA, VSB, VSC, VSD, 4)
	EXTENDROUND(VSD, VSE, VSF, VSG, VSH, VSA, VSB, VSC, 5)
	EXTENDROUND(VSC, VSD, VSE, VSF, VSG, VSH, VSA, VSB, 6)
	EXTENDROUND(VSB, VSC, VSD, VSE, VSF, VSG, VSH, VSA, 7)

	EXTENDROUND(VSA, VSB, VSC, VSD, VSE, VSF, VSG, VSH, 8)
	EXTENDROUND(VSH, VSA, VSB, VSC, VSD, VSE, VSF, VSG, 9)
	EXTENDROUND(VSG, VSH, VSA, VSB, VSC, VSD, VSE, VSF, 10)
	EXTENDROUND(VSF, VSG, VSH, VSA, VSB, VSC, VSD, VSE, 11)

	EXTENDROUND(VSE, VSF, VSG, VSH, VSA, VSB, VSC, VSD, 12)
	EXTENDROUND(VSD, VSE, VSF, VSG, VSH, VSA, VSB, VSC, 13)
	EXTENDROUND(VSC, VSD, VSE, VSF, VSG, VSH, VSA, VSB, 14)
	EXTENDROUND(VSB, VSC, VSD, VSE, VSF, VSG, VSH, VSA, 15)
')

define(`LOAD', `
	IF_BE(`lxvd2x	VSR(IV($1)), $2, INPUT')
	IF_LE(`
		lxvd2x	VSR(IV($1)), $2, INPUT
		vperm	IV($1), IV($1), IV($1), VT0
	')
')

define(`DOLOADS', `
	IF_LE(`DATA_LOAD_VEC(VT0, .load_swap, T1)')
	LOAD(0, TC0)
	LOAD(1, TC8)
	LOAD(2, TC16)
	LOAD(3, TC24)
	addi	INPUT, INPUT, 32
	LOAD(4, TC0)
	LOAD(5, TC8)
	LOAD(6, TC16)
	LOAD(7, TC24)
	addi	INPUT, INPUT, 32
	LOAD(8, TC0)
	LOAD(9, TC8)
	LOAD(10, TC16)
	LOAD(11, TC24)
	addi	INPUT, INPUT, 32
	LOAD(12, TC0)
	LOAD(13, TC8)
	LOAD(14, TC16)
	LOAD(15, TC24)
')

.text
PROLOGUE(_nettle_sha512_compress)
	C Store non-volatile registers

	li	T0, -8
	li	T1, -24
	stvx	v20, T0, SP
	stvx	v21, T1, SP
	subi	T0, T0, 32
	subi	T1, T1, 32
	stvx	v22, T0, SP
	stvx	v23, T1, SP
	subi	T0, T0, 32
	subi	T1, T1, 32
	stvx	v24, T0, SP
	stvx	v25, T1, SP
	subi	T0, T0, 32
	subi	T1, T1, 32
	stvx	v26, T0, SP
	stvx	v27, T1, SP
	subi	T0, T0, 32
	subi	T1, T1, 32
	stvx	v28, T0, SP
	stvx	v29, T1, SP
	subi	T0, T0, 32
	subi	T1, T1, 32
	stvx	v30, T0, SP
	stvx	v31, T1, SP
	subi	T0, T0, 32
	subi	T1, T1, 32
	stdx	r14, T0, SP
	stdx	r15, T1, SP

	li	TC8, 8
	li	TC16, 16
	li	TC24, 24
	li	TC32, 32
	li	TC48, 48

	C Load state values
	lxvd2x	VSR(VSA), 0, STATE	C VSA contains A, B
	lxvd2x	VSR(VSC), TC16, STATE	C VSC contains C, D
	lxvd2x	VSR(VSE), TC32, STATE	C VSE contains E, F
	lxvd2x	VSR(VSG), TC48, STATE	C VSG contains G, H

	C Temporarily store the original state values in VSX registers
	xxlor	VSXAB, VSR(VSA), VSR(VSA)
	xxlor	VSXCD, VSR(VSC), VSR(VSC)
	xxlor	VSXEF, VSR(VSE), VSR(VSE)
	xxlor	VSXGH, VSR(VSG), VSR(VSG)

	C Shift second state value into its own state register
	vsldoi	VSB, VSA, VSA, 8
	vsldoi	VSD, VSC, VSC, 8
	vsldoi	VSF, VSE, VSE, 8
	vsldoi	VSH, VSG, VSG, 8

	li	TK, 0
	lxvd2x	VSR(VK), TK, K
	addi	TK, TK, 8

	DOLOADS

	EXTENDROUNDS
	EXTENDROUNDS
	EXTENDROUNDS
	EXTENDROUNDS
	NOEXTENDROUNDS

	C Reload initial state from VSX registers
	xxlor	VSR(VT0), VSXAB, VSXAB
	xxlor	VSR(VT1), VSXCD, VSXCD
	xxlor	VSR(VT2), VSXEF, VSXEF
	xxlor	VSR(VT3), VSXGH, VSXGH

	C Repack state values to two per register for storing
	xxmrghd	VSR(VSA), VSR(VSA), VSR(VSB)
	xxmrghd	VSR(VSC), VSR(VSC), VSR(VSD)
	xxmrghd	VSR(VSE), VSR(VSE), VSR(VSF)
	xxmrghd	VSR(VSG), VSR(VSG), VSR(VSH)

	C Perform the final add of the original state values
	vaddudm	VSA, VSA, VT0
	vaddudm	VSC, VSC, VT1
	vaddudm	VSE, VSE, VT2
	vaddudm	VSG, VSG, VT3

	stxvd2x	VSR(VSA), 0, STATE
	stxvd2x	VSR(VSC), TC16, STATE
	stxvd2x	VSR(VSE), TC32, STATE
	stxvd2x	VSR(VSG), TC48, STATE

	C Restore nonvolatile registers
	li	T0, -8
	li	T1, -24
	lvx	v20, T0, SP
	lvx	v21, T1, SP
	subi	T0, T0, 32
	subi	T1, T1, 32
	lvx	v22, T0, SP
	lvx	v23, T1, SP
	subi	T0, T0, 32
	subi	T1, T1, 32
	lvx	v24, T0, SP
	lvx	v25, T1, SP
	subi	T0, T0, 32
	subi	T1, T1, 32
	lvx	v26, T0, SP
	lvx	v27, T1, SP
	subi	T0, T0, 32
	subi	T1, T1, 32
	lvx	v28, T0, SP
	lvx	v29, T1, SP
	subi	T0, T0, 32
	subi	T1, T1, 32
	lvx	v30, T0, SP
	lvx	v31, T1, SP
	subi	T0, T0, 32
	subi	T1, T1, 32
	ldx	r14, T0, SP
	ldx	r15, T1, SP

	blr
EPILOGUE(_nettle_sha512_compress)

IF_LE(`
.data
.align 4
.load_swap:
	.byte 8,9,10,11, 12,13,14,15, 0,1,2,3, 4,5,6,7
')
