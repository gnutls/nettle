C arm64/asimd/poly1305-2core.asm

ifelse(`
   Copyright (C) 2022 Mamone Tarsha
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

C Argments
define(`CTX', `x0')
define(`DATA', `x1')
define(`LEN', `x2')
define(`T4', `w3')

C Working state
define(`H0', `v1')
define(`H1', `v2')
define(`H2', `v3')
define(`H3', `v4')
define(`H4', `v0')

define(`R0', `v16')
define(`R1', `v17')
define(`R2', `v18')
define(`R3', `v19')
define(`R4', `v20')

define(`S1', `v21')
define(`S2', `v22')
define(`S3', `v23')
define(`S4', `v24')

define(`C0', `v25')
define(`C1', `v26')
define(`C2',  `v27')
define(`C3',  `v28')
define(`C4',  `v29')

define(`T4W',  `v5')
define(`MASK26',  `v6')
define(`H2TBL',  `v7')

C Multiply state by key of two horizontal parts and reduce both products
define(`MUL_REDC', `
	umull	C0.2d, H0.2s, R0.2s
	umull	C1.2d, H1.2s, R0.2s
	umull	C2.2d, H2.2s, R0.2s
	umull	C3.2d, H3.2s, R0.2s
	umull	C4.2d, H4.2s, R0.2s

	umlal	C0.2d, H4.2s, S1.2s
	umlal	C1.2d, H0.2s, R1.2s
	umlal	C2.2d, H1.2s, R1.2s
	umlal	C3.2d, H2.2s, R1.2s
	umlal	C4.2d, H3.2s, R1.2s

	umlal	C0.2d, H3.2s, S2.2s
	umlal	C1.2d, H4.2s, S2.2s
	umlal	C2.2d, H0.2s, R2.2s
	umlal	C3.2d, H1.2s, R2.2s
	umlal	C4.2d, H2.2s, R2.2s

	umlal	C0.2d, H2.2s, S3.2s
	umlal	C1.2d, H3.2s, S3.2s
	umlal	C2.2d, H4.2s, S3.2s
	umlal	C3.2d, H0.2s, R3.2s
	umlal	C4.2d, H1.2s, R3.2s

	umlal	C0.2d, H1.2s, S4.2s
	umlal	C1.2d, H2.2s, S4.2s
	umlal	C2.2d, H3.2s, S4.2s
	umlal	C3.2d, H4.2s, S4.2s
	umlal	C4.2d, H0.2s, R4.2s

	C -- Reduction phase --
	
	C carry h0 -> h1
	C carry h3 -> h4
	ushr	H1.2d, C0.2d, #26
	ushr	H4.2d, C3.2d, #26
	add		H1.2d, H1.2d, C1.2d
	add		H4.2d, H4.2d, C4.2d
	and		H0.16b, C0.16b, MASK26.16b
	and		H3.16b, C3.16b, MASK26.16b

	C carry h1 -> h2
	C carry h4 -> h0
	ushr	C1.2d, H1.2d, #26
	ushr	C4.2d, H4.2d, #26
	add		H2.2d, C2.2d, C1.2d
	add		H0.2d, H0.2d, C4.2d
	and		H1.16b, H1.16b, MASK26.16b
	and		H4.16b, H4.16b, MASK26.16b

	C carry h4*4 -> h0
	C carry h2 -> h3
	shl		C4.2d, C4.2d, #2
	ushr	C2.2d, H2.2d, #26
	add		H0.2d, H0.2d, C4.2d
	add		H3.2d, H3.2d, C2.2d
	and		H2.16b, H2.16b, MASK26.16b

	C carry h0 -> h1
	C carry h3 -> h4
	ushr	C0.2d, H0.2d, #26
	ushr	C3.2d, H3.2d, #26
	add		H1.2d, H1.2d, C0.2d
	add		H4.2d, H4.2d, C3.2d
	and		H0.16b, H0.16b, MASK26.16b
	and		H3.16b, H3.16b, MASK26.16b
	')

	.text
	C void _nettle_poly1305_2core(struct poly1305_ctx *ctx, const uint8_t *m, size_t len, unsigned t4)

PROLOGUE(_nettle_poly1305_2core)
	adr		x4, .mask26
	ld1		{MASK26.2d}, [x4]
	adr		x4, .h2tbl
	ld1		{H2TBL.16b}, [x4]

	C Shift and replicate T4 across vector
	lsl		T4, T4, #24
	dup		T4W.4s, T4

	C In case the buffer has only two blocks, process them separately
	cmp		LEN, #32
	b.eq	L2B

	C This procedure processes two blocks horizontally over vector 
	C registers. In order to keep two separated parts of state, we
	C store the state in the first parts of vector reigters and
	C initialize the second part with zeros. For each iteration, two
	C blocks would be added to both parts and multiply the state parts
	C by r^2 except for the last iteration we multiply the first part
	C of state by r^2 and the second part by r. In this way we can
	C maintain the correct sequence of multiples for each mutiplication
	C of consecutive blocks.

	C Load key and cached multiples
	ld4		{R0.s, R1.s, R2.s, R3.s}[0], [CTX], #16
	ld1		{R4.s}[0], [CTX], #4
	ld4		{S1.s, S2.s, S3.s, S4.s}[0], [CTX], #16

	C -- Calculate r^2 = r*r ---
	
	ins		H0.s[0], R0.s[0]
	ins		H1.s[0], R1.s[0]
	ins		H2.s[0], R2.s[0]
	ins		H3.s[0], R3.s[0]
	ins		H4.s[0], R4.s[0]

	MUL_REDC()

	C Horizontally asssign two parts of key vectors to r^2
	dup		R0.4s, H0.s[0]
	dup		R1.4s, H1.s[0]
	dup		R2.4s, H2.s[0]
	dup		R3.4s, H3.s[0]
	dup		R4.4s, H4.s[0]

	C Calculate S = R*5
	shl		S1.4s, R1.4s, #2
	shl		S2.4s, R2.4s, #2
	shl		S3.4s, R3.4s, #2
	shl		S4.4s, R4.4s, #2
	add		S1.4s, S1.4s, R1.4s
	add		S2.4s, S2.4s, R2.4s
	add		S3.4s, S3.4s, R3.4s
	add		S4.4s, S4.4s, R4.4s

	C initialize the second parts of state with zeros
	eor		H0.16b, H0.16b, H0.16b
	eor		H1.16b, H1.16b, H1.16b
	eor		H2.16b, H2.16b, H2.16b
	eor		H3.16b, H3.16b, H3.16b
	eor		H4.16b, H4.16b, H4.16b

	C Load state
	ld4		{H4.s, H0.s, H1.s, H2.s}[0], [CTX], #16
	ld1		{H3.s}[0], [CTX]

	C Iterate over every pair of blocks and exclude the final one.
	sub		LEN, LEN, #32
L2B_loop:
	C Load two blocks
	ld1		{C3.16b, C4.16b}, [DATA], #32

	C Permute the two blocks and line them horizontally
	zip1	C0.2d, C3.2d, C4.2d
	tbl		C2.16b, { C3.16b, C4.16b }, H2TBL.16b
	zip2	C4.2d, C3.2d, C4.2d

	ushr	C1.2d, C0.2d, #26
	ushr	C2.2d, C2.2d, #4
	ushr	C3.2d, C4.2d, #14
	ushr	C4.2d, C4.2d, #40

	and		C0.16b, C0.16b, MASK26.16b
	and		C1.16b, C1.16b, MASK26.16b
	and		C2.16b, C2.16b, MASK26.16b
	and		C3.16b, C3.16b, MASK26.16b
	orr		C4.16b, C4.16b, T4W.16b

	add		H0.2d, H0.2d, C0.2d
	add		H1.2d, H1.2d, C1.2d
	add		H2.2d, H2.2d, C2.2d
	add		H3.2d, H3.2d, C3.2d
	add		H4.2d, H4.2d, C4.2d

	xtn		H0.2s, H0.2d
	xtn		H1.2s, H1.2d
	xtn		H2.2s, H2.2d
	xtn		H3.2s, H3.2d
	xtn		H4.2s, H4.2d

	MUL_REDC()

	subs	LEN, LEN, #32
	b.ne	L2B_loop

	C Set the first part of key to r^2 and the second part to r
	sub		CTX, CTX, #52
	ld4		{R0.s, R1.s, R2.s, R3.s}[1], [CTX], #16
	ld1		{R4.s}[1], [CTX], #4
	ld4		{S1.s, S2.s, S3.s, S4.s}[1], [CTX], #16

	ld1		{C3.16b, C4.16b}, [DATA]

	zip1	C0.2d, C3.2d, C4.2d
	tbl		C2.16b, { C3.16b, C4.16b }, H2TBL.16b
	zip2	C4.2d, C3.2d, C4.2d

	ushr	C1.2d, C0.2d, #26
	ushr	C2.2d, C2.2d, #4
	ushr	C3.2d, C4.2d, #14
	ushr	C4.2d, C4.2d, #40

	and		C0.16b, C0.16b, MASK26.16b
	and		C1.16b, C1.16b, MASK26.16b
	and		C2.16b, C2.16b, MASK26.16b
	and		C3.16b, C3.16b, MASK26.16b
	orr		C4.16b, C4.16b, T4W.16b

	add		H0.2d, H0.2d, C0.2d
	add		H1.2d, H1.2d, C1.2d
	add		H2.2d, H2.2d, C2.2d
	add		H3.2d, H3.2d, C3.2d
	add		H4.2d, H4.2d, C4.2d

	xtn		H0.2s, H0.2d
	xtn		H1.2s, H1.2d
	xtn		H2.2s, H2.2d
	xtn		H3.2s, H3.2d
	xtn		H4.2s, H4.2d

	MUL_REDC()

	C Combine both state parts
	dup		C0.2d, H0.d[1]
	dup		C1.2d, H1.d[1]
	dup		C2.2d, H2.d[1]
	dup		C3.2d, H3.d[1]
	dup		C4.2d, H4.d[1]

	add		H0.2d, H0.2d, C0.2d
	add		H1.2d, H1.2d, C1.2d
	add		H2.2d, H2.2d, C2.2d
	add		H3.2d, H3.2d, C3.2d
	add		H4.2d, H4.2d, C4.2d

	b		Ldone

	C Process two blocks separately
L2B:
	ld4		{R0.s, R1.s, R2.s, R3.s}[0], [CTX], #16
	ld1		{R4.s}[0], [CTX], #4
	ld4		{S1.s, S2.s, S3.s, S4.s}[0], [CTX], #16
	ld4		{H4.s, H0.s, H1.s, H2.s}[0], [CTX], #16
	ld1		{H3.s}[0], [CTX]
	sub		CTX, CTX, #16
L1B_loop:
	ld1		{C0.16b}, [DATA], #16

	tbl		C2.16b, { C0.16b }, H2TBL.16b
	ext		C4.16b, C0.16b, C0.16b, #8

	ushr	C1.2d, C0.2d, #26
	ushr	C2.2d, C2.2d, #4
	ushr	C3.2d, C4.2d, #14
	ushr	C4.2d, C4.2d, #40

	and		C0.16b, C0.16b, MASK26.16b
	and		C1.16b, C1.16b, MASK26.16b
	and		C2.16b, C2.16b, MASK26.16b
	and		C3.16b, C3.16b, MASK26.16b
	orr		C4.16b, C4.16b, T4W.16b

	add		H0.2d, H0.2d, C0.2d
	add		H1.2d, H1.2d, C1.2d
	add		H2.2d, H2.2d, C2.2d
	add		H3.2d, H3.2d, C3.2d
	add		H4.2d, H4.2d, C4.2d

	xtn		H0.2s, H0.2d
	xtn		H1.2s, H1.2d
	xtn		H2.2s, H2.2d
	xtn		H3.2s, H3.2d
	xtn		H4.2s, H4.2d

	MUL_REDC()

	subs	LEN, LEN, #16
	b.ne	L1B_loop

Ldone:
	C Store state
	st4		{H4.s, H0.s, H1.s, H2.s}[0], [CTX], #16
	st1		{H3.s}[0], [CTX]

	ret
EPILOGUE(_nettle_poly1305_2core)

.align	4
.mask26: .quad	0x0000000003FFFFFF,0x0000000003FFFFFF
.h2tbl: .byte	0x06,0x07,0x08,0x09,0x00,0x00,0x00,0x00,0x16,0x17,0x18,0x19,0x00,0x00,0x00,0x00
