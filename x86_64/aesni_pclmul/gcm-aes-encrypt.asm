C x86_64/gcm-aes-encrypt.asm

ifelse(`
   Copyright (C) 2022, 2024 Niels Möller
   Copyright (C) 2023 Mamone Tarsha

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

C Register usage
define(`CTX', `%rdi')
define(`ROUNDS', `%rsi')
define(`COUNT', `%rdx')
define(`DST', `%rcx')
define(`SRC', `%r8')
define(`SUBKEYS', `%r9')
define(`I', `%r10')

C Long lived GHASH registers
define(`P', `%xmm0')
define(`BSWAP', `%xmm1')
define(`H', `%xmm2')
define(`D', `%xmm3')
define(`H2', `%xmm4')
define(`D2', `%xmm5')
define(`R', `%xmm6')

C Long lived AES registers
define(`CTR', `%xmm7')
define(`INCR', `%xmm8')

C Message blocks
define(`X', `%xmm9')
define(`Y', `%xmm10')

C Short lived GHASH registers
define(`T', `%xmm11')
define(`F', `%xmm12')
define(`F2', `%xmm13')

C Short lived AES registers
define(`K0', `%xmm11')
define(`K1', `%xmm12')

	C size_t
	C _gcm_aes_encrypt (struct gcm_key *key, unsigned rounds,
	C 		    size_t size, uint8_t *dst, const uint8_t *src);

PROLOGUE(_nettle_gcm_aes_encrypt)
	W64_ENTRY(5, 14)

	C Setup return value right away
	mov		COUNT, %rax
	and		$-32, %rax
	jz		.Ldone

	shr		$5, COUNT

	movdqa		.Lpolynomial(%rip), P
	movdqa		.Lbswap(%rip), BSWAP
	movdqa		.Lincr(%rip), INCR

	movups		(CTX), H
	movups		16(CTX), D
	movups		32(CTX), H2
	movups		48(CTX), D2
	add		$4096, CTX	C Point at the gcm_ctx
	movups		32(CTX), R
	pshufb		BSWAP, R

	C Setup rounds for negative indexing
	shll		$4, XREG(ROUNDS)	C Also zero extends
	lea		64(CTX, ROUNDS), SUBKEYS	C Point at last subkey
	neg		ROUNDS

	movups		16(CTX), CTR

	C Each iteration processes two blocks
.Lblock_loop:
	movups		(SUBKEYS, ROUNDS), K0
	movups		16(SUBKEYS, ROUNDS), K1
	movdqa		CTR, X
	pshufb		BSWAP, CTR
	paddd		INCR, CTR
	movdqa		CTR, Y
	paddd		INCR, CTR
	pshufb		BSWAP, Y
	pshufb		BSWAP, CTR

	pxor		K0, X
	pxor		K0, Y
	aesenc		K1, X
	aesenc		K1, Y

	lea		32(ROUNDS), I
	ALIGN(16)
.L1_loop:
	movups		(SUBKEYS, I), K0
	movups		16(SUBKEYS, I), K1
	aesenc		K0, X
	aesenc		K0, Y
	aesenc		K1, X
	aesenc		K1, Y
	add		$32, I
	jnc		.L1_loop

	movups		(SUBKEYS), K0
	aesenclast	K0, X
	aesenclast	K0, Y

	movups		(SRC), T
	movups		16(SRC), F2
	pxor		T, X
	pxor		F2, Y
	movups		X, (DST)
	movups		Y, 16(DST)
	add		$32, SRC
	add		$32, DST

	pshufb		BSWAP, X
	pxor		X, R
	movdqa		R, X
	movdqa		R, F
	movdqa		R, T
	pclmullqlqdq	D2, F 	C {D^2}0 * M1_0
	pclmullqhqdq	D2, R	C {D^2}1 * M1_0
	pclmulhqlqdq	H2, T	C {H^2}0 * M1_1
	pclmulhqhqdq	H2, X	C {H^2}1 * M1_1

	pxor		T, F
	pxor		X, R

	pshufb		BSWAP, Y
	movdqa		Y, X
	movdqa		Y, F2
	movdqa		Y, T
	pclmullqlqdq	D, F2 	C D0 * M2_0
	pclmullqhqdq	D, X	C D1 * M2_0
	pclmulhqlqdq	H, T	C H0 * M2_1
	pclmulhqhqdq	H, Y	C H1 * M2_1

	pxor		F2, F
	pxor		X, R

	pxor		T, F
	pxor		Y, R

	GHASH_REDUCE(R, F, P, T)
	dec		COUNT
	jne		.Lblock_loop

	pshufb		BSWAP, R
	movups		CTR, 16(CTX)
	movups		R, 32(CTX)
.Ldone:
	W64_EXIT(5, 14)
	ret
EPILOGUE(_nettle_gcm_aes_encrypt)

	ALIGN(16)
.Lpolynomial:
	.byte 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xC2
.Lbswap:
	.byte 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
.Lincr:
	C Applied after byte swap, should increment the last four bytes.
	.byte 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
