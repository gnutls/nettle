C nettle, low-level cryptographics library
C 
C Copyright (C) 2012 Niels Möller
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

define(<CTX>, <%rdi>)		C 25 64-bit values, 200 bytes.
define(<COUNT>, <%r8>)		C Avoid clobbering %rsi, for W64.

define(<C01>, <%xmm0>)
define(<C23>, <%xmm1>)
define(<C4>, <%rdx>)

define(<T01>, <%xmm2>)
define(<T23>, <%xmm3>)
define(<T4>, <%r9>)
define(<D12>, <%xmm4>)
define(<D34>, <%xmm5>)
define(<D0>, <%r10>)
define(<T40>, <%xmm6>)
define(<D43>, <%xmm7>)

define(<RC_END>, <%r11>)

define(<FRAME_SIZE>, <200>)

define(<OFFSET>, <ifelse($1,0,,eval(8*$1))>)
define(<A>, <OFFSET($1)(CTX)>)
define(<B>, <OFFSET($1)(%rsp)>)

	C FIXME: Possible optimizations.

	C * Compute the parity vector C at the end of the chi step.
	C   This avoids one pass over the data.
	
	C * Micro optimizations with register use and scheduling.

	C * Try different order during the permutation step, maybe
	C   doing sequential writes rather than sequential reads.

	C * Try to do the permutation and the chi step, without
	C   storing intermediate values? That would reducing the
	C   number of passes over the data. We still need a copy, but
	C   we would let the theta step produce that copy.

	.file "sha3-permute.asm"
	
	C sha3_permute(struct sha3_state *ctx)
	.text
	ALIGN(4)
PROLOGUE(nettle_sha3_permute)
	W64_ENTRY(1, 8)
	subq	$FRAME_SIZE, %rsp
	movl	$24, XREG(COUNT)
	negq	COUNT

	lea 	.rc_end(%rip), RC_END
	ALIGN(4)
.Loop:
	C theta step
	C Compute parity vector C[0,...,4].
	movups	A(0), C01
	movups	A(2), C23
	movq	A(4), C4

	movups	A(5), T01
	movups	A(7), T23
	xorq	A(9), C4	C C[4] ^= A[9]

	pxor	T01, C01	C C[0,1] ^= A[5,6]
	movups	A(10), T01
	pxor	T23, C23	C C[2,3] ^= A[7,8]
	movups	A(12), T23
	xorq	A(14), C4	C C[4] ^= A[14]

	pxor	T01, C01	C C[0,1] ^= A[10,11]
	movups	A(15), T01
	pxor	T23, C23	C C[2,3] ^= A[12,13]
	movups	A(17), T23
	xorq	A(19), C4	C C[4] ^= A[19]

	pxor	T01, C01	C C[0,1] ^= A[15,16]
	movups	A(20), T01
	pxor	T23, C23	C C[2,3] ^= A[17,18]
	movups	A(22), T23
	xorq	A(24), C4	C C[4] ^= A[24]

	pxor	T01, C01	C C[0,1] ^= A[20,21]
	pxor	T23, C23	C C[2,3] ^= A[22,23]

	C Combine parity bits:
	C D[0] = C[4] ^ ROTL64(1, C[1])
	C D[1,2] = C[0,1] ^ ROTL64(1, C[2,3])
	C D[3,4] = C[2,3] ^ ROTL64(1, C[4,0])
	
	C Copy to D0, D12, D34, rotate original
	movdqa	C01, D12
	movdqa	C23, D34
	movdqa	C01, T01
	movdqa	C23, T23
	psllq	$1, T01
	psllq	$1, T23
	psrlq	$63, C01
	psrlq	$63, C23
	movq	C4, D0
	rolq	$1, C4
	por	T01, C01
	por	T23, C23

	C Move around, putting
	C  T4 <-- ROTL(1,C1), T40 <-- ROTL(1,C[4,0])
	movq	C4, T40
	punpcklqdq	C01, T40
	psrldq	$8, C01
	movd	C01, T4			C Really a movq!

	pxor	C23, D12
	xorq	T4, D0
	pxor	T40, D34

	C xor D on top of state
	xorq	D0, A(0)
	movups	A(1), T01
	movups	A(3), T23
	pxor	D12, T01
	pxor	D34, T23
	movups	T01, A(1)
	movups	T23, A(3)
	
	xorq	D0, A(5)
	movups	A(6), T01
	movups	A(8), T23
	pxor	D12, T01
	pxor	D34, T23
	movups	T01, A(6)
	movups	T23, A(8)

	xorq	D0, A(10)
	movups	A(11), T01
	movups	A(13), T23
	pxor	D12, T01
	pxor	D34, T23
	movups	T01, A(11)
	movups	T23, A(13)

	xorq	D0, A(15)
	movups	A(16), T01
	movups	A(18), T23
	pxor	D12, T01
	pxor	D34, T23
	movups	T01, A(16)
	movups	T23, A(18)

	xorq	D0, A(20)
	movups	A(21), T01
	movups	A(23), T23
	pxor	D12, T01
	pxor	D34, T23
	movups	T01, A(21)
	movups	T23, A(23)

	C rho and pi steps: Rotate and permute
	movq	A(0), C4	C rot  0, perm 0
	movq	A(1), T4	C rot  1, perm 10
	movq	C4, B(0)
	rolq	$1, T4
	movq	A(2), C4	C rot 62, perm 20
	movq	T4, B(10)
	rolq	$62, C4	
	movq	A(3), T4	C rot 28, perm 5
	movq	C4, B(20)
	rolq	$28, T4
	movq	A(4), C4	C rot 27, perm 15
	movq	T4, B(5)	
	rolq	$27, C4	
	movq	A(5), T4	C rot 36, perm 16
	movq	C4, B(15)
	rolq	$36, T4
	movq	A(6), C4	C rot 44, perm  1
	movq	T4, B(16)
	rolq	$44, C4	
	movq	A(7), T4	C rot  6, perm 11
	movq	C4, B(1)
	rolq	$6, T4
	movq	A(8), C4	C rot 55, perm 21
	movq	T4, B(11)
	rolq	$55, C4	
	movq	A(9), T4	C rot 20, perm  6
	movq	C4, B(21)
	rolq	$20, T4
	movq	A(10), C4	C rot  3, perm  7
	movq	T4, B(6)
	rolq	$3, C4	
	movq	A(11), T4	C rot 10, perm 17
	movq	C4, B(7)
	rolq	$10, T4
	movq	A(12), C4	C rot 43, perm  2
	movq	T4, B(17)
	rolq	$43, C4	
	movq	A(13), T4	C rot 25, perm 12
	movq	C4, B(2)
	rolq	$25, T4
	movq	A(14), C4	C rot 39, perm 22
	movq	T4, B(12)
	rolq	$39, C4	
	movq	A(15), T4	C rot 41, perm 23
	movq	C4, B(22)
	rolq	$41, T4
	movq	A(16), C4	C rot 45, perm  8
	movq	T4, B(23)
	rolq	$45, C4	
	movq	A(17), T4	C rot 15, perm 18
	movq	C4, B(8)
	rolq	$15, T4
	movq	A(18), C4	C rot 21, perm  3
	movq	T4, B(18)
	rolq	$21, C4	
	movq	A(19), T4	C rot  8, perm 13
	movq	C4, B(3)
	rolq	$8, T4
	movq	A(20), C4	C rot 18, perm 14
	movq	T4, B(13)
	rolq	$18, C4	
	movq	A(21), T4	C rot  2, perm 24
	movq	C4, B(14)
	rolq	$2, T4
	movq	A(22), C4	C rot 61, perm  9
	movq	T4, B(24)
	rolq	$61, C4	
	movq	A(23), T4	C rot 56, perm 19
	movq	C4, B(9)
	rolq	$56, T4
	movq	A(24), C4	C rot 14, perm  4
	movq	T4, B(19)
	rolq	$14, C4	
	movq	C4, B(4)

	C chi step
	C Read with some overlap, pairs C01, D12, D34
	C Then also construct pairs C23 and T40.

	C We do the operations as
	C A01 = B01 ^ (~B12 & B23)
	C A12 = B12 ^ (~B23 & B34)
	C A34 = B34 ^ (~B40 & B01)

	C Where we store only the low 64 bits of A01, and add in the
	C round key if applicable.
	
	movups	B(0), C01
	movups	B(1), D12
	movups	B(3), D34

	pshufd	$0x4e, D34, D43
	movdqa 	D43, T40
	punpcklqdq	C01, T40	C Get 40
	movdqa	D12, 	C23
	punpckhqdq	D43, C23	C Get 23

	pandn	C01, T40
	pxor	D34, T40
	movups	T40, A(3)

	movdqa	D12, T40
	pandn	C23, T40
	pxor	C01, T40

	movd	T40, T4		C Really movq!
	xorq	(RC_END, COUNT, 8), T4
	movq	T4, A(0)

	pandn	D34, C23
	pxor	D12, C23
	movups	C23, A(1)


	movups	B(5), C01
	movups	B(6), D12
	movups	B(8), D34

	pshufd	$0x4e, D34, D43
	movdqa 	D43, T40
	punpcklqdq	C01, T40	C Get 40
	movdqa	D12, 	C23
	punpckhqdq	D43, C23	C Get 23

	pandn	C01, T40
	pxor	D34, T40
	movups	T40, A(8)

	movdqa	D12, T40
	pandn	C23, T40
	pxor	C01, T40

	movq	T40, A(5)

	pandn	D34, C23
	pxor	D12, C23
	movups	C23, A(6)


	movups	B(10), C01
	movups	B(11), D12
	movups	B(13), D34

	pshufd	$0x4e, D34, D43
	movdqa 	D43, T40
	punpcklqdq	C01, T40	C Get 40
	movdqa	D12, 	C23
	punpckhqdq	D43, C23	C Get 23

	pandn	C01, T40
	pxor	D34, T40
	movups	T40, A(13)

	movdqa	D12, T40
	pandn	C23, T40
	pxor	C01, T40

	movq	T40, A(10)

	pandn	D34, C23
	pxor	D12, C23
	movups	C23, A(11)


	movups	B(15), C01
	movups	B(16), D12
	movups	B(18), D34

	pshufd	$0x4e, D34, D43
	movdqa 	D43, T40
	punpcklqdq	C01, T40	C Get 40
	movdqa	D12, 	C23
	punpckhqdq	D43, C23	C Get 23

	pandn	C01, T40
	pxor	D34, T40
	movups	T40, A(18)

	movdqa	D12, T40
	pandn	C23, T40
	pxor	C01, T40

	movq	T40, A(15)

	pandn	D34, C23
	pxor	D12, C23
	movups	C23, A(16)


	movups	B(20), C01
	movups	B(21), D12
	movups	B(23), D34

	pshufd	$0x4e, D34, D43
	movdqa 	D43, T40
	punpcklqdq	C01, T40	C Get 40
	movdqa	D12, 	C23
	punpckhqdq	D43, C23	C Get 23

	pandn	C01, T40
	pxor	D34, T40
	movups	T40, A(23)

	movdqa	D12, T40
	pandn	C23, T40
	pxor	C01, T40

	movq	T40, A(20)

	pandn	D34, C23
	pxor	D12, C23
	movups	C23, A(21)


	incq	COUNT
	jnz	.Loop

	addq	$FRAME_SIZE, %rsp
	W64_EXIT(1, 8)
	ret

EPILOGUE(nettle_sha3_permute)

ALIGN(4)
	.quad	0x0000000000000001, 0X0000000000008082
	.quad	0X800000000000808A, 0X8000000080008000
	.quad	0X000000000000808B, 0X0000000080000001
	.quad	0X8000000080008081, 0X8000000000008009
	.quad	0X000000000000008A, 0X0000000000000088
	.quad	0X0000000080008009, 0X000000008000000A
	.quad	0X000000008000808B, 0X800000000000008B
	.quad	0X8000000000008089, 0X8000000000008003
	.quad	0X8000000000008002, 0X8000000000000080
	.quad	0X000000000000800A, 0X800000008000000A
	.quad	0X8000000080008081, 0X8000000000008080
	.quad	0X0000000080000001, 0X8000000080008008
.rc_end:
