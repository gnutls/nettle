C nettle, low-level cryptographics library
C 
C Copyright (C) 2004, Niels Möller
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
C the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
C MA 02111-1307, USA.

C Register usage
define(<SA>,<%eax>)
define(<SB>,<%ebx>)
define(<SC>,<%ecx>)
define(<SD>,<%edx>)
define(<SE>,<%ebp>)
define(<DATA>,<%esp>)
define(<T1>,<%edi>)
define(<T2>,<%esi>)				C  Used by SWAP
	
C Constants
define(<K1VALUE>, <0x5A827999>)		C  Rounds  0-19
define(<K2VALUE>, <0x6ED9EBA1>)		C  Rounds 20-39
define(<K3VALUE>, <0x8F1BBCDC>)		C  Rounds 40-59
define(<K4VALUE>, <0xCA62C1D6>)		C  Rounds 60-79
	
C Reads the input via T2 into register, byteswaps it, and stores it in the DATA array.
C SWAP(index, register)
define(<SWAP>, <
	movl	OFFSET($1)(T2), $2
	bswap	$2
	movl	$2, OFFSET($1) (DATA)
>)dnl

C The f functions,
C
C  f1(x,y,z) = z ^ (x & (y ^ z))
C  f2(x,y,z) = x ^ y ^ z
C  f3(x,y,z) = (x & (y ^ z)) + (y & z)
C  f4 = f2

C This form for f3 was suggested by George Spelvin. The terms can be
C added into the result one at a time, saving one temporary.

C The form of one sha1 round is
C
C   a' = e + a <<< 5 + f( b, c, d ) + k + w;
C   b' = a;
C   c' = b <<< 30;
C   d' = c;
C   e' = d;
C
C where <<< denotes rotation. We permute our variables, so that we
C instead get
C
C   e += a <<< 5 + f( b, c, d ) + k + w;
C   b <<<= 30

dnl ROUND_F1(a, b, c, d, e, i)
define(<ROUND_F1>, <
	mov	OFFSET(eval($6 % 16)) (DATA), T1
	xor	OFFSET(eval(($6 +  2) % 16)) (DATA), T1
	xor	OFFSET(eval(($6 +  8) % 16)) (DATA), T1
	xor	OFFSET(eval(($6 + 13) % 16)) (DATA), T1
	rol	<$>1, T1
	mov	T1, OFFSET(eval($6 % 16)) (DATA)
	mov	$4, T2
	xor	$3, T2
	and	$2, T2
	xor	$4, T2
	lea	K1VALUE (T1, T2), T2
	rol	<$>30, $2
	mov	$1, T1
	rol	<$>5, T1
	add	T1, $5
	add	T2, $5
>)

dnl ROUND_F1_NOEXP(a, b, c, d, e, i)
define(<ROUND_F1_NOEXP>, <
	mov	$4, T2
	xor	$3, T2
	mov	$1, T1
	and	$2, T2
	add	OFFSET($6) (DATA), $5
	xor	$4, T2
	add	T2, $5
	rol	<$>30, $2
	rol	<$>5, T1
	lea	K1VALUE (T1, $5), $5
>)

dnl ROUND_F2(a, b, c, d, e, i, k)
define(<ROUND_F2>, <
	mov	OFFSET(eval($6 % 16)) (DATA), T1
	xor	OFFSET(eval(($6 +  2) % 16)) (DATA), T1
	xor	OFFSET(eval(($6 +  8) % 16)) (DATA), T1
	xor	OFFSET(eval(($6 + 13) % 16)) (DATA), T1
	rol	<$>1, T1
	mov	T1, OFFSET(eval($6 % 16)) (DATA)
	mov	$4, T2
	xor	$3, T2
	xor	$2, T2
	lea	$7 (T1, T2), T2
	rol	<$>30, $2
	mov	$1, T1
	rol	<$>5, T1
	add	T1, $5
	add	T2, $5
>)

dnl ROUND_F3(a, b, c, d, e, i)
define(<ROUND_F3>, <
	mov	OFFSET(eval($6 % 16)) (DATA), T1
	xor	OFFSET(eval(($6 +  2) % 16)) (DATA), T1
	xor	OFFSET(eval(($6 +  8) % 16)) (DATA), T1
	xor	OFFSET(eval(($6 + 13) % 16)) (DATA), T1
	rol	<$>1, T1
	mov	T1, OFFSET(eval($6 % 16)) (DATA)
	mov	$4, T2
	and	$3, T2
	lea	K3VALUE (T1, T2), T1
	mov	$4, T2
	xor	$3, T2
	and	$2, T2
	add	T1, $5
	rol	<$>30, $2
	mov	$1, T1
	rol	<$>5, T1
	add	T1, $5
	add	T2, $5
>)

	.file "sha1-compress.asm"

	C _nettle_sha1_compress(uint32_t *state, uint8_t *data)
	
	.text
	ALIGN(4)
PROLOGUE(_nettle_sha1_compress)
	C save all registers that need to be saved
	C 			   88(%esp)  data
	C 			   84(%esp)  state
	C 			   80(%esp)  Return address
	pushl	%ebx		C  76(%esp)
	pushl	%ebp		C  72(%esp)
	pushl	%esi		C  68(%esp)
	pushl	%edi		C  64(%esp)

	subl	$64, %esp	C  %esp = W

	C Load and byteswap data
	movl	88(%esp), T2

	SWAP( 0, %eax) SWAP( 1, %ebx) SWAP( 2, %ecx) SWAP( 3, %edx)
	SWAP( 4, %eax) SWAP( 5, %ebx) SWAP( 6, %ecx) SWAP( 7, %edx)
	SWAP( 8, %eax) SWAP( 9, %ebx) SWAP(10, %ecx) SWAP(11, %edx)
	SWAP(12, %eax) SWAP(13, %ebx) SWAP(14, %ecx) SWAP(15, %edx)

	C load the state vector
	movl	84(%esp),T1
	movl	(T1),   SA
	movl	4(T1),  SB
	movl	8(T1),  SC
	movl	12(T1), SD
	movl	16(T1), SE

	ROUND_F1_NOEXP(SA, SB, SC, SD, SE,  0)
	ROUND_F1_NOEXP(SE, SA, SB, SC, SD,  1)
	ROUND_F1_NOEXP(SD, SE, SA, SB, SC,  2)
	ROUND_F1_NOEXP(SC, SD, SE, SA, SB,  3)
	ROUND_F1_NOEXP(SB, SC, SD, SE, SA,  4)

	ROUND_F1_NOEXP(SA, SB, SC, SD, SE,  5)
	ROUND_F1_NOEXP(SE, SA, SB, SC, SD,  6)
	ROUND_F1_NOEXP(SD, SE, SA, SB, SC,  7)
	ROUND_F1_NOEXP(SC, SD, SE, SA, SB,  8)
	ROUND_F1_NOEXP(SB, SC, SD, SE, SA,  9)

	ROUND_F1_NOEXP(SA, SB, SC, SD, SE, 10)
	ROUND_F1_NOEXP(SE, SA, SB, SC, SD, 11)
	ROUND_F1_NOEXP(SD, SE, SA, SB, SC, 12)
	ROUND_F1_NOEXP(SC, SD, SE, SA, SB, 13)
	ROUND_F1_NOEXP(SB, SC, SD, SE, SA, 14)

	ROUND_F1_NOEXP(SA, SB, SC, SD, SE, 15)
	ROUND_F1(SE, SA, SB, SC, SD, 16)
	ROUND_F1(SD, SE, SA, SB, SC, 17)
	ROUND_F1(SC, SD, SE, SA, SB, 18)
	ROUND_F1(SB, SC, SD, SE, SA, 19)

	ROUND_F2(SA, SB, SC, SD, SE, 20, K2VALUE)
	ROUND_F2(SE, SA, SB, SC, SD, 21, K2VALUE)
	ROUND_F2(SD, SE, SA, SB, SC, 22, K2VALUE)
	ROUND_F2(SC, SD, SE, SA, SB, 23, K2VALUE)
	ROUND_F2(SB, SC, SD, SE, SA, 24, K2VALUE)

	ROUND_F2(SA, SB, SC, SD, SE, 25, K2VALUE)
	ROUND_F2(SE, SA, SB, SC, SD, 26, K2VALUE)
	ROUND_F2(SD, SE, SA, SB, SC, 27, K2VALUE)
	ROUND_F2(SC, SD, SE, SA, SB, 28, K2VALUE)
	ROUND_F2(SB, SC, SD, SE, SA, 29, K2VALUE)

	ROUND_F2(SA, SB, SC, SD, SE, 30, K2VALUE)
	ROUND_F2(SE, SA, SB, SC, SD, 31, K2VALUE)
	ROUND_F2(SD, SE, SA, SB, SC, 32, K2VALUE)
	ROUND_F2(SC, SD, SE, SA, SB, 33, K2VALUE)
	ROUND_F2(SB, SC, SD, SE, SA, 34, K2VALUE)

	ROUND_F2(SA, SB, SC, SD, SE, 35, K2VALUE)
	ROUND_F2(SE, SA, SB, SC, SD, 36, K2VALUE)
	ROUND_F2(SD, SE, SA, SB, SC, 37, K2VALUE)
	ROUND_F2(SC, SD, SE, SA, SB, 38, K2VALUE)
	ROUND_F2(SB, SC, SD, SE, SA, 39, K2VALUE)

	ROUND_F3(SA, SB, SC, SD, SE, 40)
	ROUND_F3(SE, SA, SB, SC, SD, 41)
	ROUND_F3(SD, SE, SA, SB, SC, 42)
	ROUND_F3(SC, SD, SE, SA, SB, 43)
	ROUND_F3(SB, SC, SD, SE, SA, 44)

	ROUND_F3(SA, SB, SC, SD, SE, 45)
	ROUND_F3(SE, SA, SB, SC, SD, 46)
	ROUND_F3(SD, SE, SA, SB, SC, 47)
	ROUND_F3(SC, SD, SE, SA, SB, 48)
	ROUND_F3(SB, SC, SD, SE, SA, 49)

	ROUND_F3(SA, SB, SC, SD, SE, 50)
	ROUND_F3(SE, SA, SB, SC, SD, 51)
	ROUND_F3(SD, SE, SA, SB, SC, 52)
	ROUND_F3(SC, SD, SE, SA, SB, 53)
	ROUND_F3(SB, SC, SD, SE, SA, 54)

	ROUND_F3(SA, SB, SC, SD, SE, 55)
	ROUND_F3(SE, SA, SB, SC, SD, 56)
	ROUND_F3(SD, SE, SA, SB, SC, 57)
	ROUND_F3(SC, SD, SE, SA, SB, 58)
	ROUND_F3(SB, SC, SD, SE, SA, 59)

	ROUND_F2(SA, SB, SC, SD, SE, 60, K4VALUE)
	ROUND_F2(SE, SA, SB, SC, SD, 61, K4VALUE)
	ROUND_F2(SD, SE, SA, SB, SC, 62, K4VALUE)
	ROUND_F2(SC, SD, SE, SA, SB, 63, K4VALUE)
	ROUND_F2(SB, SC, SD, SE, SA, 64, K4VALUE)

	ROUND_F2(SA, SB, SC, SD, SE, 65, K4VALUE)
	ROUND_F2(SE, SA, SB, SC, SD, 66, K4VALUE)
	ROUND_F2(SD, SE, SA, SB, SC, 67, K4VALUE)
	ROUND_F2(SC, SD, SE, SA, SB, 68, K4VALUE)
	ROUND_F2(SB, SC, SD, SE, SA, 69, K4VALUE)

	ROUND_F2(SA, SB, SC, SD, SE, 70, K4VALUE)
	ROUND_F2(SE, SA, SB, SC, SD, 71, K4VALUE)
	ROUND_F2(SD, SE, SA, SB, SC, 72, K4VALUE)
	ROUND_F2(SC, SD, SE, SA, SB, 73, K4VALUE)
	ROUND_F2(SB, SC, SD, SE, SA, 74, K4VALUE)

	ROUND_F2(SA, SB, SC, SD, SE, 75, K4VALUE)
	ROUND_F2(SE, SA, SB, SC, SD, 76, K4VALUE)
	ROUND_F2(SD, SE, SA, SB, SC, 77, K4VALUE)
	ROUND_F2(SC, SD, SE, SA, SB, 78, K4VALUE)
	ROUND_F2(SB, SC, SD, SE, SA, 79, K4VALUE)

	C Update the state vector
	movl	84(%esp),T1
	addl	SA, (T1) 
	addl	SB, 4(T1) 
	addl	SC, 8(T1) 
	addl	SD, 12(T1) 
	addl	SE, 16(T1)

	addl	$64, %esp
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret
EPILOGUE(_nettle_sha1_compress)
