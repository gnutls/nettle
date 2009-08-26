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
define(<KVALUE>,<%esi>)				C  Used by rounds
	
C Constants
define(<K1VALUE>, <0x5A827999>)		C  Rounds  0-19
define(<K2VALUE>, <0x6ED9EBA1>)		C  Rounds 20-39
define(<K3VALUE>, <<$>0x8F1BBCDC>)		C  Rounds 40-59
define(<K4VALUE>, <<$>0xCA62C1D6>)		C  Rounds 60-79
	
C Reads the input via T2 into register, byteswaps it, and stores it in the DATA array.
C SWAP(index, register)
define(<SWAP>, <
	movl	OFFSET($1)(T2), $2
	bswap	$2
	movl	$2, OFFSET($1) (DATA)
>)dnl

C expand(i) is the expansion function
C
C   W[i] = (W[i - 16] ^ W[i - 14] ^ W[i - 8] ^ W[i - 3]) <<< 1
C
C where W[i] is stored in DATA[i mod 16].
C
C Result is stored back in W[i], and also left in T1, the only
C register that is used.
define(<EXPAND>, <
	movl	OFFSET(eval($1 % 16)) (DATA), T1
	xorl	OFFSET(eval(($1 +  2) % 16)) (DATA), T1
	xorl	OFFSET(eval(($1 +  8) % 16)) (DATA), T1
	xorl	OFFSET(eval(($1 + 13) % 16)) (DATA), T1
	roll	<$>1, T1
	movl	T1, OFFSET(eval($1 % 16)) (DATA)>)dnl
define(<NOEXPAND>, <OFFSET($1) (DATA)>)dnl

C The f functions,
C
C  f1(x,y,z) = z ^ (x & (y ^ z))
C  f2(x,y,z) = x ^ y ^ z
C  f3(x,y,z) = (x & y) | (z & (x | y))
C  f4 = f2
C
C The macro Fk(x,y,z) computes = fk(x,y,z). 
C Result is left in T1.
define(<F1>, <
	movl	$3, T1
	xorl	$2, T1
	andl	$1, T1
	xorl	$3, T1>)dnl

define(<F2>, <
	movl	$1, T1
	xorl	$2, T1
	xorl	$3, T1>)dnl

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
C
C ROUND(a,b,c,d,e,f,w)
define(<ROUND>, <
	addl	KVALUE, $5
	addl	ifelse($7,,T1,$7), $5
	$6($2,$3,$4)
	addl	T1, $5

C Using the T1 register can be avoided, by rotating $1 in place,
C adding, and then rotating back.
	movl	$1, T1
	roll	<$>5, T1
	addl	T1, $5
	C roll	<$>5, $1
	C addl	$1, $5
	C rorl	<$>5, $1
	roll	<$>30, $2>)dnl

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

define(<ROUND_F1_NOEXP>, <
	mov	$4, T2
	xor	$3, T2
	and	$2, T2
	xor	$4, T2
	add	OFFSET(eval($6 % 16)) (DATA), T2
	rol	<$>30, $2
	mov	$1, T1
	rol	<$>5, T1
	lea	K1VALUE (T1, $5), $5
	add	T2, $5
>)

dnl ROUND_F2(a, b, c, d, e, i)
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
	lea	K2VALUE (T1, T2), T2
	rol	<$>30, $2
	mov	$1, T1
	rol	<$>5, T1
	add	T1, $5
	add	T2, $5
>)

C As suggested by George Spelvin, write the F3 function as
C (x&y) | (y&z) | (x&z) == (x & (y^z)) + (y&z). Then, we can compute
C and add each term to e, using a single temporary.
	
C ROUND_F3(a,b,c,d,e,w)
define(<ROUND_F3>, <
	addl	KVALUE, $5
	addl	T1, $5

	movl	$3, T1
	andl	$4, T1
	addl	T1, $5
	movl	$3, T1
	xorl	$4, T1
	andl	$2, T1
	addl	T1, $5

C Using the T1 register can be avoided, by rotating $1 in place,
C adding, and then rotating back.
	movl	$1, T1
	roll	<$>5, T1
	addl	T1, $5
	C roll	<$>5, $1
	C addl	$1, $5
	C rorl	<$>5, $1
	roll	<$>30, $2>)dnl


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

	C FIXME: Trim to 64
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

	movl	$ K1VALUE, KVALUE
	ROUND(SA, SB, SC, SD, SE, <F1>, NOEXPAND( 0))
	ROUND(SE, SA, SB, SC, SD, <F1>, NOEXPAND( 1))
	ROUND(SD, SE, SA, SB, SC, <F1>, NOEXPAND( 2))
	ROUND(SC, SD, SE, SA, SB, <F1>, NOEXPAND( 3))
	ROUND(SB, SC, SD, SE, SA, <F1>, NOEXPAND( 4))

	ROUND(SA, SB, SC, SD, SE, <F1>, NOEXPAND( 5))
	ROUND(SE, SA, SB, SC, SD, <F1>, NOEXPAND( 6))
	ROUND(SD, SE, SA, SB, SC, <F1>, NOEXPAND( 7))
	ROUND(SC, SD, SE, SA, SB, <F1>, NOEXPAND( 8))
	ROUND(SB, SC, SD, SE, SA, <F1>, NOEXPAND( 9))

	ROUND(SA, SB, SC, SD, SE, <F1>, NOEXPAND(10))
	ROUND(SE, SA, SB, SC, SD, <F1>, NOEXPAND(11))
	ROUND(SD, SE, SA, SB, SC, <F1>, NOEXPAND(12))
	ROUND(SC, SD, SE, SA, SB, <F1>, NOEXPAND(13))
	ROUND(SB, SC, SD, SE, SA, <F1>, NOEXPAND(14))

	ROUND(SA, SB, SC, SD, SE, <F1>, NOEXPAND(15))
	EXPAND(16) ROUND(SE, SA, SB, SC, SD, <F1>)
	EXPAND(17) ROUND(SD, SE, SA, SB, SC, <F1>)
	EXPAND(18) ROUND(SC, SD, SE, SA, SB, <F1>)
	EXPAND(19) ROUND(SB, SC, SD, SE, SA, <F1>)

	C T2 is free to use in these rounds
	C movl	K2VALUE, KVALUE
	ROUND_F2(SA, SB, SC, SD, SE, 20)
	ROUND_F2(SE, SA, SB, SC, SD, 21)
	ROUND_F2(SD, SE, SA, SB, SC, 22)
	ROUND_F2(SC, SD, SE, SA, SB, 23)
	ROUND_F2(SB, SC, SD, SE, SA, 24)

	ROUND_F2(SA, SB, SC, SD, SE, 25)
	ROUND_F2(SE, SA, SB, SC, SD, 26)
	ROUND_F2(SD, SE, SA, SB, SC, 27)
	ROUND_F2(SC, SD, SE, SA, SB, 28)
	ROUND_F2(SB, SC, SD, SE, SA, 29)

	ROUND_F2(SA, SB, SC, SD, SE, 30)
	ROUND_F2(SE, SA, SB, SC, SD, 31)
	ROUND_F2(SD, SE, SA, SB, SC, 32)
	ROUND_F2(SC, SD, SE, SA, SB, 33)
	ROUND_F2(SB, SC, SD, SE, SA, 34)

	ROUND_F2(SA, SB, SC, SD, SE, 35)
	ROUND_F2(SE, SA, SB, SC, SD, 36)
	ROUND_F2(SD, SE, SA, SB, SC, 37)
	ROUND_F2(SC, SD, SE, SA, SB, 38)
	ROUND_F2(SB, SC, SD, SE, SA, 39)

	C We have to put this constant on the stack
	movl	K3VALUE, KVALUE
	EXPAND(40) ROUND_F3(SA, SB, SC, SD, SE)
	EXPAND(41) ROUND_F3(SE, SA, SB, SC, SD)
	EXPAND(42) ROUND_F3(SD, SE, SA, SB, SC)
	EXPAND(43) ROUND_F3(SC, SD, SE, SA, SB)
	EXPAND(44) ROUND_F3(SB, SC, SD, SE, SA)

	EXPAND(45) ROUND_F3(SA, SB, SC, SD, SE)
	EXPAND(46) ROUND_F3(SE, SA, SB, SC, SD)
	EXPAND(47) ROUND_F3(SD, SE, SA, SB, SC)
	EXPAND(48) ROUND_F3(SC, SD, SE, SA, SB)
	EXPAND(49) ROUND_F3(SB, SC, SD, SE, SA)

	EXPAND(50) ROUND_F3(SA, SB, SC, SD, SE)
	EXPAND(51) ROUND_F3(SE, SA, SB, SC, SD)
	EXPAND(52) ROUND_F3(SD, SE, SA, SB, SC)
	EXPAND(53) ROUND_F3(SC, SD, SE, SA, SB)
	EXPAND(54) ROUND_F3(SB, SC, SD, SE, SA)

	EXPAND(55) ROUND_F3(SA, SB, SC, SD, SE)
	EXPAND(56) ROUND_F3(SE, SA, SB, SC, SD)
	EXPAND(57) ROUND_F3(SD, SE, SA, SB, SC)
	EXPAND(58) ROUND_F3(SC, SD, SE, SA, SB)
	EXPAND(59) ROUND_F3(SB, SC, SD, SE, SA)

	movl	K4VALUE, KVALUE
	EXPAND(60) ROUND(SA, SB, SC, SD, SE, <F2>)
	EXPAND(61) ROUND(SE, SA, SB, SC, SD, <F2>)
	EXPAND(62) ROUND(SD, SE, SA, SB, SC, <F2>)
	EXPAND(63) ROUND(SC, SD, SE, SA, SB, <F2>)
	EXPAND(64) ROUND(SB, SC, SD, SE, SA, <F2>)

	EXPAND(65) ROUND(SA, SB, SC, SD, SE, <F2>)
	EXPAND(66) ROUND(SE, SA, SB, SC, SD, <F2>)
	EXPAND(67) ROUND(SD, SE, SA, SB, SC, <F2>)
	EXPAND(68) ROUND(SC, SD, SE, SA, SB, <F2>)
	EXPAND(69) ROUND(SB, SC, SD, SE, SA, <F2>)

	EXPAND(70) ROUND(SA, SB, SC, SD, SE, <F2>)
	EXPAND(71) ROUND(SE, SA, SB, SC, SD, <F2>)
	EXPAND(72) ROUND(SD, SE, SA, SB, SC, <F2>)
	EXPAND(73) ROUND(SC, SD, SE, SA, SB, <F2>)
	EXPAND(74) ROUND(SB, SC, SD, SE, SA, <F2>)

	EXPAND(75) ROUND(SA, SB, SC, SD, SE, <F2>)
	EXPAND(76) ROUND(SE, SA, SB, SC, SD, <F2>)
	EXPAND(77) ROUND(SD, SE, SA, SB, SC, <F2>)
	EXPAND(78) ROUND(SC, SD, SE, SA, SB, <F2>)
	EXPAND(79) ROUND(SB, SC, SD, SE, SA, <F2>)

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

C George Spelvin also suggested using lea, with an immediate offset
C for the magic constants. This frees one register, which can be used
C for loosen up dependencies and to more operations in parallel. For
C example, take the rounds involving f2, the simplest round function.
C Currently, we have
C 
C 	movl	16(%esp), T1
C 	xorl	24(%esp), T1
C 	xorl	48(%esp), T1
C 	xorl	4(%esp), T1
C 	roll	$1, T1
C 	movl	T1, 16(%esp)
C 	addl	KVALUE, SE	C 0
C 	addl	T1, SE		C 1
C 	movl	SB, T1		C 0
C 	xorl	SC, T1		C 1
C 	xorl	SD, T1		C 2
C 	addl	T1, SE		C 3
C 	movl	SA, T1		C 0
C 	roll	$5, T1		C 1
C 	addl	T1, SE		C 4
C 	roll	$30, SB		C 0
	
C These 16 instructions could be executed in 5.33 cycles if there were
C no dependencies. The crucial dependencies are from (previous) SE to
C use SA, and (previous) result SB to use SC. (What does this say
C about recurrency chain? Ought to unroll 5 times to see it).

C It would be preferable to accumulate the terms in two or more
C registers, to make dependencies shallower. Something like

C	...expand, put data in W
C	movl	SD, T1			C 0
C	leal	K1VALUE(SE, W), SE	C 0
C	movl	SA, T2		C 0
C	xorl	SC, T1			C 1
C	roll	$5, T2		C 1
C 	xorl	SB, T1			C 2
C	addl	T2, T1		C 3
C	addl	T1, SE			C 4
C a + b + c + d + e = ((((a + b) + c) + d) + e), latency 4
C a + b + c + d + e = ((a + b) + c) + (d + e)
C the out-of-order execution. Next iteration
C
C 	...expand...
C 	roll	$1, T1		C 4
C 	movl	T1, 16(%esp)	C 5
C 	addl	KVALUE, SD	C 0
C 	addl	T1, SD		C 5
C 	movl	SA, T1		C 0
C 	xorl	SB, T1		C 1
C 	xorl	SC, T1		C 2
C 	addl	T1, SD		C 6
C 	movl	SE, T1		C 8
C 	roll	$5, T1		C 9
C 	addl	T1, SD		C 7
C 	roll	$30, SA		C 0
C
C Lets look at the latency. Next iteration will operate on (E, A, B, C, D), so we have recurrencies:

C from result SA to use of SE (none, SA not modified)
C from result of SB to use of SA, result of SC to use of SB

C It's possible to shave of half of the stores to tmp in the evaluation of f3,
C  although it's probably not worth the effort. This is the trick: 
C  
C  round(a,b,c,d,e,f,k) modifies only b,e.
C  
C  round(a,b,c,d,e,f3,k)
C  round(e,a,b,c,d,f3,k)
C  
C  ; f3(b,c,d) = (b & c) | (d & (b | c))
C  
C    movl b, tmp
C    andl c, tmp
C    movl tmp, tmp2
C    movl b, tmp
C    orl  c, tmp
C    andl d, tmp
C    orl tmp2, tmp
C  
C  and corresponding code for f3(a,b,c)
C  
C  Use the register allocated for c as a temporary?
C  
C    movl c, tmp2
C  ; f3(b,c,d) = (b & c) | (d & (b | c))
C    movl b, tmp
C    orl  c, tmp
C    andl b, c
C    andl d, tmp
C    orl  c, tmp
C  
C  ; f3(a,b,c) = (a & b) | (c & (a | b))
C    movl b, tmp
C    andl a, tmp
C    movl a, c
C    orl  b, c
C    andl tmp2, c
C    orl  c, tmp
C  
C    movl tmp2, c
C  
C  Before: 14 instr, 2 store, 2 load
C  After: 13 instr, 1 store, 2 load
C  
C  Final load can be folded into the next round,
C  
C  round(d,e,a,b,c,f3,k)
C  
C    c += d <<< 5 + f(e, a, b) + k + w
C  
C  if we arrange to have w placed directly into the register
C  corresponding to w. That way we save one more instruction, total save
C  of two instructions, one of which is a store, per two rounds. For the
C  twenty rounds involving f3, that's 20 instructions, 10 of which are
C  stores, or about 1.5 %.
