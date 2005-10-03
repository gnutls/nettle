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
define(<TMP>,<%edi>)
define(<TMP2>,<%esi>)				C  Used by SWAP and F3

define(<TMP3>, <64(%esp)>)dnl
C Constants
define(<K1VALUE>, <<$>0x5A827999>)		C  Rounds  0-19
define(<K2VALUE>, <<$>0x6ED9EBA1>)		C  Rounds 20-39
define(<K3VALUE>, <<$>0x8F1BBCDC>)		C  Rounds 40-59
define(<K4VALUE>, <<$>0xCA62C1D6>)		C  Rounds 60-79

C OFFSET(i)
C Expands to 4*i, or to the empty string if i is zero
define(<OFFSET>, <ifelse($1,0,,eval(4*$1))>)
	
C Reads the input via TMP2 into register, byteswaps it, and stores it in the DATA array.
C SWAP(index, register)
define(<SWAP>, <
	movl	OFFSET($1)(TMP2), $2
	bswap	$2
	movl	$2, OFFSET($1) (DATA)
>)dnl

C expand(i) is the expansion function
C
C   W[i] = (W[i - 16] ^ W[i - 14] ^ W[i - 8] ^ W[i - 3]) <<< 1
C
C where W[i] is stored in DATA[i & 15].
C
C Result is stored back in W[i], and also left in TMP, the only
C register that is used.
define(<EXPAND>, <
	movl	OFFSET(eval($1 & 15)) (DATA), TMP
	xorl	OFFSET(eval(($1 +  2) & 15)) (DATA), TMP
	xorl	OFFSET(eval(($1 +  8) & 15)) (DATA), TMP
	xorl	OFFSET(eval(($1 + 13) & 15)) (DATA), TMP
	roll	<$>1, TMP
	movl	TMP, OFFSET(eval($1 & 15)) (DATA)>)dnl
define(<NOEXPAND>, <OFFSET($1) (DATA)>)dnl

C The f functions,
C
C  f1(x,y,z) = z ^ (x & (y ^ z))
C  f2(x,y,z) = x ^ y ^ z
C  f3(x,y,z) = (x & y) | (z & (x | y))
C  f4 = f2
C
C The macro Fk(x,y,z) computes = fk(x,y,z). 
C Result is left in TMP.
define(<F1>, <
	movl	$3, TMP
	xorl	$2, TMP
	andl	$1, TMP
	xorl	$3, TMP>)dnl
define(<F2>, <
	movl	$1, TMP
	xorl	$2, TMP
	xorl	$3, TMP>)dnl
C Uses TMP2
define(<F3>, <
	movl	$1, TMP2
	andl	$2, TMP2
	movl	$1, TMP
	orl	$2, TMP
	andl	$3, TMP
	orl	TMP2, TMP>)dnl

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
C ROUND(a,b,c,d,e,f,k,w)
define(<ROUND>, <
	addl	$7, $5
	addl	ifelse($8,,TMP,$8), $5
	$6($2,$3,$4)
	addl	TMP, $5

C Using the TMP register can be avoided, by rotating $1 in place,
C adding, and then rotating back.
	movl	$1, TMP
	roll	<$>5, TMP
	addl	TMP, $5
	roll	<$>30, $2>)dnl

	.file "sha1-compress.asm"

	C sha1_compress(uint32_t *state, uint8_t *data)
	
	.text
	.align 16
	.globl C_NAME(_nettle_sha1_compress)
	.type  C_NAME(_nettle_sha1_compress),@function
C_NAME(_nettle_sha1_compress):
	C save all registers that need to be saved
	
	pushl	%ebx		C  80(%esp)
	pushl	%ebp		C  76(%esp)
	pushl	%esi		C  72(%esp)
	pushl	%edi		C  68(%esp)

	subl	$68, %esp	C  %esp = W

	C Load and byteswap data
	movl	92(%esp), TMP2

	SWAP( 0, %eax) SWAP( 1, %ebx) SWAP( 2, %ecx) SWAP( 3, %edx)
	SWAP( 4, %eax) SWAP( 5, %ebx) SWAP( 6, %ecx) SWAP( 7, %edx)
	SWAP( 8, %eax) SWAP( 9, %ebx) SWAP(10, %ecx) SWAP(11, %edx)
	SWAP(12, %eax) SWAP(13, %ebx) SWAP(14, %ecx) SWAP(15, %edx)

	C load the state vector
	movl	88(%esp),TMP
	movl	(TMP),   SA
	movl	4(TMP),  SB
	movl	8(TMP),  SC
	movl	12(TMP), SD
	movl	16(TMP), SE

	movl	K1VALUE, TMP2	
	ROUND(SA, SB, SC, SD, SE, <F1>, TMP2, NOEXPAND( 0))
	ROUND(SE, SA, SB, SC, SD, <F1>, TMP2, NOEXPAND( 1))
	ROUND(SD, SE, SA, SB, SC, <F1>, TMP2, NOEXPAND( 2))
	ROUND(SC, SD, SE, SA, SB, <F1>, TMP2, NOEXPAND( 3))
	ROUND(SB, SC, SD, SE, SA, <F1>, TMP2, NOEXPAND( 4))

	ROUND(SA, SB, SC, SD, SE, <F1>, TMP2, NOEXPAND( 5))
	ROUND(SE, SA, SB, SC, SD, <F1>, TMP2, NOEXPAND( 6))
	ROUND(SD, SE, SA, SB, SC, <F1>, TMP2, NOEXPAND( 7))
	ROUND(SC, SD, SE, SA, SB, <F1>, TMP2, NOEXPAND( 8))
	ROUND(SB, SC, SD, SE, SA, <F1>, TMP2, NOEXPAND( 9))

	ROUND(SA, SB, SC, SD, SE, <F1>, TMP2, NOEXPAND(10))
	ROUND(SE, SA, SB, SC, SD, <F1>, TMP2, NOEXPAND(11))
	ROUND(SD, SE, SA, SB, SC, <F1>, TMP2, NOEXPAND(12))
	ROUND(SC, SD, SE, SA, SB, <F1>, TMP2, NOEXPAND(13))
	ROUND(SB, SC, SD, SE, SA, <F1>, TMP2, NOEXPAND(14))

	ROUND(SA, SB, SC, SD, SE, <F1>, TMP2, NOEXPAND(15))
	EXPAND(16) ROUND(SE, SA, SB, SC, SD, <F1>, TMP2)
	EXPAND(17) ROUND(SD, SE, SA, SB, SC, <F1>, TMP2)
	EXPAND(18) ROUND(SC, SD, SE, SA, SB, <F1>, TMP2)
	EXPAND(19) ROUND(SB, SC, SD, SE, SA, <F1>, TMP2)

	C TMP2 is free to use in these rounds
	movl	K2VALUE, TMP2
	EXPAND(20) ROUND(SA, SB, SC, SD, SE, <F2>, TMP2)
	EXPAND(21) ROUND(SE, SA, SB, SC, SD, <F2>, TMP2)
	EXPAND(22) ROUND(SD, SE, SA, SB, SC, <F2>, TMP2)
	EXPAND(23) ROUND(SC, SD, SE, SA, SB, <F2>, TMP2)
	EXPAND(24) ROUND(SB, SC, SD, SE, SA, <F2>, TMP2)

	EXPAND(25) ROUND(SA, SB, SC, SD, SE, <F2>, TMP2)
	EXPAND(26) ROUND(SE, SA, SB, SC, SD, <F2>, TMP2)
	EXPAND(27) ROUND(SD, SE, SA, SB, SC, <F2>, TMP2)
	EXPAND(28) ROUND(SC, SD, SE, SA, SB, <F2>, TMP2)
	EXPAND(29) ROUND(SB, SC, SD, SE, SA, <F2>, TMP2)

	EXPAND(30) ROUND(SA, SB, SC, SD, SE, <F2>, TMP2)
	EXPAND(31) ROUND(SE, SA, SB, SC, SD, <F2>, TMP2)
	EXPAND(32) ROUND(SD, SE, SA, SB, SC, <F2>, TMP2)
	EXPAND(33) ROUND(SC, SD, SE, SA, SB, <F2>, TMP2)
	EXPAND(34) ROUND(SB, SC, SD, SE, SA, <F2>, TMP2)

	EXPAND(35) ROUND(SA, SB, SC, SD, SE, <F2>, TMP2)
	EXPAND(36) ROUND(SE, SA, SB, SC, SD, <F2>, TMP2)
	EXPAND(37) ROUND(SD, SE, SA, SB, SC, <F2>, TMP2)
	EXPAND(38) ROUND(SC, SD, SE, SA, SB, <F2>, TMP2)
	EXPAND(39) ROUND(SB, SC, SD, SE, SA, <F2>, TMP2)

	C We have to put this constant on the stack
	movl	K3VALUE, TMP3
	EXPAND(40) ROUND(SA, SB, SC, SD, SE, <F3>, TMP3)
	EXPAND(41) ROUND(SE, SA, SB, SC, SD, <F3>, TMP3)
	EXPAND(42) ROUND(SD, SE, SA, SB, SC, <F3>, TMP3)
	EXPAND(43) ROUND(SC, SD, SE, SA, SB, <F3>, TMP3)
	EXPAND(44) ROUND(SB, SC, SD, SE, SA, <F3>, TMP3)

	EXPAND(45) ROUND(SA, SB, SC, SD, SE, <F3>, TMP3)
	EXPAND(46) ROUND(SE, SA, SB, SC, SD, <F3>, TMP3)
	EXPAND(47) ROUND(SD, SE, SA, SB, SC, <F3>, TMP3)
	EXPAND(48) ROUND(SC, SD, SE, SA, SB, <F3>, TMP3)
	EXPAND(49) ROUND(SB, SC, SD, SE, SA, <F3>, TMP3)

	EXPAND(50) ROUND(SA, SB, SC, SD, SE, <F3>, TMP3)
	EXPAND(51) ROUND(SE, SA, SB, SC, SD, <F3>, TMP3)
	EXPAND(52) ROUND(SD, SE, SA, SB, SC, <F3>, TMP3)
	EXPAND(53) ROUND(SC, SD, SE, SA, SB, <F3>, TMP3)
	EXPAND(54) ROUND(SB, SC, SD, SE, SA, <F3>, TMP3)

	EXPAND(55) ROUND(SA, SB, SC, SD, SE, <F3>, TMP3)
	EXPAND(56) ROUND(SE, SA, SB, SC, SD, <F3>, TMP3)
	EXPAND(57) ROUND(SD, SE, SA, SB, SC, <F3>, TMP3)
	EXPAND(58) ROUND(SC, SD, SE, SA, SB, <F3>, TMP3)
	EXPAND(59) ROUND(SB, SC, SD, SE, SA, <F3>, TMP3)

	movl	K4VALUE, TMP2
	EXPAND(60) ROUND(SA, SB, SC, SD, SE, <F2>, TMP2)
	EXPAND(61) ROUND(SE, SA, SB, SC, SD, <F2>, TMP2)
	EXPAND(62) ROUND(SD, SE, SA, SB, SC, <F2>, TMP2)
	EXPAND(63) ROUND(SC, SD, SE, SA, SB, <F2>, TMP2)
	EXPAND(64) ROUND(SB, SC, SD, SE, SA, <F2>, TMP2)

	EXPAND(65) ROUND(SA, SB, SC, SD, SE, <F2>, TMP2)
	EXPAND(66) ROUND(SE, SA, SB, SC, SD, <F2>, TMP2)
	EXPAND(67) ROUND(SD, SE, SA, SB, SC, <F2>, TMP2)
	EXPAND(68) ROUND(SC, SD, SE, SA, SB, <F2>, TMP2)
	EXPAND(69) ROUND(SB, SC, SD, SE, SA, <F2>, TMP2)

	EXPAND(70) ROUND(SA, SB, SC, SD, SE, <F2>, TMP2)
	EXPAND(71) ROUND(SE, SA, SB, SC, SD, <F2>, TMP2)
	EXPAND(72) ROUND(SD, SE, SA, SB, SC, <F2>, TMP2)
	EXPAND(73) ROUND(SC, SD, SE, SA, SB, <F2>, TMP2)
	EXPAND(74) ROUND(SB, SC, SD, SE, SA, <F2>, TMP2)

	EXPAND(75) ROUND(SA, SB, SC, SD, SE, <F2>, TMP2)
	EXPAND(76) ROUND(SE, SA, SB, SC, SD, <F2>, TMP2)
	EXPAND(77) ROUND(SD, SE, SA, SB, SC, <F2>, TMP2)
	EXPAND(78) ROUND(SC, SD, SE, SA, SB, <F2>, TMP2)
	EXPAND(79) ROUND(SB, SC, SD, SE, SA, <F2>, TMP2)

	C Update the state vector
	movl	88(%esp),TMP
	addl	SA, (TMP) 
	addl	SB, 4(TMP) 
	addl	SC, 8(TMP) 
	addl	SD, 12(TMP) 
	addl	SE, 16(TMP)

	addl	$68, %esp
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret

.Leord:
	.size	_nettle_sha1_compress,.Leord-_nettle_sha1_compress

C  It's possible to shave of half of the stores to tmp in the evaluation of f3,
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
