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
define(<DATA>,<%esi>)
define(<TMP>,<%edi>)
C Extra temporary needed by F3. Can we get rid of it?
define(<TMP2>,<(%esp)>)
define(<K>, <4(%esp)>)dnl
C Constants
define(<K1VALUE>, <<$>0x5A827999>)		C  Rounds  0-19
define(<K2VALUE>, <<$>0x6ED9EBA1>)		C  Rounds 20-39
define(<K3VALUE>, <<$>0x8F1BBCDC>)		C  Rounds 40-59
define(<K4VALUE>, <<$>0xCA62C1D6>)		C  Rounds 60-79
	
C expand(i) is the expansion function
C
C   W[i] = (W[i - 16] ^ W[i - 14] ^ W[i - 8] ^ W[i - 3]) <<< 1
C
C where W[i] is stored in DATA[i & 15].
C
C Result is stored back in W[i], and also left in TMP, the only
C register that is used.
define(<EXPAND>, <
	movl	eval(4 *        ($1 & 15)) (DATA), TMP
	xorl	eval(4 * (($1 +  2) & 15)) (DATA), TMP
	xorl	eval(4 * (($1 +  8) & 15)) (DATA), TMP
	xorl	eval(4 * (($1 + 13) & 15)) (DATA), TMP
	roll	<$>1, TMP
	movl	TMP, eval(4 * ($1 & 15)) (DATA)	
>)dnl
define(<NOEXPAND>, <eval(4 * ($1 & 15)) (DATA)>)dnl
C The f functions,
C
C  f1(x,y,z) = z ^ (x & (y ^ z))
C  f2(x,y,z) = x ^ y ^ z
C  f3(x,y,z) = (x & y) | (z & (x | y))
C  f4 = f2
C
C The macro Fk(x,y,z) computes = fk(x,y,z). 
C Result is left in TMP. May the TMP2 stackslot.
define(<F1>, <
	movl	$3, TMP
	xorl	$2, TMP
	andl	$1, TMP
	xorl	$3, TMP
>)dnl
define(<F2>, <
	movl	$1, TMP
	xorl	$2, TMP
	xorl	$3, TMP
>)dnl
C We have one register too little. Can this be rewritten so we don't need the stack?
define(<F3>, <
	movl	$1, TMP
	andl	$2, TMP
	movl	TMP, TMP2
	movl	$1, TMP
	orl	$2, TMP
	andl	$3, TMP
	orl	TMP2, TMP
>)dnl
C The form of the sha1 subround is
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
C round(a,b,c,d,e,f,w)
define(<round>, <
	addl	K, $5
	addl	$7, $5
	$6($2,$3,$4)
	addl	TMP, $5
	movl	$1, TMP
	roll	<$>5, TMP
	addl	TMP, $5
	roll	<$>30, $2
>)dnl

	.file "sha1-compress.asm"

	C sha1_compress(uint32_t *state, uint32_t *data)
	
	.text
	.align 16
	.globl _nettle_sha1_compress
	.type  _nettle_sha1_compress,@function
_nettle_sha1_compress:
	C save all registers that need to be saved
	
	pushl	%ebx		C  20(%esp)
	pushl	%ebp		C  16(%esp)
	pushl	%esi		C  12(%esp)
	pushl	%edi		C  8(%esp)

	pushl	K1VALUE		C  4(%esp)	
	subl	$4, %esp	C  0(%esp) = TMP

	C load the state vector
	movl	28(%esp),TMP
	movl	(TMP),   SA
	movl	4(TMP),  SB
	movl	8(TMP),  SC
	movl	12(TMP), SD
	movl	16(TMP), SE

	movl	32(%esp), DATA

	round(SA, SB, SC, SD, SE, <F1>, NOEXPAND( 0))
	round(SE, SA, SB, SC, SD, <F1>, NOEXPAND( 1))
	round(SD, SE, SA, SB, SC, <F1>, NOEXPAND( 2))
	round(SC, SD, SE, SA, SB, <F1>, NOEXPAND( 3))
	round(SB, SC, SD, SE, SA, <F1>, NOEXPAND( 4))

	round(SA, SB, SC, SD, SE, <F1>, NOEXPAND( 5))
	round(SE, SA, SB, SC, SD, <F1>, NOEXPAND( 6))
	round(SD, SE, SA, SB, SC, <F1>, NOEXPAND( 7))
	round(SC, SD, SE, SA, SB, <F1>, NOEXPAND( 8))
	round(SB, SC, SD, SE, SA, <F1>, NOEXPAND( 9))

	round(SA, SB, SC, SD, SE, <F1>, NOEXPAND(10))
	round(SE, SA, SB, SC, SD, <F1>, NOEXPAND(11))
	round(SD, SE, SA, SB, SC, <F1>, NOEXPAND(12))
	round(SC, SD, SE, SA, SB, <F1>, NOEXPAND(13))
	round(SB, SC, SD, SE, SA, <F1>, NOEXPAND(14))

		   round(SA, SB, SC, SD, SE, <F1>, NOEXPAND(15))
	EXPAND(16) round(SE, SA, SB, SC, SD, <F1>, TMP)
	EXPAND(17) round(SD, SE, SA, SB, SC, <F1>, TMP)
	EXPAND(18) round(SC, SD, SE, SA, SB, <F1>, TMP)
	EXPAND(19) round(SB, SC, SD, SE, SA, <F1>, TMP)

	movl	K2VALUE, K
	EXPAND(20) round(SA, SB, SC, SD, SE, <F2>, TMP)
	EXPAND(21) round(SE, SA, SB, SC, SD, <F2>, TMP)
	EXPAND(22) round(SD, SE, SA, SB, SC, <F2>, TMP)
	EXPAND(23) round(SC, SD, SE, SA, SB, <F2>, TMP)
	EXPAND(24) round(SB, SC, SD, SE, SA, <F2>, TMP)

	EXPAND(25) round(SA, SB, SC, SD, SE, <F2>, TMP)
	EXPAND(26) round(SE, SA, SB, SC, SD, <F2>, TMP)
	EXPAND(27) round(SD, SE, SA, SB, SC, <F2>, TMP)
	EXPAND(28) round(SC, SD, SE, SA, SB, <F2>, TMP)
	EXPAND(29) round(SB, SC, SD, SE, SA, <F2>, TMP)

	EXPAND(30) round(SA, SB, SC, SD, SE, <F2>, TMP)
	EXPAND(31) round(SE, SA, SB, SC, SD, <F2>, TMP)
	EXPAND(32) round(SD, SE, SA, SB, SC, <F2>, TMP)
	EXPAND(33) round(SC, SD, SE, SA, SB, <F2>, TMP)
	EXPAND(34) round(SB, SC, SD, SE, SA, <F2>, TMP)

	EXPAND(35) round(SA, SB, SC, SD, SE, <F2>, TMP)
	EXPAND(36) round(SE, SA, SB, SC, SD, <F2>, TMP)
	EXPAND(37) round(SD, SE, SA, SB, SC, <F2>, TMP)
	EXPAND(38) round(SC, SD, SE, SA, SB, <F2>, TMP)
	EXPAND(39) round(SB, SC, SD, SE, SA, <F2>, TMP)

	movl	K3VALUE, K
	EXPAND(40) round(SA, SB, SC, SD, SE, <F3>, TMP)
	EXPAND(41) round(SE, SA, SB, SC, SD, <F3>, TMP)
	EXPAND(42) round(SD, SE, SA, SB, SC, <F3>, TMP)
	EXPAND(43) round(SC, SD, SE, SA, SB, <F3>, TMP)
	EXPAND(44) round(SB, SC, SD, SE, SA, <F3>, TMP)

	EXPAND(45) round(SA, SB, SC, SD, SE, <F3>, TMP)
	EXPAND(46) round(SE, SA, SB, SC, SD, <F3>, TMP)
	EXPAND(47) round(SD, SE, SA, SB, SC, <F3>, TMP)
	EXPAND(48) round(SC, SD, SE, SA, SB, <F3>, TMP)
	EXPAND(49) round(SB, SC, SD, SE, SA, <F3>, TMP)

	EXPAND(50) round(SA, SB, SC, SD, SE, <F3>, TMP)
	EXPAND(51) round(SE, SA, SB, SC, SD, <F3>, TMP)
	EXPAND(52) round(SD, SE, SA, SB, SC, <F3>, TMP)
	EXPAND(53) round(SC, SD, SE, SA, SB, <F3>, TMP)
	EXPAND(54) round(SB, SC, SD, SE, SA, <F3>, TMP)

	EXPAND(55) round(SA, SB, SC, SD, SE, <F3>, TMP)
	EXPAND(56) round(SE, SA, SB, SC, SD, <F3>, TMP)
	EXPAND(57) round(SD, SE, SA, SB, SC, <F3>, TMP)
	EXPAND(58) round(SC, SD, SE, SA, SB, <F3>, TMP)
	EXPAND(59) round(SB, SC, SD, SE, SA, <F3>, TMP)

	movl	K4VALUE, K
	EXPAND(60) round(SA, SB, SC, SD, SE, <F2>, TMP)
	EXPAND(61) round(SE, SA, SB, SC, SD, <F2>, TMP)
	EXPAND(62) round(SD, SE, SA, SB, SC, <F2>, TMP)
	EXPAND(63) round(SC, SD, SE, SA, SB, <F2>, TMP)
	EXPAND(64) round(SB, SC, SD, SE, SA, <F2>, TMP)

	EXPAND(65) round(SA, SB, SC, SD, SE, <F2>, TMP)
	EXPAND(66) round(SE, SA, SB, SC, SD, <F2>, TMP)
	EXPAND(67) round(SD, SE, SA, SB, SC, <F2>, TMP)
	EXPAND(68) round(SC, SD, SE, SA, SB, <F2>, TMP)
	EXPAND(69) round(SB, SC, SD, SE, SA, <F2>, TMP)

	EXPAND(70) round(SA, SB, SC, SD, SE, <F2>, TMP)
	EXPAND(71) round(SE, SA, SB, SC, SD, <F2>, TMP)
	EXPAND(72) round(SD, SE, SA, SB, SC, <F2>, TMP)
	EXPAND(73) round(SC, SD, SE, SA, SB, <F2>, TMP)
	EXPAND(74) round(SB, SC, SD, SE, SA, <F2>, TMP)

	EXPAND(75) round(SA, SB, SC, SD, SE, <F2>, TMP)
	EXPAND(76) round(SE, SA, SB, SC, SD, <F2>, TMP)
	EXPAND(77) round(SD, SE, SA, SB, SC, <F2>, TMP)
	EXPAND(78) round(SC, SD, SE, SA, SB, <F2>, TMP)
	EXPAND(79) round(SB, SC, SD, SE, SA, <F2>, TMP)

	C Update the state vector
	movl	28(%esp),TMP
	addl	SA, (TMP) 
	addl	SB, 4(TMP) 
	addl	SC, 8(TMP) 
	addl	SD, 12(TMP) 
	addl	SE, 16(TMP)

	addl	$8, %esp
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret

.Leord:
	.size	_nettle_sha1_compress,.Leord-_nettle_sha1_compress
