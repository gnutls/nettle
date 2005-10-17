C -*- mode: asm; asm-comment-char: ?C; -*-  
C nettle, low-level cryptographics library
C 
C Copyright (C) 2002, 2005 Niels Möller
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

C Registers

define(<CTX>,	<%i0>)
define(<LENGTH>,<%i1>)
define(<DST>,	<%i2>)
define(<SRC>,	<%i3>)

define(<I>,	<%i4>)
define(<J>,	<%i5>)
define(<SI>,	<%g1>)
define(<SJ>,	<%g2>)
define(<TMP>,	<%g3>)

C	FIXME: Consider using the callers window

define(<FRAME_SIZE>, 104)

	.file "arcfour-crypt.asm"

	C arcfour_crypt(struct arcfour_ctx *ctx,
	C               unsigned length, uint8_t *dst,
	C               const uint8_t *src)

	.section	".text"
	.align 16
	.proc	020
	
PROLOGUE(nettle_arcfour_crypt)

	save	%sp, -FRAME_SIZE, %sp
	cmp	LENGTH, 0
	be	.Lend
	
	C	Load both I and J
	lduh	[CTX + ARCFOUR_I], I
	and	I, 0xff, J
	srl	I, 8, I

.Loop:	
	add	I, 1, I
	and	I, 0xff, I
	ldub	[CTX + I], SI
	add	J, SI, J
	and	J, 0xff, J
	ldub	[CTX + J], SJ
	stb	SJ, [CTX + I]
	stb	SI, [CTX + J]
	add	SI, SJ, SI
	and	SI, 0xff, SI
	ldub	[CTX + SI], SI
	ldub	[SRC], TMP
	xor	TMP, SI, TMP
	stb	TMP, [DST]
	subcc	LENGTH,1,LENGTH
	add	SRC, 1, SRC
	bne	.Loop
	add	DST, 1, DST

	C	Save back I and J	
	sll	I, 8, I
	or	I, J, I
	stuh	I, [CTX + ARCFOUR_I]

.Lend:
	ret
	restore

EPILOGUE(nettle_arcfour_crypt)

C Some stats from adriana.lysator.liu.se (SS1000$, 85 MHz), for AES 128

C 1:	nettle-1.13 C-code
C 2:	First working version of the assembler code
	
C	MB/s	cycles/byte	Code size (bytes)
C 1:	6.6	12.4		132
C 2:	5.6	14.5		116
