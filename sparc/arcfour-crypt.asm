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

C	Define to YES, to enable the complex code to special case SRC
C	and DST with compatible alignment.
	
define(<WITH_ALIGN>, <YES>)

C	Registers

define(<CTX>,	<%i0>)
define(<LENGTH>,<%i1>)
define(<DST>,	<%i2>)
define(<SRC>,	<%i3>)

define(<I1>,	<%i4>)
define(<I2>,	<%i5>)
define(<J>,	<%g1>)
define(<SI>,	<%g2>)
define(<SJ>,	<%g3>)
define(<TMP>,	<%o0>)
define(<N>,	<%o1>)
define(<DATA>,	<%o2>)

C	Computes the next byte of the key stream. As input, i must
C	already point to the index for the current access, the index
C	for the next access is stored in ni. The resulting key byte is
C	stored in res.
C	ARCFOUR_BYTE(i, ni, res)
define(<ARCFOUR_BYTE>, <
	ldub	[CTX + $1], SI
	add	$1, 1, $2
	add	J, SI, J
	and	J, 0xff, J
	ldub	[CTX + J], SJ
	and	$2, 0xff, $2
	stb	SI, [CTX + J]
	add	SI, SJ, SI
	and	SI, 0xff, SI
	stb	SJ, [CTX + $1]
	ldub	[CTX + SI], $3
>)dnl
			
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
	lduh	[CTX + ARCFOUR_I], I1
	and	I1, 0xff, J
	srl	I1, 8, I1

	andcc	LENGTH, 1, %g0
	beq	.Loop

	add	I1, 1 ,I1
	and	I1, 0xff, I1

	ARCFOUR_BYTE(I1, I2, TMP)
	ldub	[SRC], DATA
	subcc	LENGTH, 1, LENGTH
	add	SRC, 1, SRC
	xor	DATA, TMP, DATA
	stb	DATA, [DST]
	beq	.Ldone
	add	DST, 1, DST

	mov	I2, I1
.Loop:
	ARCFOUR_BYTE(I1, I2, TMP)
	ldub	[SRC], DATA
	add	SRC, 2, SRC
	xor	DATA, TMP, DATA
	stb	DATA, [DST]

	ARCFOUR_BYTE(I2, I1, TMP)
	ldub	[SRC - 1], DATA
	subcc	LENGTH, 2, LENGTH
	add	DST, 2, DST
	xor	DATA, TMP, DATA
	
	bne	.Loop
	stb	DATA, [DST - 1]

	mov	I2, I1
.Ldone:
	C	Save back I and J
	sll	I1, 8, I1
	or	I1, J, I1
	stuh	I1, [CTX + ARCFOUR_I]

.Lend:
	ret
	restore

EPILOGUE(nettle_arcfour_crypt)

C Some stats from adriana.lysator.liu.se (SS1000E, 85 MHz), for AES 128

C 1:	nettle-1.13 C-code
C 2:	First working version of the assembler code
C 3:	Moved load of source byte
C 4:	Better instruction scheduling
C 5:	Special case SRC and DST with compatible alignment
C 6:	After bugfix (reorder of ld [CTX+SI+SJ] and st [CTX + SI])
C 7:	Unrolled only twice, with byte-accesses

C	MB/s	cycles/byte	Code size (bytes)
C 1:	6.6	12.4		132
C 2:	5.6	14.5		116
C 3:	6.0	13.5		116
C 4:	6.5	12.4		116
C 5:	7.9	10.4		496
C 6:	8.3	9.7		496
C 7:	6.7	12.1		268
