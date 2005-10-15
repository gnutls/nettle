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


C Arguments
define(<CTX>,	<%i0>)
define(<T>,	<%i1>)
define(<LENGTH>,<%i2>)
define(<DST>,	<%i3>)
define(<SRC>,	<%i4>)

C AES state, two copies for unrolling

define(<W0>,	<%l0>)
define(<W1>,	<%l1>)
define(<W2>,	<%l2>)
define(<W3>,	<%l3>)

define(<T0>,	<%l4>)
define(<T1>,	<%l5>)
define(<T2>,	<%l6>)
define(<T3>,	<%l7>)

C %o0 and %01 are TMP1 and TMP2
define(<KEY>,	<%o4>)
define(<ROUND>, <%o5>)

C Registers %g1-%g3 and %o0 - %o5 are free to use.

C The sparc32 stack frame looks like
C
C %fp -   4: OS-dependent link field
C %fp -   8: OS-dependent link field
C %fp -  24: tmp, uint32_t[4]
C %fp -  40: wtxt, uint32_t[4]
C %fp - 136: OS register save area. 
define(<FRAME_SIZE>, 136)

	.file "aes-encrypt-internal.asm"

	C _aes_encrypt(struct aes_context *ctx, 
	C	       const struct aes_table *T,
	C	       unsigned length, uint8_t *dst,
	C	       uint8_t *src)

	.section	".text"
	.align 16
	.proc	020
	
PROLOGUE(_nettle_aes_encrypt)

	save	%sp, -FRAME_SIZE, %sp
	cmp	LENGTH, 0
	be	.Lend
	nop

.Lblock_loop:
	C  Read src, and add initial subkey
	add	CTX, AES_KEYS, KEY
	AES_LOAD(0, SRC, KEY, W0)
	AES_LOAD(1, SRC, KEY, W1)
	AES_LOAD(2, SRC, KEY, W2)
	AES_LOAD(3, SRC, KEY, W3)

	add	SRC, 16, SRC
	add	KEY, 16, KEY

	C	Must be even, and includes the final round
	ld	[AES_NROUNDS + CTX], ROUND
	srl	ROUND, 1, ROUND

.Lround_loop:
	C	Transform W -> T
	AES_ROUND(0, T, W0, W1, W2, W3, KEY, T0)
	AES_ROUND(1, T, W1, W2, W3, W0, KEY, T1)
	AES_ROUND(2, T, W2, W3, W0, W1, KEY, T2)
	AES_ROUND(3, T, W3, W0, W1, W2, KEY, T3)

	C	Transform T -> W
	AES_ROUND(4, T, T0, T1, T2, T3, KEY, W0)
	AES_ROUND(5, T, T1, T2, T3, T0, KEY, W1)
	AES_ROUND(6, T, T2, T3, T0, T1, KEY, W2)
	AES_ROUND(7, T, T3, T0, T1, T2, KEY, W3)

	subcc	ROUND, 1, ROUND
	bne	.Lround_loop
	add	KEY, 32, KEY

	C	Penultimate round
	AES_ROUND(0, T, W0, W1, W2, W3, KEY, T0)
	AES_ROUND(1, T, W1, W2, W3, W0, KEY, T1)
	AES_ROUND(2, T, W2, W3, W0, W1, KEY, T2)
	AES_ROUND(3, T, W3, W0, W1, W2, KEY, T3)

	add	KEY, 16, KEY
	C	Final round
	AES_ROUND(0, T, T0, T1, T2, T3, KEY, DST)
	AES_ROUND(1, T, T1, T2, T3, T0, KEY, DST)
	AES_ROUND(2, T, T2, T3, T0, T1, KEY, DST)
	AES_ROUND(3, T, T3, T0, T1, T2, KEY, DST)

	subcc	LENGTH, 16, LENGTH
	bne	.Lblock_loop
	add	DST, 16, DST

.Lend:
	ret
	restore
EPILOGUE(_nettle_aes_encrypt)

C Some stats from adriana.lysator.liu.se (SS1000$, 85 MHz), for AES 128

C nettle-1.13 C-code:		1.2 MB/s, 1107 cycles/block	
C nettle-1.13 assembler:	2.3 MB/s,  572 cycles/block

	
