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
define(CTX,	%i0)
define(T,	%i1)
define(LENGTH,	%i2)
define(DST,	%i3)
define(SRC,	%i4)

C AES state, two copies for unrolling

define(W0,	%l0)
define(W1,	%l1)
define(W2,	%l2)
define(W3,	%l3)

define(T0,	%l4)
define(T1,	%l5)
define(T2,	%l6)
define(T3,	%l7)

C Registers %g1-%g3 and %o0 - %o5 are free to use.

C The sparc32 stack frame looks like
C
C %fp -   4: OS-dependent link field
C %fp -   8: OS-dependent link field
C %fp -  24: tmp, uint32_t[4]
C %fp -  40: wtxt, uint32_t[4]
C %fp - 136: OS register save area. 
define(<FRAME_SIZE>, 136)

	.section	".text"
	.align 16
	.proc	020
	
PROLOGUE(_nettle_aes_encrypt)

	save	%sp, -FRAME_SIZE, %sp
	cmp	length, 0
	be	.Lend

.Lblock_loop:
	C  Read src, and add initial subkey

	
.Lend:
	ret
	restore
EPILOGUE(_nettle_aes_encrypt)

C Some stats from adriana.lysator.liu.se (SS1000$, 85 MHz), for AES 128

C nettle-1.13 C-code:		1.2 MB/s, 1107 cycles/block	
C nettle-1.13 assembler:	2.3 MB/s,  572 cycles/block

	
