C x86_64/ghash-update.asm

ifelse(`
   Copyright (C) 2013, 2022 Niels Möller

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

C Register usage:

define(`KEY', `%rdi')
define(`XP', `%rsi')
define(`BLOCKS', `%rdx')
define(`SRC', `%rcx')
define(`CNT', `%rax')
define(`X', `%xmm0')
define(`M0', `%xmm1')
define(`M1', `%xmm2')
define(`R', `%xmm3')
define(`ONE', `%xmm4')

	.file "ghash-update.asm"

	C const uint8_t *_ghash_update (const struct gcm_key *key,
	C				union nettle_block16 *x,
	C				size_t blocks, const uint8_t *data)

	.text
	ALIGN(16)
PROLOGUE(_nettle_ghash_update)
	W64_ENTRY(4, 5)
	sub	$1, BLOCKS
	movups	(XP), X
	jc	.Ldone
	C Point to middle of table.
	lea	1024(KEY), KEY
	movaps	X, ONE
	pcmpeqd	ONE, ONE
	psrlq	$63, ONE

ALIGN(16)
.Lblock_loop:
	C Unaligned input
	movups	(SRC), M0
	pxor	M0, X
	pxor	R, R
	mov	$-1024, CNT
ALIGN(16)
.Loop_bit:
	movaps	ONE, M0
	pand	X, M0
	pcmpeqd	ONE, M0
	pshufd	$0xaa, M0, M1
	pshufd	$0, M0, M0
	psrlq	$1, X
	pand	(KEY, CNT), M0
	pand	1024(KEY, CNT), M1
	pxor	M0, R
	pxor	M1, R

	add	$16, CNT
	jnz	.Loop_bit

	movaps	R, X

	add	$16, SRC
	sub	$1, BLOCKS
	jnc	.Lblock_loop

.Ldone:
	movups	X, (XP)
	mov	SRC, %rax
	W64_EXIT(4, 5)
	ret
EPILOGUE(_nettle_ghash_update)
