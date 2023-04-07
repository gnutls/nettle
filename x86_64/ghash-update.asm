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
define(`X0', `%rax')
define(`X1', `%rbx')
define(`CNT', `%rbp')
define(`R0', `%r8')
define(`R1', `%r9')
define(`T0', `%r10')
define(`T1', `%r11')
define(`M0', `%r12')
define(`M1', `%r13')

	.file "ghash-update.asm"

	C const uint8_t *_ghash_update (const struct gcm_key *key,
	C				union nettle_block16 *x,
	C				size_t blocks, const uint8_t *data)

	.text
	ALIGN(16)
PROLOGUE(_nettle_ghash_update)
	W64_ENTRY(4, 0)
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	sub	$1, BLOCKS
	mov	(XP), X0
	mov	8(XP), X1
	jc	.Ldone
	C Point to middle of table.
	lea	1024(KEY), KEY
ALIGN(16)
.Lblock_loop:

	xor (SRC), X0
	xor 8(SRC), X1

	xor	R0, R0
	xor	R1, R1
	mov	$-1024, CNT

ALIGN(16)
.Loop_bit:
	shr	X0
	sbb	M0, M0
	shr	X1
	sbb	M1, M1

	mov	(KEY, CNT), T0
	and	M0, T0
	and	8(KEY, CNT), M0
	mov	1024(KEY, CNT), T1
	and	M1, T1
	and	1032(KEY, CNT), M1
	xor	T1, T0
	xor	M0, M1

	xor	T0, R0
	xor	M1, R1
	add	$16, CNT
	jnz	.Loop_bit

	mov	R0, X0
	mov	R1, X1

	add	$16, SRC
	sub	$1, BLOCKS
	jnc	.Lblock_loop

.Ldone:
	mov	X0, (XP)
	mov	X1, 8(XP)
	mov	SRC, %rax
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	W64_EXIT(4, 0)
	ret
EPILOGUE(_nettle_ghash_update)
