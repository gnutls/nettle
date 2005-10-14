C -*- mode: asm; asm-comment-char: ?C; -*-  
C nettle, low-level cryptographics library
C 
C Copyright (C) 2001, 2002 Rafael R. Sevilla, Niels Möller
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

C Register usage:

C AES state
define(<SA>,<%eax>)
define(<SB>,<%ebx>)
define(<SC>,<%ecx>)
define(<SD>,<%edx>)

C Primary use of these registers. They're also used temporarily for other things.
define(<T>,<%ebp>)
define(<TMP>,<%edi>)
define(<KEY>,<%esi>)

define(<FRAME_CTX>,	<28(%esp)>)
define(<FRAME_TABLE>,	<32(%esp)>)
define(<FRAME_LENGTH>,	<36(%esp)>)
define(<FRAME_DST>,	<40(%esp)>)
define(<FRAME_SRC>,	<44(%esp)>)

define(<FRAME_KEY>,	<4(%esp)>)
define(<FRAME_COUNT>,	<(%esp)>)

C The aes state is kept in %eax, %ebx, %ecx and %edx
C
C %esi is used as temporary, to point to the input, and to the
C subkeys, etc.
C
C %ebp is used as the round counter, and as a temporary in the final round.
C
C %edi is a temporary, often used as an accumulator.

	.file "aes-encrypt-internal.asm"
	
	C _aes_encrypt(struct aes_context *ctx, 
	C	       const struct aes_table *T,
	C	       unsigned length, uint8_t *dst,
	C	       uint8_t *src)
	.text
	.align 16
PROLOGUE(_nettle_aes_encrypt)
	C save all registers that need to be saved
	pushl	%ebx		C  20(%esp)
	pushl	%ebp		C  16(%esp)
	pushl	%esi		C  12(%esp)
	pushl	%edi		C  8(%esp)

	subl	$8, %esp	C  loop counter and save area for the key pointer

	movl	FRAME_LENGTH, %ebp
	testl	%ebp,%ebp
	jz	.Lend

.Lblock_loop:
	movl	FRAME_CTX,KEY	C  address of context struct ctx
	C  get number of rounds to do from ctx struct	
	
	movl	FRAME_SRC,TMP	C  address of plaintext
	AES_LOAD(SA, SB, SC, SD, TMP, KEY)
	addl	$16, FRAME_SRC	C Increment src pointer
	movl	FRAME_TABLE, T

	C  get number of rounds to do from ctx struct	
	movl	AES_NROUNDS (KEY),TMP
	subl	$1,TMP

	C Loop counter on stack
	movl	TMP, FRAME_COUNT

	addl	$16,KEY		C  point to next key
	movl	KEY,FRAME_KEY
	.align 16
.Lround_loop:
	AES_ROUND(T, SA, SB, SC, SD, TMP, KEY)
	pushl	TMP

	AES_ROUND(T, SB, SC, SD, SA, TMP, KEY)
	pushl	TMP

	AES_ROUND(T, SC, SD, SA, SB, TMP, KEY)
	pushl	TMP

	AES_ROUND(T, SD, SA, SB, SC, TMP, KEY)
	
	movl	TMP,SD
	popl	SC
	popl	SB
	popl	SA
	
	movl	FRAME_KEY, KEY

	xorl	(KEY),SA	C  add current session key to plaintext
	xorl	4(KEY),SB
	xorl	8(KEY),SC
	xorl	12(KEY),SD
	addl	$16,FRAME_KEY	C  point to next key
	decl	FRAME_COUNT
	jnz	.Lround_loop

	C last round

	AES_FINAL_ROUND(SA,SB,SC,SD, TMP, KEY)
	pushl	TMP

	AES_FINAL_ROUND(SB,SC,SD,SA, TMP, KEY)
	pushl	TMP

	AES_FINAL_ROUND(SC,SD,SA,SB, TMP, KEY)
	pushl	TMP

	AES_FINAL_ROUND(SD,SA,SB,SC, TMP, KEY)

	movl	TMP,SD
	popl	SC
	popl	SB
	popl	SA

	C S-box substitution
	mov	$4,TMP
.Lsubst:
	AES_SUBST_BYTE(T, KEY)

	decl	TMP
	jnz	.Lsubst

	C Add last subkey, and store encrypted data
	movl	FRAME_DST,TMP
	movl	FRAME_KEY, KEY
	AES_STORE(SA, SB, SC, SD, KEY, TMP)
	
	addl	$16, FRAME_DST		C Increment destination pointer
	subl	$16, FRAME_LENGTH	C Length

	C NOTE: Will loop forever if input data is not an
	C integer number of blocks.
	jnz	.Lblock_loop

.Lend:
	addl	$8, %esp
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret
EPILOGUE(_nettle_aes_encrypt)
