C -*- mode: asm; asm-comment-char: ?C; -*-  
C nettle, low-level cryptographics library
C 
C Copyright (C) 2001, 2002, 2005, 2008 Rafael R. Sevilla, Niels Möller
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

C Use same macros as for plain x86. FIXME: AES_SUBST_BYTE uses
C hardcoded registers. 
include_src(<x86/aes.m4>)

C Register usage:

C AES state, use two of them
define(<SA>,<%eax>)
define(<SB>,<%ebx>)
define(<SC>,<%ebp>)
define(<SD>,<%r9d>)

define(<TA>,<%r10d>)
define(<TB>,<%r11d>)
define(<TC>,<%r12d>)
define(<TD>,<%r13d>)

define(<CTX>,	<%rdi>)
define(<TABLE>,	<%rsi>)
define(<LENGTH>,<%edx>)		C Length is only 32 bits
define(<DST>,	<%rcx>)
define(<SRC>,	<%r8>)

define(<KEY>,<%r14>)
define(<COUNT>,	<%r15d>)

C Put the outer loop counter on the stack, and reuse the LENGTH
C register as a temporary. 
	
define(<FRAME_COUNT>,	<(%esp)>)
define(<TMP>,<%edx>)
define(<TMPPTR>,<%rdx>)
	.file "aes-encrypt-internal.asm"
	
	C _aes_encrypt(struct aes_context *ctx, 
	C	       const struct aes_table *T,
	C	       unsigned length, uint8_t *dst,
	C	       uint8_t *src)
	.text
	ALIGN(4)
PROLOGUE(_nettle_aes_encrypt)
	test	LENGTH, LENGTH
	jz	.Lend

        C save all registers that need to be saved
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15	

	C Allocates 4 bytes more than we need, for nicer alignment.
	sub	$8, %rsp

	shrl	$4, LENGTH
	movl	LENGTH, FRAME_COUNT
.Lblock_loop:
	movl	CTX,KEY
	
	AES_LOAD(SA, SB, SC, SD, SRC, KEY)
	addl	$16, SRC	C Increment src pointer

	C  get number of rounds to do from ctx struct	
	movl	AES_NROUNDS (CTX), COUNT
	shrl	$1, COUNT
	subl	$1, COUNT

	addl	$16,KEY		C  point to next key
	ALIGN(4)
.Lround_loop:
	AES_ROUND(TABLE, SA,SB,SC,SD, TA, TMPPTR)
	xorl	(KEY), TA

	AES_ROUND(TABLE, SB,SC,SD,SA, TB, TMPPTR)
	xorl	4(KEY),TB

	AES_ROUND(TABLE, SC,SD,SA,SB, TC, TMPPTR)
	xorl	8(KEY),TC

	AES_ROUND(TABLE, SD,SA,SB,SC, TD, TMPPTR)
	xorl	12(KEY),TD

	AES_ROUND(TABLE, TA,TB,TC,TD, SA, TMPPTR)
	xorl	16(KEY), SA

	AES_ROUND(TABLE, TB,TC,TD,TA, SB, TMPPTR)
	xorl	20(KEY),SB

	AES_ROUND(TABLE, TC,TD,TA,TB, SC, TMPPTR)
	xorl	24(KEY),SC

	AES_ROUND(TABLE, TD,TA,TB,TC, SD, TMPPTR)
	xorl	28(KEY),SD
	
	addl	$32,KEY	C  point to next key
	decl	COUNT
	jnz	.Lround_loop

	C last round

	AES_FINAL_ROUND(SA,SB,SC,SD, TABLE, TA, TMP)
	AES_FINAL_ROUND(SB,SC,SD,SA, TABLE, TB, TMP)
	AES_FINAL_ROUND(SC,SD,SA,SB, TABLE, TC, TMP)
	AES_FINAL_ROUND(SD,SA,SB,SC, TABLE, TD, TMP)

	C S-box substitution
	mov	$3, COUNT
.Lsubst:
	AES_SUBST_BYTE(TA,TB,TC,TD, TABLE, TMPPTR)

	decl	COUNT
	jnz	.Lsubst

	C Add last subkey, and store encrypted data
	AES_STORE(TA,TB,TC,TD, KEY, DST)
	
	addl	$16, DST
	decl	FRAME_COUNT

	jnz	.Lblock_loop

	add	$8, %rsp
	pop	%r15	
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
.Lend:
	ret
EPILOGUE(_nettle_aes_encrypt)
