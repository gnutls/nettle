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

	.file "aes-decrypt.asm"

	C aes_decrypt(struct aes_context *ctx, 
	C             unsigned length, uint8_t *dst,
	C 	      uint8_t *src)
	.text
	.align 16
	.globl aes_decrypt
	.type	aes_decrypt,@function
aes_decrypt:
	C save all registers that need to be saved
	pushl	%ebx		C  16(%esp)
	pushl	%ebp		C  12(%esp)
	pushl	%esi		C  8(%esp)
	pushl	%edi		C  4(%esp)

	C ctx = 20(%esp)
	C length = 24(%esp)
	C dst = 28(%esp)
	C src = 32(%esp)

	movl	24(%esp), %ebp
	testl	%ebp,%ebp
	jz	.Ldecrypt_end
	
.Ldecrypt_block_loop:
	movl	20(%esp),%esi	C  address of context struct ctx
	movl	32(%esp),%ebp	C  address of plaintext
	AES_LOAD(%esi, %ebp)
	addl	$16, 32(%esp)	C Increment src pointer

	C  get number of rounds to do from struct	
	movl	AES_NROUNDS (%esi),%ebp	

	subl	$1,%ebp		C  one round is complete
	addl	$16,%esi	C  point to next key
.Ldecrypt_loop:
	pushl	%esi		C  save this first: we'll clobber it later

	C Why???
	xchgl	%ebx,%edx

	AES_ROUND(_aes_decrypt_table,a,b,c,d)
	pushl	%edi		C  save first on stack

	AES_ROUND(_aes_decrypt_table,d,a,b,c)
	pushl	%edi

	AES_ROUND(_aes_decrypt_table,c,d,a,b)
	pushl	%edi		C  save first on stack

	AES_ROUND(_aes_decrypt_table,b,c,d,a)

	movl	%edi,%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	
	popl	%esi
	
	xorl	(%esi),%eax	C  add current session key to plaintext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx
	addl	$16,%esi	C  point to next key
	decl	%ebp
	jnz	.Ldecrypt_loop

	C Foo?
	xchgl	%ebx,%edx

	C last round

	AES_FINAL_ROUND(a,b,c,d)
	pushl	%edi

	AES_FINAL_ROUND(b,c,d,a)
	pushl	%edi

	AES_FINAL_ROUND(c,d,a,b)
	pushl	%edi

	AES_FINAL_ROUND(d,a,b,c)
	
	movl	%edi,%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	xchgl	%ebx,%edx

	C inverse S-box substitution
	mov	$4,%edi
.Lisubst:
	AES_SUBST_BYTE(_aes_decrypt_table)

	decl	%edi
	jnz	.Lisubst

	xorl	(%esi),%eax	C  add last key to plaintext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx

	C // store decrypted data back to caller's buffer
	movl	28(%esp),%edi
	movl	%eax,(%edi)
	movl	%ebx,4(%edi)
	movl	%ecx,8(%edi)
	movl	%edx,12(%edi)
	
	addl	$16, 28(%esp)	C Increment destination pointer
	subl	$16, 24(%esp)
	jnz	.Ldecrypt_block_loop

.Ldecrypt_end: 
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret
.Leord:
	.size	aes_decrypt,.Leord-aes_decrypt
