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
C
C The aes state is kept in %eax, %ebx, %ecx and %edx
C
C %esi is used as temporary, to point to the input, and to the
C subkeys, etc.
C
C %ebp is used as the round counter, and as a temporary in the final round.
C
C %edi is a temporary, often used as an accumulator.

	.file "aes-encrypt.asm"
	
	C aes_encrypt(struct aes_context *ctx, 
	C             unsigned length, uint8_t *dst,
	C 	      uint8_t *src)
	.text
	.align 16
	.globl aes_encrypt
	.type	aes_encrypt,@function
aes_encrypt:
	C // save all registers that need to be saved
	pushl	%ebx		C  16(%esp)
	pushl	%ebp		C  12(%esp)
	pushl	%esi		C  8(%esp)
	pushl	%edi		C  4(%esp)

	C ctx = 20(%esp)
	C length = 24(%esp)
	C dst = 28(%esp)
	C src = 32(%esp)

	movl	24(%esp), %ebp
	C What's the right way to set the flags?
	addl	$0, %ebp
	jz	.Lencrypt_end
	
.Lencrypt_block_loop:
	movl	20(%esp),%esi	C  address of context struct ctx
	movl	32(%esp),%ebp	C  address of plaintext
	AES_LOAD(%esi, %ebp)
	addl	$16, 32(%esp)	C Increment src pointer
		
	C FIXME:	Use %esi instead
	movl	20(%esp),%ebp	C  address of context struct
	movl	AES_NROUNDS (%ebp),%ebp	C  get number of rounds to do from struct

	subl	$1,%ebp
	addl	$16,%esi	C  point to next key
.Laes_encrypt_loop:
	pushl	%esi		C  save this first: we'll clobber it later

	C Computation of the new %eax is broken, in the first test case, 
	C first round, we get 0xb3b638c6, not dfd5b20f, just
	C before adding the subkey
	
	C First column, IDXi = 0, 1, 2, 3
	C T[0] = table[0][B0(%eax)]
	C      ^ table[1][B1(%ebx)]
	C      ^ table[2][B2(%ebx)]
	C      ^ table[3][B3(%ebx)]
	C
	C a b c d
	movl	%eax, %esi
	andl	$0xff, %esi
	shll	$2,%esi		C  index in table
	movl	AES_TABLE0 + _aes_encrypt_table (%esi),%edi
	movl	%ebx, %esi
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	AES_TABLE1 + _aes_encrypt_table (%esi),%edi
	movl	%ecx,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	AES_TABLE2 + _aes_encrypt_table (%esi),%edi
	movl	%edx,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	AES_TABLE3 + _aes_encrypt_table (%esi),%edi
	pushl	%edi		C  save first on stack

	C // Second column
	C b c d a
	movl	%ebx,%esi	C  copy first in
	andl	$0x000000ff,%esi C  clear all but offset
	shll	$2,%esi		C  index in table
	movl	AES_TABLE0 + _aes_encrypt_table (%esi),%edi
	movl	%ecx,%esi	C  second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	AES_TABLE1 + _aes_encrypt_table (%esi),%edi
	movl	%edx,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	AES_TABLE2 + _aes_encrypt_table (%esi),%edi
	movl	%eax,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	AES_TABLE3 + _aes_encrypt_table (%esi),%edi
	pushl	%edi		C  save first on stack

	C // Third column
	C c d a b
	movl	%ecx,%esi	C  copy first in
	andl	$0x000000ff,%esi C  clear all but offset
	shll	$2,%esi		C  index in table
	movl	AES_TABLE0 + _aes_encrypt_table (%esi),%edi
	movl	%edx,%esi	C  second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	AES_TABLE1 + _aes_encrypt_table (%esi),%edi
	movl	%eax,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	AES_TABLE2 + _aes_encrypt_table (%esi),%edi
	movl	%ebx,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	AES_TABLE3 + _aes_encrypt_table (%esi),%edi
	pushl	%edi		C  save first on stack

	C // Fourth column
	C d a b c
	movl	%edx,%esi	C  copy first in
	andl	$0x000000ff,%esi C  clear all but offset
	shll	$2,%esi		C  index in table
	movl	AES_TABLE0 + _aes_encrypt_table (%esi),%edi
	movl	%eax,%esi	C  second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	AES_TABLE1 + _aes_encrypt_table (%esi),%edi
	movl	%ebx,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	AES_TABLE2 + _aes_encrypt_table (%esi),%edi
	movl	%ecx,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	AES_TABLE3 + _aes_encrypt_table (%esi),%edi

	movl	%edi,%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	popl	%esi
C .Laes_got_t: 
	xorl	(%esi),%eax	C  add current session key to plaintext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx
	addl	$16,%esi	C  point to next key
	decl	%ebp
	jnz	.Laes_encrypt_loop

	C last round

	C first column
	AES_LAST_ROUND(a,b,c,d)
	pushl	%edi

	C second column
	AES_LAST_ROUND(b,c,d,a)
	pushl	%edi

	C third column
	AES_LAST_ROUND(c,d,a,b)
	pushl	%edi

	C fourth column
	AES_LAST_ROUND(d,a,b,c)
	movl	%edi,%edx
	
	popl	%ecx
	popl	%ebx
	popl	%eax

	C S-box substitution
	mov	$4,%edi
.Lsubst:	
	movl	%eax,%ebp
	andl	$0x000000ff,%ebp
	movb	AES_SBOX + _aes_encrypt_table (%ebp),%al
	roll	$8,%eax

	movl	%ebx,%ebp
	andl	$0x000000ff,%ebp
	movb	AES_SBOX + _aes_encrypt_table (%ebp),%bl
	roll	$8,%ebx

	movl	%ecx,%ebp
	andl	$0x000000ff,%ebp
	movb	AES_SBOX + _aes_encrypt_table (%ebp),%cl
	roll	$8,%ecx

	movl	%edx,%ebp
	andl	$0x000000ff,%ebp
	movb	AES_SBOX + _aes_encrypt_table (%ebp),%dl
	roll	$8,%edx

	decl	%edi
	jnz	.Lsubst

	C Add last subkey, and store encrypted data
	movl	28(%esp),%edi
	AES_STORE(%esi, %edi)
	
	addl	$16, 28(%esp)	C Increment destination pointer
	subl	$16, 24(%esp)	C Length

	C NOTE: Will loop forever if input data is not an
	C integer number of blocks.
	jnz	.Lencrypt_block_loop

.Lencrypt_end: 
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret
.eore:
	.size	aes_encrypt,.eore-aes_encrypt
