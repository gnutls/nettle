C nettle, low-level cryptographics library
C 
C Copyright (C) 2001, 2002 Rafael R. Sevilla
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


	.file	"aes.asm"

	.data

include_src(<x86/aes_tables.asm>)

	.text

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

	C aes_encrypt(struct aes_context *ctx, 
	C             unsigned length, uint8_t *dst,
	C 	      uint8_t *src)
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
	
	movl	32(%esp),%esi	C  address of plaintext
	movl	(%esi),%eax	C  load plaintext into registers
	movl	4(%esi),%ebx
	movl	8(%esi),%ecx
	movl	12(%esi),%edx
aes_got_plain: 
	movl	20(%esp),%esi	C  address of context struct ctx
	xorl	(%esi),%eax	C  add first key to plaintext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx
aes_xored_initial:
	C FIXME:	Use %esi instead
	movl	20(%esp),%ebp	C  address of context struct
	movl	AES_NROUNDS (%ebp),%ebp	C  get number of rounds to do from struct

	subl	$1,%ebp
	addl	$16,%esi	C  point to next key
aes_encrypt_loop:
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
	shll	$2,%esi		C  index in dtbl1
	movl	dtbl1(%esi),%edi
	movl	%ebx, %esi
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	dtbl2(%esi),%edi
	movl	%ecx,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl3(%esi),%edi
	movl	%edx,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl4(%esi),%edi
	pushl	%edi		C  save first on stack

	C // Second column
	C b c d a
	movl	%ebx,%esi	C  copy first in
	andl	$0x000000ff,%esi C  clear all but offset
	shll	$2,%esi		C  index in dtbl1
	movl	dtbl1(%esi),%edi
	movl	%ecx,%esi	C  second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	dtbl2(%esi),%edi
	movl	%edx,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl3(%esi),%edi
	movl	%eax,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl4(%esi),%edi
	pushl	%edi		C  save first on stack

	C // Third column
	C c d a b
	movl	%ecx,%esi	C  copy first in
	andl	$0x000000ff,%esi C  clear all but offset
	shll	$2,%esi		C  index in dtbl1
	movl	dtbl1(%esi),%edi
	movl	%edx,%esi	C  second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	dtbl2(%esi),%edi
	movl	%eax,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl3(%esi),%edi
	movl	%ebx,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl4(%esi),%edi
	pushl	%edi		C  save first on stack

	C // Fourth column
	C d a b c
	movl	%edx,%esi	C  copy first in
	andl	$0x000000ff,%esi C  clear all but offset
	shll	$2,%esi		C  index in dtbl1
	movl	dtbl1(%esi),%edi
	movl	%eax,%esi	C  second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	dtbl2(%esi),%edi
	movl	%ebx,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl3(%esi),%edi
	movl	%ecx,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl4(%esi),%edi

	movl	%edi,%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	popl	%esi
aes_got_t: 
	xorl	(%esi),%eax	C  add current session key to plaintext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx
	addl	$16,%esi	C  point to next key
	decl	%ebp
	jnz	aes_encrypt_loop

	C // last round
	C // first column
	C a b c d
	movl	%eax,%edi
	andl	$0x000000ff,%edi
	movl	%ebx,%ebp
	andl	$0x0000ff00,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0x00ff0000,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0xff000000,%ebp
	orl	%ebp,%edi
	pushl	%edi

	C // second column
	C d a b c
	movl	%eax,%edi
	andl	$0x0000ff00,%edi
	movl	%ebx,%ebp
	andl	$0x00ff0000,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0xff000000,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0x000000ff,%ebp
	orl	%ebp,%edi
	pushl	%edi

	C c d a b
	C // third column
	movl	%eax,%edi
	andl	$0x00ff0000,%edi
	movl	%ebx,%ebp
	andl	$0xff000000,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0x000000ff,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0x0000ff00,%ebp
	orl	%ebp,%edi
	pushl	%edi

	C // fourth column
	C b c d a
	movl	%eax,%edi
	andl	$0xff000000,%edi
	movl	%ebx,%ebp
	andl	$0x000000ff,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0x0000ff00,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0x00ff0000,%ebp
	orl	%ebp,%edi
	movl	%edi,%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	xchgl	%ebx,%edx

	C // S-box substitution
	mov	$4,%edi
.sb_sub:
	movl	%eax,%ebp
	andl	$0x000000ff,%ebp
	movb	sbox(%ebp),%al
	roll	$8,%eax

	movl	%ebx,%ebp
	andl	$0x000000ff,%ebp
	movb	sbox(%ebp),%bl
	roll	$8,%ebx

	movl	%ecx,%ebp
	andl	$0x000000ff,%ebp
	movb	sbox(%ebp),%cl
	roll	$8,%ecx

	movl	%edx,%ebp
	andl	$0x000000ff,%ebp
	movb	sbox(%ebp),%dl
	roll	$8,%edx

	decl	%edi
	jnz	.sb_sub

aes_got_tlast:		
	xorl	(%esi),%eax	C  add last key to plaintext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx
aes_got_result:
	C // store encrypted data back to caller's buffer
	movl	28(%esp),%edi
	movl	%eax,(%edi)
	movl	%ebx,4(%edi)
	movl	%ecx,8(%edi)
	movl	%edx,12(%edi)
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret
.eore:
	.size	aes_encrypt,.eore-aes_encrypt


	C aes_encrypt(struct aes_context *ctx, 
	C             unsigned length, uint8_t *dst,
	C 	      uint8_t *src)
	.align 16
.globl aes_decrypt
	.type	aes_decrypt,@function
aes_decrypt:
	C // save all registers that need to be saved
	pushl	%ebx		C  16(%esp)
	pushl	%ebp		C  12(%esp)
	pushl	%esi		C  8(%esp)
	pushl	%edi		C  4(%esp)

	C ctx = 20(%esp)
	C length = 24(%esp)
	C dst = 28(%esp)
	C src = 32(%esp)

	movl	32(%esp),%esi	C  address of ciphertext
	movl	(%esi),%eax	C  load ciphertext into registers
	movl	4(%esi),%ebx
	movl	8(%esi),%ecx
	movl	12(%esi),%edx
	
	movl	20(%esp),%esi	C  address of context struct ctx
	xorl	(%esi),%eax	C  add first key to ciphertext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx
	movl	AES_NROUNDS (%esi),%ebp	C  get number of rounds to do from struct
	C shll	$4,%ebp
	C leal	240(%esi, %ebp),%esi
	C shrl	$4,%ebp
	C xorl	(%esi),%eax	C  add last key to ciphertext
	C xorl	4(%esi),%ebx
	C xorl	8(%esi),%ecx
	C xorl	12(%esi),%edx

	subl	$1,%ebp		C  one round is complete
	addl	$16,%esi	C  point to next key
Ldecrypt_loop:
	pushl	%esi		C  save this first: we'll clobber it later

	C Why???
	xchgl	%ebx,%edx

	C // First column
	C a b c d
	movl	%eax,%esi	C  copy first in
	andl	$0x000000ff,%esi C  clear all but offset
	shll	$2,%esi		C  index in itbl1
	movl	itbl1(%esi),%edi
	movl	%ebx,%esi	C  second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	itbl2(%esi),%edi
	movl	%ecx,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	itbl3(%esi),%edi
	movl	%edx,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	itbl4(%esi),%edi
	pushl	%edi		C  save first on stack

	C // Second column
	C d a b c
	movl	%edx,%esi	C  copy first in
	andl	$0x000000ff,%esi C  clear all but offset
	shll	$2,%esi		C  index in itbl1
	movl	itbl1(%esi),%edi
	movl	%eax,%esi	C  second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	itbl2(%esi),%edi
	movl	%ebx,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	itbl3(%esi),%edi
	movl	%ecx,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	itbl4(%esi),%edi
	pushl	%edi

	C // Third column
	C c d a b
	movl	%ecx,%esi	C  copy first in
	andl	$0x000000ff,%esi C  clear all but offset
	shll	$2,%esi		C  index in itbl1
	movl	itbl1(%esi),%edi
	movl	%edx,%esi	C  second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	itbl2(%esi),%edi
	movl	%eax,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	itbl3(%esi),%edi
	movl	%ebx,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	itbl4(%esi),%edi
	pushl	%edi		C  save first on stack

	C // Fourth column
	C b c d a
	movl	%ebx,%esi	C  copy first in
	andl	$0x000000ff,%esi C  clear all but offset
	shll	$2,%esi		C  index in itbl1
	movl	itbl1(%esi),%edi
	movl	%ecx,%esi	C  second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	itbl2(%esi),%edi
	movl	%edx,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	itbl3(%esi),%edi
	movl	%eax,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	itbl4(%esi),%edi

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
	jnz	Ldecrypt_loop

	C Foo?
	xchgl	%ebx,%edx

	C // last round
	C // first column
	C a b c d
	movl	%eax,%edi
	andl	$0x000000ff,%edi
	movl	%ebx,%ebp
	andl	$0x0000ff00,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0x00ff0000,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0xff000000,%ebp
	orl	%ebp,%edi
	pushl	%edi

	C // second column
	C b c d a
	movl	%eax,%edi
	andl	$0xff000000,%edi
	movl	%ebx,%ebp
	andl	$0x000000ff,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0x0000ff00,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0x00ff0000,%ebp
	orl	%ebp,%edi
	pushl	%edi

	C // third column
	C c d a b
	movl	%eax,%edi
	andl	$0x00ff0000,%edi
	movl	%ebx,%ebp
	andl	$0xff000000,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0x000000ff,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0x0000ff00,%ebp
	orl	%ebp,%edi
	pushl	%edi

	C // fourth column
	C d a b c
	movl	%eax,%edi
	andl	$0x0000ff00,%edi
	movl	%ebx,%ebp
	andl	$0x00ff0000,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0xff000000,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0x000000ff,%ebp
	orl	%ebp,%edi
	movl	%edi,%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	xchgl	%ebx,%edx

	C // inverse S-box substitution
	mov	$4,%edi
.isb_sub:
	movl	%eax,%ebp
	andl	$0x000000ff,%ebp
	movb	isbox(%ebp),%al
	roll	$8,%eax

	movl	%ebx,%ebp
	andl	$0x000000ff,%ebp
	movb	isbox(%ebp),%bl
	roll	$8,%ebx

	movl	%ecx,%ebp
	andl	$0x000000ff,%ebp
	movb	isbox(%ebp),%cl
	roll	$8,%ecx

	movl	%edx,%ebp
	andl	$0x000000ff,%ebp
	movb	isbox(%ebp),%dl
	roll	$8,%edx

	decl	%edi
	jnz	.isb_sub

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
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret
.eord:
	.size	aes_decrypt,.eord-aes_decrypt

C 	.align 16
C .globl aes_setup
C 	.type	aes_setup,@function
C aes_decrypt:
C 	C // save all registers that need to be saved
C 	pushl	%ebx		C  16(%esp)
C 	pushl	%ebp		C  12(%esp)
C 	pushl	%esi		C  8(%esp)
C 	pushl	%edi		C  4(%esp)
C 	movl	20(%esp),%esi	/* context structure */
C 	movl	24(%esp),%ecx	/* key size */
C 	movl	28(%esp),%edi	/* original key */
C 	/* This code assumes that the key length given is greater than
C 	   or equal to 4 words (128 bits).  BAD THINGS WILL HAPPEN
C 	   OTHERWISEC */
C 	shrl	$2,%ecx		/* divide by 4 to get total key length */
C 	movl	%ecx,%edx	/* calculate the number of rounds */
C 	addl	$6,%edx		/* key length in words + 6 = num. rounds */
C 	/* copy the initial key into the context structure */
C 	pushl	%ecx
C .key_copy_loop:	
C 	movl	(%edi),%eax
C 	addl	$4,%edi
C 	movl	%eax,(%esi)
C 	addl	$4,%esi
C 	decl	%ecx
C 	jnz	.key_copy_loop
C 	popl	%ecx
C 	incl	%edx		/* number of rounds + 1 */
C 	shll	$2,%edx		/* times aes blk size 4words */
C 	subl	%ecx,%edx	/* # of other keys to make */
C 	movl	%ecx,%ebp
C 	decl	%ecx		/* turn ecx into a mask */
C 	movl	$1,%ebx		/* round constant */
C .keygen_loop:
C 	movl	-4(%esi),%eax	/* previous key */
C 	testl	%ecx,%ebp
C 	jnz	.testnk
C 	/* rotate and substitute */
C 	roll	$8,%eax
C 	movl	%eax,%edi
C 	andl	$0xff,%eax
