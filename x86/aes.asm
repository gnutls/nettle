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

	movl	24(%esp), %ebp
	C What's the right way to set the flags?
	addl	$0, %ebp
	jz	.Ldecrypt_end
	
.Ldecrypt_block_loop:
	movl	32(%esp),%esi	C  address of ciphertext
	movl	(%esi),%eax	C  load ciphertext into registers
	movl	4(%esi),%ebx
	movl	8(%esi),%ecx
	movl	12(%esi),%edx
	
	addl	$16, 32(%esp)	C Increment src pointer
	
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
.Ldecrypt_loop:
	pushl	%esi		C  save this first: we'll clobber it later

	C Why???
	xchgl	%ebx,%edx

	C // First column
	C a b c d
	movl	%eax,%esi	C  copy first in
	andl	$0x000000ff,%esi C  clear all but offset
	shll	$2,%esi		C  index in itbl1
	movl	AES_TABLE0 + _aes_decrypt_table (%esi),%edi
	movl	%ebx,%esi	C  second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi C  clear all but offset bytes
	xorl	AES_TABLE1 + _aes_decrypt_table (%esi),%edi
	movl	%ecx,%esi	C  third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	AES_TABLE2 + _aes_decrypt_table (%esi),%edi
	movl	%edx,%esi	C  fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	AES_TABLE3 + _aes_decrypt_table (%esi),%edi
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
	jnz	.Ldecrypt_loop

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
.Lisubst:
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

C Some performance figures, measured on a 
C 930 MHz Pentium III with 1854 bogomips.
C
C Optimized C code
C
C        aes128 (ECB encrypt): 1.04s, 9.615MB/s
C        aes128 (ECB decrypt): 1.04s, 9.615MB/s
C        aes128 (CBC encrypt): 1.21s, 8.264MB/s
C        aes128 (CBC decrypt): 1.10s, 9.091MB/s
C 
C        aes192 (ECB encrypt): 1.25s, 8.000MB/s
C        aes192 (ECB decrypt): 1.24s, 8.065MB/s
C        aes192 (CBC encrypt): 1.40s, 7.143MB/s
C        aes192 (CBC decrypt): 1.29s, 7.752MB/s
C 
C        aes256 (ECB encrypt): 1.43s, 6.993MB/s
C        aes256 (ECB decrypt): 1.44s, 6.944MB/s
C        aes256 (CBC encrypt): 1.60s, 6.250MB/s
C        aes256 (CBC decrypt): 1.49s, 6.711MB/s
C
C Assembler code
C
C        aes128 (ECB encrypt): 0.50s, 20.000MB/s
C        aes128 (ECB decrypt): 0.48s, 20.833MB/s
C        aes128 (CBC encrypt): 0.63s, 15.873MB/s
C        aes128 (CBC decrypt): 0.54s, 18.519MB/s
C 
C        aes192 (ECB encrypt): 0.54s, 18.519MB/s
C        aes192 (ECB decrypt): 0.55s, 18.182MB/s
C        aes192 (CBC encrypt): 0.69s, 14.493MB/s
C        aes192 (CBC decrypt): 0.60s, 16.667MB/s
C 
C        aes256 (ECB encrypt): 0.62s, 16.129MB/s
C        aes256 (ECB decrypt): 0.62s, 16.129MB/s
C        aes256 (CBC encrypt): 0.76s, 13.158MB/s
C        aes256 (CBC decrypt): 0.67s, 14.925MB/s
