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
