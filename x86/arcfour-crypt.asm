C nettle, low-level cryptographics library
C 
C Copyright (C) 2004, Niels Möller
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

	.file "arcfour-crypt.asm"

	C arcfour_crypt(struct arcfour_ctx *ctx,
	C               unsigned length, uint8_t *dst,
	C               const uint8_t *src)
	.text
	.align 16
	.globl nettle_arcfour_crypt
	.type  nettle_arcfour_crypt,@function
nettle_arcfour_crypt:
	C save all registers that need to be saved
	pushl	%ebx		C  16(%esp)
	pushl	%ebp		C  12(%esp)
	pushl	%esi		C  8(%esp)
	pushl	%edi		C  4(%esp)

	C ctx = 20(%esp)
	C length = 24(%esp)
	C dst = 28(%esp)
	C src = 32(%esp)

	movl	24(%esp), %edx		C  length
	testl	%edx,%edx
	jz	.Lend

	movl	20(%esp), %ebp		C  ctx
	movl	28(%esp), %edi
	movl	32(%esp), %esi
	addl	%esi, %edx		C  Keep src + length
	
	movzbl  256(%ebp), %eax		C  i
	movzbl  257(%ebp), %ebx		C  j
.Lloop:
	incb	%al
	movzbl  (%ebp, %eax), %ecx	C  si. Clears high bytes
	addb    %cl, %bl
	movb    (%ebp, %ebx), %ch	C  sj
	movb    %ch, (%ebp, %eax)
	addb    %ch, %cl
	xorb    %ch, %ch		C  Clear, so it can be used
					C  for indexing.
	movb    (%ebp, %ecx), %cl
	xorb    (%esi), %cl
	incl    %esi
	movb    %cl, (%edi)
	incl    %edi
	cmpl	%esi, %edx
	jne	.Lloop
.Lend:
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret
.Leord:
	.size	nettle_arcfour_crypt,.Leord-nettle_arcfour_crypt
