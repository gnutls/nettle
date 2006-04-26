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
	ALIGN(4)
PROLOGUE(nettle_arcfour_crypt)
	C save all registers that need to be saved
	pushl	%ebx		C  12(%esp)
	pushl	%ebp		C  8(%esp)
	pushl	%esi		C  4(%esp)
	pushl	%edi		C  0(%esp)

C Input arguments:
	C ctx = 20(%esp)
	C length = 24(%esp)
	C dst = 28(%esp)
	C src = 32(%esp)
C Register usage:
	C %ebp = ctx
	C %esi = src (updated through out loop)
	C %edi = dst (updated through out loop)
	C %edx = src + length (end of source area)
	C %eax = i
	C %ebx = j
	C %cl  = si
	C %ch  = sj

	movl	24(%esp), %edx		C  length
	testl	%edx,%edx
	jz	.Lend

	movl	20(%esp), %ebp		C  ctx
	movl	28(%esp), %edi
	movl	32(%esp), %esi
	addl	%esi, %edx		C  Keep src + length
	
	movzbl  ARCFOUR_I (%ebp), %eax	C  i
	movzbl  ARCFOUR_J (%ebp), %ebx	C  j
.Lloop:
C	incb	%al
	incl	%eax
	andl	$0xff, %eax
	movzbl  (%ebp, %eax), %ecx	C  si. Clears high bytes
	addb    %cl, %bl
C The addl andl is preferable on PPro and PII, but slows thing down on AMD Duron.
C	addl	%ecx, %ebx
C	andl	$0xff, %ebx
	movb    (%ebp, %ebx), %ch	C  sj
	movb    %ch, (%ebp, %eax)	C  S[i] = sj
	movb	%cl, (%ebp, %ebx)	C  S[j] = si
	addb    %ch, %cl
	movzbl  %cl, %ecx		C  Clear, so it can be used
					C  for indexing.
	movb    (%ebp, %ecx), %cl
	xorb    (%esi), %cl
	incl    %esi
	movb    %cl, (%edi)
	incl    %edi
	cmpl	%esi, %edx
	jne	.Lloop

	movb	%al, ARCFOUR_I (%ebp)		C  Store the new i and j.
	movb	%bl, ARCFOUR_J (%ebp)
.Lend:
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret
EPILOGUE(nettle_arcfour_crypt)
