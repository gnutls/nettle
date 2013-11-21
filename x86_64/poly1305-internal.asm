C nettle, low-level cryptographics library
C 
C Copyright (C) 2013 Niels Möller
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
C the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
C MA 02111-1301, USA.

	.file "poly1305-internal.asm"

C Registers mainly used by poly1305_block
define(<CTX>, <%rdi>)
define(<T0>, <%rcx>)
define(<T1>, <%rsi>)
define(<T2>, <%r8>)
define(<H0>, <%r9>)
define(<H1>, <%r10>)
define(<H2>, <%r11>)
	
	C poly1305_set_key(struct poly1305_ctx *ctx, const uint8_t key[16])
	.text
	C Registers:
	C  %rdi: ctx
	C  %rsi: key
	C  %r8: mask
	ALIGN(16)
PROLOGUE(nettle_poly1305_set_key)
	W64_ENTRY(2,0)
	mov	$0x0ffffffc0fffffff, %r8
	mov	(%rsi), %rax
	and	%r8, %rax
	and	$-4, %r8
	mov	%rax, (CTX)
	mov	8(%rsi), %rax
	and	%r8, %rax
	mov	%rax, P1305_R1 (CTX)
	shr	$2, %rax
	imul	$5, %rax
	mov	%rax, P1305_S1 (CTX)
	xor	XREG(%rax), XREG(%rax)
	mov	%rax, P1305_H0 (CTX)
	mov	%rax, P1305_H1 (CTX)
	mov	XREG(%rax), P1305_H2 (CTX)
	mov	XREG(%rax), P1305_INDEX (CTX)
	
	W64_EXIT(2,0)
	ret

EPILOGUE(nettle_poly1305_set_key)

C 64-bit multiplication mod 2^130 - 5
C
C (x_0 + B x_1 + B^2 x_1) * (r_0 + B r_1) =
C     1   B B^2 B^3 
C   x_0 r_0
C       x_0 r_1
C	x_1 r_0
C	    x_1 r_1
C	    x_2 r_0
C               x_2 r_1
C Then r_1 B^2 = r_1/4 (2^130) = 5/4 r_1.
C and  r_1 B^3 = 5/4 B r_1
C So we get
C
C  x_0 r_0 + x_1 (5/4 r_1) + B (x_0 r_1 + x_1 r_0 + x_2 5/4 r_1 + B x_2 r_0)	

	C poly1305_block (struct poly1305_ctx *ctx, const uint8_t m[16])
	
PROLOGUE(nettle_poly1305_block)
	mov	(%rsi), T0
	mov	8(%rsi), T1
	mov	$1,	T2
C FIXME: Support windows ABI 
	C Registers:
	C Inputs:  CTX, T0, T1, T2,
	C Outputs: H0, H1, H2, stored into the context.

C_NAME(poly1305_block):
	add	P1305_H0 (CTX), T0
	adc	P1305_H1 (CTX), T1
	adc	P1305_H2 (CTX), XREG(T2)
	mov	P1305_R0 (CTX), %rax
	mul	T0
	mov	%rax, H0
	mov	%rdx, H1
	mov	P1305_S1 (CTX), %rax	C 5/4 r1
	mov	%rax, H2
	mul	T1
	imul	T2, H2
	imul	P1305_R0 (CTX), T2
	add	%rax, H0
	adc	%rdx, H1
	mov	P1305_R0 (CTX), %rax
	mul	T1
	add	%rax, H2
	adc	%rdx, T2
	mov	P1305_R1 (CTX), %rax
	mul	T0
	add	%rax, H2
	adc	%rdx, T2
	mov	T2, %rax
	shr	$2, %rax
	imul	$5, %rax
	and	$3, XREG(T2)
	add	%rax, H0
	adc	H2, H1
	adc	$0, XREG(T2)
	mov	H0, P1305_H0 (CTX)
	mov	H1, P1305_H1 (CTX)
	mov	XREG(T2), P1305_H2 (CTX)
	ret
EPILOGUE(nettle_poly1305_block)

	C poly1305_digest (struct poly1305_ctx *ctx,
 	C		   size_t length, uint8_t *digest,
	C		   const uint8_t *s)
	C Registers:
	C   %rdi: ctx
	C   %rsi: length
	C   %rdx: digest
	C   %rcx: s
	
PROLOGUE(nettle_poly1305_digest)
	W64_ENTRY(4, 0)
	mov	P1305_INDEX (CTX), XREG(%rax)
	push	%rsi
	push	%rdx
	push	%rcx
	test	XREG(%rax), XREG(%rax)
	jz	.Lfinal

	C Pad with a 1 byte.
	C FIXME: Or in, without storing in memory.
	inc	XREG(%rax)	C Also clears high half
	movb	$1, P1305_BLOCK-1 (CTX, %rax)
	
	mov	XREG(%rax), XREG(%rcx)
	mov	$1, T1
	and	$7, XREG(%rcx)	
	shl	$3, XREG(%rcx)
	shl	LREG(%rcx), T1
	dec	T1
	mov	P1305_BLOCK (CTX), T0
	xor	T2, T2
	cmp	$8, XREG(%rax)
	jc	.Lfinal_lt8
	C	If %rax == 16, we get T1 == 0,
	C 	tweak so we get need T1 = -1 instead.
	cmp	$16, XREG(%rax)
	adc	$-1, T1
	and	P1305_BLOCK+8 (CTX), T1
	jmp	.Lfinal_block

.Lfinal_lt8:
	and	T1, T0
	xor	T1, T1
.Lfinal_block:

	call	poly1305_block

.Lfinal:

	mov	P1305_H0 (CTX), H0
	mov	P1305_H1 (CTX), H1
	mov	P1305_H2 (CTX), XREG(H2)
	mov	XREG(H2), XREG(%rax)
	shr	$2, XREG(%rax)
	and	$3, H2
	imul	$5, XREG(%rax)
	add	%rax, H0
	adc	$0, H1
	adc	$0, XREG(H2)

	C Add 5, use result if >= 2^130
	mov	$5, T0
	xor	T1, T1
	add	H0, T0
	adc	H1, T1
	adc	$0, XREG(H2)
	cmp	$4, XREG(H2)
	cmovnc	T0, H0
	cmovnc	T1, H1

	pop	%rcx
	pop	%rdx
	pop	%rsi

	add	(%rcx), H0
	adc	8(%rcx), H1

	C Store, taking length into account
	cmp	$8, %rsi
	jc	.Ldigest_lt8
	mov	H0, (%rdx)
	jz	.Ldigest_done
	cmp	$16, %rsi
	jc	.Ldigest_lt16
	mov	H1, 8(%rdx)
	jmp	.Ldigest_done
.Ldigest_lt16:
	mov	H1, H0
	add	$8, %rdx
	sub	$8, %rsi
.Ldigest_lt8:
	movb	LREG(H0), (%rdx)
	shr	$8, H0
	inc	%rdx
	dec	%rsi
	jnz	.Ldigest_lt8
.Ldigest_done:
	xor	XREG(%rax), XREG(%rax)
	mov	%rax, P1305_H0 (CTX)
	mov	%rax, P1305_H1 (CTX)
	mov	XREG(%rax), P1305_H2 (CTX)
	mov	XREG(%rax), P1305_INDEX (CTX)
	W64_EXIT(4, 0)
	ret

