C nettle, low-level cryptographics library
C 
C Copyright (C) 2013, Niels Möller
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

C Register usage:

define(<XP>, <%rdi>)
define(<TABLE>, <%rsi>)
define(<XW>, <%rax>)
define(<CNT>, <%ecx>)
define(<Z0>, <%rdx>)
define(<Z1>, <%r8>)
define(<T0>, <%r9>)
define(<T1>, <%r10>)
define(<T2>, <%r11>)
define(<SHIFT_TABLE>, <%rbx>)
	
C The C code is 12.5 c/byte, slower than sha1 (10.6), while this code runs
C at 10.2, slightly faster. Benchmarked on a low-end AMD E-350.

	.file "gcm-gf-mul-8.asm"
	
	C void _gcm_gf_mul_8(union gcm_block *x, const union gcm_block *table)
	.text
	ALIGN(16)
PROLOGUE(_nettle_gcm_gf_mul_8)
	W64_ENTRY(2, 0)
	push	%rbx
	mov	8(XP), XW
	rol	$8, XW
	movzbl	LREG(XW), XREG(T0)
	shl	$4, T0
	mov	(TABLE, T0), Z0
	mov	8(TABLE, T0), Z1
	lea	.Lshift_table(%rip), SHIFT_TABLE
	movl	$7, CNT
	call	.Lmul_word
	mov	(XP), XW
	movl	$8, CNT
	call	.Lmul_word
	mov	Z0, (XP)
	mov	Z1, 8(XP)
	W64_EXIT(2, 0)
	pop	%rbx
	ret

.Lmul_word:
	C shift Z1, Z0, transforming
	C +-----------------------+-----------------------+
	C |15 14 13 12 11 10 09 08|07 06 05 04 03 02 01 00|
	C +-----------------------+-----------------------+
	C into
	C +-----------------------+-----------------------+
	C |14 13 12 11 10 09 08 07|06 05 04 03 02 01 00   |
	C +-----------------------+-----------------+-----+
	C                               xor         |T[15]|
	C                                           +-----+
	mov	Z1, T1
	mov	Z0, T0
	shl	$8, Z1		C Use shld?
	shl	$8, Z0
	shr	$56, T1
	shr	$56, T0
	movzwl	(SHIFT_TABLE, T1, 2), XREG(T1)
	rol	$8, XW
	add	T0, Z1
	xor	T1, Z0
	movzbl	LREG(XW), XREG(T2)
	shl	$4, T2
	xor	(TABLE, T2), Z0
	xor	8(TABLE, T2), Z1
	decl	CNT
	jne	.Lmul_word
	ret
	
EPILOGUE(_nettle_gcm_gf_mul_8)

define(<W>, <0x$2$1>)
	.section .rodata
	ALIGN(2)
.Lshift_table:
.hword W(00,00),W(01,c2),W(03,84),W(02,46),W(07,08),W(06,ca),W(04,8c),W(05,4e)
.hword W(0e,10),W(0f,d2),W(0d,94),W(0c,56),W(09,18),W(08,da),W(0a,9c),W(0b,5e)
.hword W(1c,20),W(1d,e2),W(1f,a4),W(1e,66),W(1b,28),W(1a,ea),W(18,ac),W(19,6e)
.hword W(12,30),W(13,f2),W(11,b4),W(10,76),W(15,38),W(14,fa),W(16,bc),W(17,7e)
.hword W(38,40),W(39,82),W(3b,c4),W(3a,06),W(3f,48),W(3e,8a),W(3c,cc),W(3d,0e)
.hword W(36,50),W(37,92),W(35,d4),W(34,16),W(31,58),W(30,9a),W(32,dc),W(33,1e)
.hword W(24,60),W(25,a2),W(27,e4),W(26,26),W(23,68),W(22,aa),W(20,ec),W(21,2e)
.hword W(2a,70),W(2b,b2),W(29,f4),W(28,36),W(2d,78),W(2c,ba),W(2e,fc),W(2f,3e)
.hword W(70,80),W(71,42),W(73,04),W(72,c6),W(77,88),W(76,4a),W(74,0c),W(75,ce)
.hword W(7e,90),W(7f,52),W(7d,14),W(7c,d6),W(79,98),W(78,5a),W(7a,1c),W(7b,de)
.hword W(6c,a0),W(6d,62),W(6f,24),W(6e,e6),W(6b,a8),W(6a,6a),W(68,2c),W(69,ee)
.hword W(62,b0),W(63,72),W(61,34),W(60,f6),W(65,b8),W(64,7a),W(66,3c),W(67,fe)
.hword W(48,c0),W(49,02),W(4b,44),W(4a,86),W(4f,c8),W(4e,0a),W(4c,4c),W(4d,8e)
.hword W(46,d0),W(47,12),W(45,54),W(44,96),W(41,d8),W(40,1a),W(42,5c),W(43,9e)
.hword W(54,e0),W(55,22),W(57,64),W(56,a6),W(53,e8),W(52,2a),W(50,6c),W(51,ae)
.hword W(5a,f0),W(5b,32),W(59,74),W(58,b6),W(5d,f8),W(5c,3a),W(5e,7c),W(5f,be)
.hword W(e1,00),W(e0,c2),W(e2,84),W(e3,46),W(e6,08),W(e7,ca),W(e5,8c),W(e4,4e)
.hword W(ef,10),W(ee,d2),W(ec,94),W(ed,56),W(e8,18),W(e9,da),W(eb,9c),W(ea,5e)
.hword W(fd,20),W(fc,e2),W(fe,a4),W(ff,66),W(fa,28),W(fb,ea),W(f9,ac),W(f8,6e)
.hword W(f3,30),W(f2,f2),W(f0,b4),W(f1,76),W(f4,38),W(f5,fa),W(f7,bc),W(f6,7e)
.hword W(d9,40),W(d8,82),W(da,c4),W(db,06),W(de,48),W(df,8a),W(dd,cc),W(dc,0e)
.hword W(d7,50),W(d6,92),W(d4,d4),W(d5,16),W(d0,58),W(d1,9a),W(d3,dc),W(d2,1e)
.hword W(c5,60),W(c4,a2),W(c6,e4),W(c7,26),W(c2,68),W(c3,aa),W(c1,ec),W(c0,2e)
.hword W(cb,70),W(ca,b2),W(c8,f4),W(c9,36),W(cc,78),W(cd,ba),W(cf,fc),W(ce,3e)
.hword W(91,80),W(90,42),W(92,04),W(93,c6),W(96,88),W(97,4a),W(95,0c),W(94,ce)
.hword W(9f,90),W(9e,52),W(9c,14),W(9d,d6),W(98,98),W(99,5a),W(9b,1c),W(9a,de)
.hword W(8d,a0),W(8c,62),W(8e,24),W(8f,e6),W(8a,a8),W(8b,6a),W(89,2c),W(88,ee)
.hword W(83,b0),W(82,72),W(80,34),W(81,f6),W(84,b8),W(85,7a),W(87,3c),W(86,fe)
.hword W(a9,c0),W(a8,02),W(aa,44),W(ab,86),W(ae,c8),W(af,0a),W(ad,4c),W(ac,8e)
.hword W(a7,d0),W(a6,12),W(a4,54),W(a5,96),W(a0,d8),W(a1,1a),W(a3,5c),W(a2,9e)
.hword W(b5,e0),W(b4,22),W(b6,64),W(b7,a6),W(b2,e8),W(b3,2a),W(b1,6c),W(b0,ae)
.hword W(bb,f0),W(ba,32),W(b8,74),W(b9,b6),W(bc,f8),W(bd,3a),W(bf,7c),W(be,be)
	
	
