C s390x/vf/sha3-permute.asm

ifelse(`
   Copyright (C) 2012 Niels Möller
   Copyright (C) 2021 Mamone Tarsha
   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
')

define(`STATE', `%r2')       C 25 64-bit values, 200 bytes.

define(`COUNT', `%r3')

define(`A00',  `%r0')
define(`A0102', `%v0')
define(`A0304', `%v1')

define(`A05',  `%r4')
define(`A0607', `%v2')
define(`A0809', `%v3')
	
define(`A10',  `%r5')
define(`A1112', `%v4')
define(`A1314', `%v5')

define(`A15',  `%r6')
define(`A1617', `%v6')
define(`A1819', `%v7')
	
define(`A20',  `%r7')
define(`A2122', `%v8')
define(`A2324', `%v9')

define(`C0', `%r8')
define(`C12', `%v24')
define(`C34', `%v25')

define(`D0', `%r9')
define(`D12', `%v26')
define(`D34', `%v27')

C Wide temporaries
define(`W0', `%v28')
define(`W1', `%v29')
define(`W2', `%v30')
define(`W3', `%v31')

define(`TMP', `%r9')

define(`T0', `%r10')
define(`T1', `%r11')
define(`T2', `%r12')
define(`T3', `%r13')

define(`RC', `%r14')

.file "sha3-permute.asm"

.text

C void
C sha3_permute(struct sha3_ctx *ctx)

PROLOGUE(nettle_sha3_permute)
    stmg           %r6,%r14,48(SP)
    ALLOC_STACK(%r1,16)
    std            %f8,0(%r1)
    std            %f9,8(%r1)
  
    lghi           COUNT,24*8
    larl           RC,.rc
    aghi           RC,-8
  
    lg             A00,0*8(STATE)
    vl             A0102,1*8(STATE)
    vl             A0304,3*8(STATE)

    lg             A05,5*8(STATE)
    vl             A0607,6*8(STATE)
    vl             A0809,8*8(STATE)
    xgrk           C0,A00,A05
    vx             C12,A0102,A0607
    vx             C34,A0304,A0809

    lg             A10,10*8(STATE)
    vl             A1112,11*8(STATE)
    vl             A1314,13*8(STATE)
    xgr            C0,A10
    vx             C12,C12,A1112
    vx             C34,C34,A1314

    lg             A15,15*8(STATE)
    vl             A1617,16*8(STATE)
    vl             A1819,18*8(STATE)
    xgr            C0,A15
    vx             C12,C12,A1617
    vx             C34,C34,A1819

    lg             A20,20*8(STATE)
    vl             A2122,21*8(STATE)
    vl             A2324,23*8(STATE)
    xgr            C0,A20
    vx             C12,C12,A2122
    vx             C34,C34,A2324

    j              .Loop

.align  16
.Loop:
    vlvgg          D12,C0,0
    vmrhg          D12,D12,C12           C Holds C0, C1
    vpdi           D34,C12,C34,0b0100    C Holds C2, C3
    vpdi           C34,C34,D12,0b0100    C Holds C4, C0
    vlgvg          D0,C34,0
    vlgvg          T0,C12,0
    rllg           T0,T0,1
    xgr            D0,T0

    C Can use C12 as temporary
    veslg          W0,D34,1
    vesrlg         W1,D34,63
    vx             D12,D12,W0
    vx             D12,D12,W1            C Done D12

    veslg          C12,C34,1
    vesrlg         C34,C34,63
    vx             D34,D34,C34
    vx             D34,D34,C12           C Done D34

    xgr            A00,D0
    xgr            A05,D0
    xgr            A10,D0
    xgr            A15,D0
    xgr            A20,D0
    vx             A0102,A0102,D12
    vx             A0607,A0607,D12
    vx             A1112,A1112,D12
    vx             A1617,A1617,D12
    vx             A2122,A2122,D12
    vx             A0304,A0304,D34
    vx             A0809,A0809,D34
    vx             A1314,A1314,D34
    vx             A1819,A1819,D34
    vx             A2324,A2324,D34

    C Do the 1,2,3,4 row. First rotate, then permute.
    vesrlg         W0,A0102,63
    veslg          W1,A0102,62
    vesrlg         W2,A0102,2
    veslg          A0102,A0102,1
    vo             W0,W0,A0102           C veslg 1  (A01)
    vo             W2,W2,W1              C veslg 62 (A02)

    veslg          A0102,A0304,28
    vesrlg         W1,A0304,36
    vo             A0102,A0102,W1        C veslg 28 (A03)
    vesrlg         W1,A0304,37
    veslg          A0304,A0304,27
    vo             A0304,A0304,W1        C veslg 27 (A04)

    vmrhg          A0102,A0102,W0
    vmrlg          A0304,A0304,W2

    rllg           A05,A05,36
    vlvgg          W0,A05,0
    vlgvg          A05,A0607,0
    rllg           A05,A05,44            C Done A05
    verllg         W1,A0607,6
    verllg         A0607,A0809,20
    vmrlg          A0607,A0607,W1        C Done A0607
    verllg         W1,A0809,55
    vmrhg          A0809,W0,W1           C Done A0809

    rllg           A10,A10,42            C 42 + 25 = 3 (mod 64)
    verllg         W0,A1112,10
    vlvgg          A1112,A10,0
    vlgvg          A10,A1112,1
    rllg           A10,A10,43            C Done A10

    vmrhg          A1112,A1112,A1314
    verllg         A1112,A1112,25        C Done A1112
    verllg         W2,A1314,39
    vpdi           A1314,W0,W2,0b0001    C Done A1314

    verllg         W0,A1819,8
    rllg           A15,A15,41
    vlvgg          W1,A15,1
    vlgvg          A15,A1819,0
    rllg           A15,A15,21            C Done A15
    verllg         A1819,A1617,15
    verllg         A1617,A1617,45
    vpdi           A1617,A1617,W0,0b0001 C Done A1617
    vmrlg          A1819,A1819,W1        C Done A1819

    rllg           A20,A20,18
    vlvgg          W0,A20,1
    vlgvg          A20,A2324,1
    rllg           A20,A20,14            C Done A20
    verllg         A2324,A2324,56

    verllg         W2,A2122,2
    vmrhg          A2324,A2324,W2        C Done A2324

    verllg         A2122,A2122,61
    vmrlg          A2122,A2122,W0        C Done A2122

	  C chi step. With the transposed matrix, applied independently
	  C to each column.
    lghi           TMP,-1
    xgrk           T0,A05,TMP
    ngr            T0,A10
    xgrk           T1,A10,TMP
    ngr            T1,A15
    xgrk           T2,A15,TMP
    ngr            T2,A20
    xgr            A10,T2
    xgrk           T3,A20,TMP
    ngr            T3,A00
    xgr            A15,T3
    xgrk           T2,A00,TMP
    ngr            T2,A05
    xgr            A20,T2
    xgr            A00,T0
    xgr            A05,T1

    vnc            W0,A1112,A0607
    vnc            W1,A1617,A1112
    vnc            W2,A2122,A1617
    vx             A1112,A1112,W2
    vnc            W3,A0102,A2122
    vx             A1617,A1617,W3
    vnc            W2,A0607,A0102
    vx             A2122,A2122,W2
    vx             A0102,A0102,W0
    vx             A0607,A0607,W1

    vnc            W0,A1314,A0809
    vnc            W1,A1819,A1314
    vnc            W2,A2324,A1819
    vx             A1314,A1314,W2
    vnc            W3,A0304,A2324
    vx             A1819,A1819,W3
    vnc            W2,A0809,A0304
    vx             A2324,A2324,W2
    vx             A0304,A0304,W0
    vx             A0809,A0809,W1

    lg             TMP,0(COUNT,RC)
    xgr            A00,TMP

    C Transpose.
    C Swap (A05, A10) <->  A0102, and (A15, A20) <->  A0304,
    C and also copy to C12 and C34 while at it.

    vlvgg          C12,A05,0
    vlvgg          C34,A15,0
    vlvgg          W0,A10,0
    vlvgg          W1,A20,0
    vlgvg          A05,A0102,0
    vlgvg          A15,A0304,0
    xgrk           C0,A00,A05
    xgr            C0,A15
    vlgvg          A10,A0102,1
    vlgvg          A20,A0304,1
    vmrhg          A0102,C12,W0
    vmrhg          A0304,C34,W1

    C Transpose (A0607, A1112)
    vlr            W0,A0607
    vmrhg          A0607,A0607,A1112
    xgr            C0,A10
    xgr            C0,A20
    vmrlg          A1112,W0,A1112

    C Transpose (A1819, A2324)
    vlr            W0,A1819
    vmrhg          A1819,A1819,A2324
    vx             C12,A0102,A0607
    vx             C12,C12,A1112
    vmrlg          A2324,W0,A2324

    C Transpose (A0809, A1314) and (A1617, A2122), and swap
    vlr            W0,A0809
    vlr            W1,A1314
    vx             C34,A0304,A1819
    vx             C34,C34,A2324
    vmrhg          A0809,A1617,A2122
    vmrlg          A1314,A1617,A2122
    vx             C34,C34,A0809
    vx             C34,C34,A1314
    vmrhg          A1617,W0,W1
    vmrlg          A2122,W0,W1

    ahi            COUNT,-8
    vx             C12,C12,A1617
    vx             C12,C12,A2122
    clijne         COUNT,0,.Loop

    stg            A00,0*8(STATE)
    vst            A0102,1*8(STATE)
    vst            A0304,3*8(STATE)

    stg            A05,5*8(STATE)
    vst            A0607,6*8(STATE)
    vst            A0809,8*8(STATE)

    stg            A10,10*8(STATE)
    vst            A1112,11*8(STATE)
    vst            A1314,13*8(STATE)

    stg            A15,15*8(STATE)
    vst            A1617,16*8(STATE)
    vst            A1819,18*8(STATE)

    stg            A20,20*8(STATE)
    vst            A2122,21*8(STATE)
    vst            A2324,23*8(STATE)

    ld             %f8,0(%r1)
    ld             %f9,8(%r1)
    FREE_STACK(16)
    lmg            %r6,%r14,48(SP)

    br             RA
EPILOGUE(nettle_sha3_permute)

.align  16
.rc:	C In reverse order
	.quad	0x8000000080008008
	.quad	0x0000000080000001
	.quad	0x8000000000008080
	.quad	0x8000000080008081
	.quad	0x800000008000000A
	.quad	0x000000000000800A
	.quad	0x8000000000000080
	.quad	0x8000000000008002
	.quad	0x8000000000008003
	.quad	0x8000000000008089
	.quad	0x800000000000008B
	.quad	0x000000008000808B
	.quad	0x000000008000000A
	.quad	0x0000000080008009
	.quad	0x0000000000000088
	.quad	0x000000000000008A
	.quad	0x8000000000008009
	.quad	0x8000000080008081
	.quad	0x0000000080000001
	.quad	0x000000000000808B
	.quad	0x8000000080008000
	.quad	0x800000000000808A
	.quad	0x0000000000008082
	.quad	0x0000000000000001
.size	.rc,.-.rc
