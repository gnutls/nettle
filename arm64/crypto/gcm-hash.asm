C arm64/crypto/gcm-hash.asm

ifelse(`
   Copyright (C) 2020 Niels Möller and Mamone Tarsha
   Copyright (C) 2021 Michael Weiser
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

.file "gcm-hash.asm"
.arch armv8-a+crypto

.text

C gcm_set_key() assigns H value in the middle element of the table
define(`H_Idx', `128')

C common SIMD register usage:
define(`POLY', `v6')
C temporary register that assist the reduction procedure
define(`T', `v7')
C permenant register that hold the 16-byte result of pmull
define(`F', `v16')
C permenant register that hold the 16-byte result of pmull2,
C its value is accumulated on 'F' register immediately
define(`F1', `v17')
C permenant register that hold the 16-byte result of pmull
define(`R', `v18')
C permenant register that hold the 16-byte result of pmull2,
C its value is accumulated on 'F' register immediately
define(`R1', `v19')

C common macros:
C long multiply of six 64-bit polynomials and sum
C R = (in.l × param2.l) + (in.h × param2.h)
C F = (in.l × param3.l) + (in.h × param3.h)
C PMUL(in, param1, param2)
define(`PMUL', m4_assert_numargs(3)`
    pmull          F.1q,$3.1d,$1.1d
    pmull2         F1.1q,$3.2d,$1.2d
    pmull          R.1q,$2.1d,$1.1d
    pmull2         R1.1q,$2.2d,$1.2d
    eor            F.16b,F.16b,F1.16b
    eor            R.16b,R.16b,R1.16b
')
C Reduce 'R' and 'F' values to 128-bit output
C REDUCTION(out)
define(`REDUCTION', m4_assert_numargs(1)`
    pmull          T.1q,F.1d,POLY.1d
    eor            R.16b,R.16b,T.16b
    ext            R.16b,R.16b,R.16b,#8
    eor            $1.16b,F.16b,R.16b
')

    C void gcm_init_key (union gcm_block *table)

C This function populates the gcm table as the following layout
C *******************************************************************************
C | H1M = (H1 div x⁶⁴)||((H1 mod x⁶⁴) × (x⁶⁴+x⁶³+x⁶²+x⁵⁷)) div x⁶⁴              |
C | H1L = (H1 mod x⁶⁴)||(((H1 mod x⁶⁴) × (x⁶³+x⁶²+x⁵⁷)) mod x⁶⁴) + (H1 div x⁶⁴) |
C |                                                                             |
C | H2M = (H2 div x⁶⁴)||((H2 mod x⁶⁴) × (x⁶⁴+x⁶³+x⁶²+x⁵⁷)) div x⁶⁴              |
C | H2L = (H2 mod x⁶⁴)||(((H2 mod x⁶⁴) × (x⁶³+x⁶²+x⁵⁷)) mod x⁶⁴) + (H2 div x⁶⁴) |
C |                                                                             |
C | H3M = (H3 div x⁶⁴)||((H3 mod x⁶⁴) × (x⁶⁴+x⁶³+x⁶²+x⁵⁷)) div x⁶⁴              |
C | H3L = (H3 mod x⁶⁴)||(((H3 mod x⁶⁴) × (x⁶³+x⁶²+x⁵⁷)) mod x⁶⁴) + (H3 div x⁶⁴) |
C |                                                                             |
C | H4M = (H3 div x⁶⁴)||((H4 mod x⁶⁴) × (x⁶⁴+x⁶³+x⁶²+x⁵⁷)) div x⁶⁴              |
C | H4L = (H3 mod x⁶⁴)||(((H4 mod x⁶⁴) × (x⁶³+x⁶²+x⁵⁷)) mod x⁶⁴) + (H4 div x⁶⁴) |
C *******************************************************************************

C gcm_init_key register usage:
define(`TABLE', `x0')

define(`EMSB', `v0')
define(`B', `v1')
define(`H', `v2')
define(`H2', `v3')
define(`H3', `v4')
define(`H4', `v5')
define(`Hp', `v20')
define(`Hl', `v21')
define(`Hm', `v22')
define(`H1M', `v23')
define(`H1L', `v24')
define(`H2M', `v25')
define(`H2L', `v26')
define(`H3M', `v27')
define(`H3L', `v28')
define(`H4M', `v29')
define(`H4L', `v30')

C PMUL_PARAM(in, param1, param2)
define(`PMUL_PARAM', m4_assert_numargs(3)`
    pmull2         Hp.1q,$1.2d,POLY.2d
    eor            Hm.16b,$1.16b,Hp.16b
    ext            $2.16b,Hm.16b,$1.16b,#8
    ext            $3.16b,$1.16b,Hm.16b,#8
    ext            $2.16b,$2.16b,$2.16b,#8
')

PROLOGUE(_nettle_gcm_init_key)
    add            x1,TABLE,#16*H_Idx
    ld1            {H.2d},[x1]

    C we treat data as big-endian doublewords for processing. Since there is no
    C endianness-neutral MSB-first load operation we need to restore our desired
    C byte order on little-endian systems. The same holds true for DATA below
    C but not our own internal precalculated TABLE (see below).
IF_LE(`
    rev64          H.16b,H.16b
')
    C --- calculate H = H × x mod R(X); R(X) = (x¹²⁸+x¹²⁷+x¹²⁶+x¹²¹+1) ---

    dup            EMSB.16b,H.b[7]
    mov            x1,#0xC200000000000000
    mov            x2,#1
    mov            POLY.d[0],x1
    mov            POLY.d[1],x2
    sshr           EMSB.16b,EMSB.16b,#7
    and            EMSB.16b,EMSB.16b,POLY.16b
    ushr           B.2d,H.2d,#63
    and            B.16b,B.16b,POLY.16b
    ext            B.16b,B.16b,B.16b,#8
    shl            H.2d,H.2d,#1
    orr            H.16b,H.16b,B.16b
    eor            H.16b,H.16b,EMSB.16b

    dup            POLY.2d,POLY.d[0]

    C --- calculate H^2 = H × H ---

    PMUL_PARAM(H,H1M,H1L)

    PMUL(H,H1M,H1L)

    REDUCTION(H2)

    PMUL_PARAM(H2,H2M,H2L)

    C we store to the table as doubleword-vectors in current memory endianness
    C because it's our own strictly internal data structure and what gcm_hash
    C can most naturally use
    st1            {H1M.2d,H1L.2d,H2M.2d,H2L.2d},[TABLE],#64

    C --- calculate H^3 = H^1 × H^2 ---

    PMUL(H2,H1M,H1L)

    REDUCTION(H3)

    PMUL_PARAM(H3,H3M,H3L)

    C --- calculate H^4 = H^2 × H^2 ---

    PMUL(H2,H2M,H2L)

    REDUCTION(H4)

    PMUL_PARAM(H4,H4M,H4L)

    st1            {H3M.2d,H3L.2d,H4M.2d,H4L.2d},[TABLE]

    ret
EPILOGUE(_nettle_gcm_init_key)

C gcm_hash register usage:
define(`TABLE', `x0')
define(`X', `x1')
define(`LENGTH', `x2')
define(`DATA', `x3')

define(`D', `v0')
define(`C0', `v1')
define(`C1', `v2')
define(`C2', `v3')
define(`C3', `v4')
define(`R2', `v20')
define(`F2', `v21')
define(`R3', `v22')
define(`F3', `v23')
define(`H1M', `v24')
define(`H1L', `v25')
define(`H2M', `v26')
define(`H2L', `v27')
define(`H3M', `v28')
define(`H3L', `v29')
define(`H4M', `v30')
define(`H4L', `v31')

C PMUL_SUM(in, param1, param2)
define(`PMUL_SUM', m4_assert_numargs(3)`
    pmull          F2.1q,$3.1d,$1.1d
    pmull2         F3.1q,$3.2d,$1.2d
    pmull          R2.1q,$2.1d,$1.1d
    pmull2         R3.1q,$2.2d,$1.2d
    eor            F2.16b,F2.16b,F3.16b
    eor            R2.16b,R2.16b,R3.16b
    eor            F.16b,F.16b,F2.16b
    eor            R.16b,R.16b,R2.16b
')

C Load the final partial block into SIMD register,
C stored in little-endian order for each 64-bit part
C LOAD_REV_PARTIAL_BLOCK(out)
define(`LOAD_REV_PARTIAL_BLOCK', m4_assert_numargs(1)`
    tbz            LENGTH,3,Lless_8_bytes
    ldr            `d'substr($1,1,len($1)),[DATA],#8
IF_LE(`
    rev64          $1.16b,$1.16b
')
    mov            x7,#0
    mov            $1.d[1],x7
    tst            LENGTH,#7
    b.eq           Lload_done
Lless_8_bytes:
    mov            x6,#0
    mov            x5,#64
    and            x4,LENGTH,#7
Lload_byte_loop:
    mov            x7,#0
    ldrb           w7,[DATA],#1
    sub            x5,x5,#8
    lsl            x7,x7,x5
    orr            x6,x6,x7
    subs           x4,x4,#1
    b.ne           Lload_byte_loop
    tbz            LENGTH,3,Lstore_hi_dw
    mov            $1.d[1],x6
    b              Lload_done
Lstore_hi_dw:
    mov            x7,#0
    mov            $1.d[0],x6
    mov            $1.d[1],x7
Lload_done:
')

    C void gcm_hash (const struct gcm_key *key, union gcm_block *x,
    C                size_t length, const uint8_t *data)

PROLOGUE(_nettle_gcm_hash)
    mov            x4,#0xC200000000000000
    mov            POLY.d[0],x4

    ld1            {D.2d},[X]
IF_LE(`
    rev64          D.16b,D.16b
')

    ands           x4,LENGTH,#-64
    b.eq           L1_block

    add            x5,TABLE,#64
    ld1            {H1M.2d,H1L.2d,H2M.2d,H2L.2d},[TABLE]
    ld1            {H3M.2d,H3L.2d,H4M.2d,H4L.2d},[x5]

L4_blocks_loop:
    ld1            {C0.2d,C1.2d,C2.2d,C3.2d},[DATA],#64
IF_LE(`
    rev64          C0.16b,C0.16b
    rev64          C1.16b,C1.16b
    rev64          C2.16b,C2.16b
    rev64          C3.16b,C3.16b
')

    eor            C0.16b,C0.16b,D.16b

    PMUL(C1,H3M,H3L)
    PMUL_SUM(C2,H2M,H2L)
    PMUL_SUM(C3,H1M,H1L)
    PMUL_SUM(C0,H4M,H4L)

    REDUCTION(D)

    subs           x4,x4,#64
    b.ne           L4_blocks_loop

    and            LENGTH,LENGTH,#63

L1_block:
    ands           x4,LENGTH,#-16
    b.eq           Lpartial

    ld1            {H1M.2d,H1L.2d},[TABLE]

L1_block_loop:
    ld1            {C0.2d},[DATA],#16
IF_LE(`
    rev64          C0.16b,C0.16b
')

    eor            C0.16b,C0.16b,D.16b

    PMUL(C0,H1M,H1L)

    REDUCTION(D)

    subs           x4,x4,#16
    b.ne           L1_block_loop

Lpartial:
    tst            LENGTH,#15
    b.eq           Lghash_done

    ld1            {H1M.2d,H1L.2d},[TABLE]

    LOAD_REV_PARTIAL_BLOCK(C0)

    eor            C0.16b,C0.16b,D.16b

    PMUL(C0,H1M,H1L)

    REDUCTION(D)

Lghash_done:
IF_LE(`
    rev64          D.16b,D.16b
')
    st1            {D.2d},[X]
    ret
EPILOGUE(_nettle_gcm_hash)
