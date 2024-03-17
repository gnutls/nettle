C powerpc64/p8/gcm-aes-encrypt.asm

ifelse(`
   Copyright (C) 2023- IBM Inc.
   Copyright (C) 2024 Niels Möller.

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

C Register usage:

define(`SP', `r1')
define(`TOCP', `r2')

define(`HT', `r3')
define(`SRND', `r4')
define(`SLEN', `r5')
define(`SDST', `r6')
define(`SSRC', `r7')
define(`RK', `r10')
define(`LOOP', `r12')

C
C vectors used in aes encrypt output
C

define(`K0', `v1')
define(`S0', `v2')
define(`S1', `v3')
define(`S2', `v4')
define(`S3', `v5')
define(`S4', `v6')
define(`S5', `v7')
define(`S6', `v8')
define(`S7', `v9')

C
C ghash assigned registers and vectors
C

define(`ZERO', `v21')
define(`POLY', `v22')
define(`POLY_L', `v0')

define(`D', `v10')
define(`H1M', `v11')
define(`H1L', `v12')
define(`H2M', `v13')
define(`H2L', `v14')
define(`H3M', `v15')
define(`H3L', `v16')
define(`H4M', `v17')
define(`H4L', `v18')
define(`R', `v19')
define(`F', `v20')
define(`R2', `v21')
define(`F2', `v22')

define(`K', `v30')
define(`LE_TEMP', `v30')
define(`LE_MASK', `v31')
define(`TEMP1', `v31')

define(`CNT1', `v28')
define(`LASTCNT', `v29')

.file "gcm-aes-encrypt.asm"

.text

 C size_t
 C _gcm_aes_encrypt(struct gcm_key *key, size_t rounds,
 C                  size_t len, uint8_t *dst, const uint8_t *src)
 C

define(`FUNC_ALIGN', `5')
PROLOGUE(_nettle_gcm_aes_encrypt)
    cmpdi SLEN, 128
    blt No_encrypt_out

    mflr 0
    std 0,16(1)
    stdu  SP,-336(SP)

    std r25, 112(SP)
    std r26, 120(SP)
    std r27, 128(SP)
    std r28, 136(SP)
    std r29, 144(SP)
    std r30, 152(SP)
    std r31, 160(SP)
    std r30, 176(SP)
    std r31, 184(SP)
    stxv VSR(v20), 208(SP)
    stxv VSR(v21), 224(SP)
    stxv VSR(v22), 240(SP)
    stxv VSR(v28), 256(SP)
    stxv VSR(v29), 272(SP)
    stxv VSR(v30), 288(SP)
    stxv VSR(v31), 304(SP)

    vxor ZERO,ZERO,ZERO
    vspltisb TEMP1, 1
    vsldoi CNT1, ZERO, TEMP1, 1    C counter 1

    DATA_LOAD_VEC(POLY,.polynomial,r9)

    li             r9,0
    lvsl           LE_MASK,0,r9
IF_LE(`vspltisb    LE_TEMP,0x07')
IF_BE(`vspltisb    LE_TEMP,0x03')
    vxor           LE_MASK,LE_MASK,LE_TEMP

    xxmrghd        VSR(POLY_L),VSR(ZERO),VSR(POLY)

    addi r12, HT, 4096

    C load table elements
    li             r9,1*16
    li             r10,2*16
    li             r11,3*16
    lxvd2x         VSR(H1M),0,HT
    lxvd2x         VSR(H1L),r9,HT
    lxvd2x         VSR(H2M),r10,HT
    lxvd2x         VSR(H2L),r11,HT
    addi HT, HT, 64
    lxvd2x         VSR(H3M),0,HT
    lxvd2x         VSR(H3L),r9,HT
    lxvd2x         VSR(H4M),r10,HT
    lxvd2x         VSR(H4L),r11,HT

    addi HT, HT,  4048  C Advance to point to the 'CTR' field in the context

    li r25,0x10
    li r26,0x20
    li r27,0x30
    li r28,0x40
    li r29,0x50
    li r30,0x60
    li r31,0x70

    lxvd2x         VSR(D),r9,HT		C load 'X' pointer
    C byte-reverse of each doubleword permuting on little-endian mode
IF_LE(`
    vperm          D,D,D,LE_MASK
')

    addi RK, r12, 64
    lxvb16x VSR(S0), 0, HT		C Load 'CTR'

    li r11, 128
    divdu LOOP, SLEN, r11		C loop n 8 blocks
    sldi SLEN, LOOP, 7

    addi LOOP, LOOP, -1

    lxvd2x VSR(K0),0,RK
    vperm   K0,K0,K0,LE_MASK

.align 5
    C increase ctr value as input to aes_encrypt
    vadduwm S1, S0, CNT1
    vadduwm S2, S1, CNT1
    vadduwm S3, S2, CNT1
    vadduwm S4, S3, CNT1
    vadduwm S5, S4, CNT1
    vadduwm S6, S5, CNT1
    vadduwm S7, S6, CNT1
    vmr LASTCNT, S7			C save last cnt

    OPN_XXY(vxor, K0, S0, S1, S2, S3, S4, S5, S6, S7)

    addi SRND, SRND, -1
    mtctr SRND
    li r11,0x10
.align 5
L8x_round_loop1:
    lxvd2x VSR(K),r11,RK
    vperm   K,K,K,LE_MASK
    OPN_XXY(vcipher, K, S0, S1, S2, S3, S4, S5, S6, S7)
    addi r11,r11,0x10
    bdnz L8x_round_loop1

    lxvd2x VSR(K),r11,RK
    vperm   K,K,K,LE_MASK
    OPN_XXY(vcipherlast, K, S0, S1, S2, S3, S4, S5, S6, S7)

    cmpdi LOOP, 0
    beq do_ghash

.align 5
Loop8x_en:
    xxlor vs1, VSR(S0), VSR(S0)
    xxlor vs2, VSR(S1), VSR(S1)
    xxlor vs3, VSR(S2), VSR(S2)
    xxlor vs4, VSR(S3), VSR(S3)
    xxlor vs5, VSR(S4), VSR(S4)
    xxlor vs6, VSR(S5), VSR(S5)
    xxlor vs7, VSR(S6), VSR(S6)
    xxlor vs8, VSR(S7), VSR(S7)

    lxvd2x VSR(S0),0,SSRC
    lxvd2x VSR(S1),r25,SSRC
    lxvd2x VSR(S2),r26,SSRC
    lxvd2x VSR(S3),r27,SSRC
    lxvd2x VSR(S4),r28,SSRC
    lxvd2x VSR(S5),r29,SSRC
    lxvd2x VSR(S6),r30,SSRC
    lxvd2x VSR(S7),r31,SSRC

IF_LE(`OPN_XXXY(vperm, LE_MASK, S0,S1,S2,S3)')

    xxlxor VSR(S0), VSR(S0), vs1
    xxlxor VSR(S1), VSR(S1), vs2
    xxlxor VSR(S2), VSR(S2), vs3
    xxlxor VSR(S3), VSR(S3), vs4

IF_LE(`OPN_XXXY(vperm, LE_MASK, S4,S5,S6,S7)')

    C do two 4x ghash

    C previous digest combining
    vxor D,S0,D

    GF_MUL(F2, R2, H3L, H3M, S1)
    GF_MUL(F, R, H4L, H4M, D)
    vxor           F,F,F2
    vxor           R,R,R2

    GF_MUL(F2, R2, H2L, H2M, S2)
    vxor	   F, F, F2
    vxor	   R, R, R2
    GF_MUL(F2, R2, H1L, H1M, S3)
    vxor	   F, F, F2
    vxor	   D, R, R2

    GHASH_REDUCE(D, F, POLY_L, R2, F2)  C R2, F2 used as temporaries

IF_LE(`OPN_XXXY(vperm, LE_MASK, S0,S1,S2,S3)')

    stxvd2x VSR(S0),0,SDST
    stxvd2x VSR(S1),r25,SDST
    stxvd2x VSR(S2),r26,SDST
    stxvd2x VSR(S3),r27,SDST

    xxlxor VSR(S4), VSR(S4), vs5
    xxlxor VSR(S5), VSR(S5), vs6
    xxlxor VSR(S6), VSR(S6), vs7
    xxlxor VSR(S7), VSR(S7), vs8

    C previous digest combining
    vxor D,S4,D

    GF_MUL(F2, R2, H3L, H3M, S5)
    GF_MUL(F, R, H4L, H4M, D)
    vxor           F,F,F2
    vxor           R,R,R2

    GF_MUL(F2, R2, H2L, H2M, S6)
    vxor	   F, F, F2
    vxor	   R, R, R2
    GF_MUL(F2, R2, H1L, H1M, S7)
    vxor	   F, F, F2
    vxor	   D, R, R2

    GHASH_REDUCE(D, F, POLY_L, R2, F2)  C R2, F2 used as temporaries

IF_LE(`OPN_XXXY(vperm, LE_MASK, S4,S5,S6,S7)')

    stxvd2x VSR(S4),r28,SDST
    stxvd2x VSR(S5),r29,SDST
    stxvd2x VSR(S6),r30,SDST
    stxvd2x VSR(S7),r31,SDST

    addi SDST, SDST, 0x80
    addi SSRC, SSRC, 0x80

    vadduwm S0, LASTCNT, CNT1
    vadduwm S1, S0, CNT1
    vadduwm S2, S1, CNT1
    vadduwm S3, S2, CNT1
    vadduwm S4, S3, CNT1
    vadduwm S5, S4, CNT1
    vadduwm S6, S5, CNT1
    vadduwm S7, S6, CNT1
    vmr LASTCNT, S7			C save last cnt to v29

    OPN_XXY(vxor, K0, S0, S1, S2, S3, S4, S5, S6, S7)

    mtctr SRND
    li r11,0x10
.align 5
L8x_round_loop2:
    lxvd2x VSR(K),r11,RK
    vperm   K,K,K,LE_MASK
    OPN_XXY(vcipher, K, S0, S1, S2, S3, S4, S5, S6, S7)
    addi r11,r11,0x10
    bdnz L8x_round_loop2

    lxvd2x VSR(K),r11,RK
    vperm   K,K,K,LE_MASK
    OPN_XXY(vcipherlast, K, S0, S1, S2, S3, S4, S5, S6, S7)

    addi LOOP, LOOP, -1

    cmpdi LOOP, 0
    bne Loop8x_en

do_ghash:
    xxlor vs1, VSR(S0), VSR(S0)
    xxlor vs2, VSR(S1), VSR(S1)
    xxlor vs3, VSR(S2), VSR(S2)
    xxlor vs4, VSR(S3), VSR(S3)
    xxlor vs5, VSR(S4), VSR(S4)
    xxlor vs6, VSR(S5), VSR(S5)
    xxlor vs7, VSR(S6), VSR(S6)
    xxlor vs8, VSR(S7), VSR(S7)

    lxvd2x VSR(S0),0,SSRC
    lxvd2x VSR(S1),r25,SSRC
    lxvd2x VSR(S2),r26,SSRC
    lxvd2x VSR(S3),r27,SSRC
    lxvd2x VSR(S4),r28,SSRC
    lxvd2x VSR(S5),r29,SSRC
    lxvd2x VSR(S6),r30,SSRC
    lxvd2x VSR(S7),r31,SSRC

IF_LE(`OPN_XXXY(vperm, LE_MASK, S0,S1,S2,S3)')

    xxlxor VSR(S0), VSR(S0), vs1
    xxlxor VSR(S1), VSR(S1), vs2
    xxlxor VSR(S2), VSR(S2), vs3
    xxlxor VSR(S3), VSR(S3), vs4

IF_LE(`OPN_XXXY(vperm, LE_MASK, S4,S5,S6,S7)')

    C previous digest combining
    vxor D,S0,D

    GF_MUL(F2, R2, H3L, H3M, S1)
    GF_MUL(F, R, H4L, H4M, D)
    vxor           F,F,F2
    vxor           R,R,R2

    GF_MUL(F2, R2, H2L, H2M, S2)
    vxor	   F, F, F2
    vxor	   R, R, R2
    GF_MUL(F2, R2, H1L, H1M, S3)
    vxor	   F, F, F2
    vxor	   D, R, R2

    GHASH_REDUCE(D, F, POLY_L, R2, F2)  C R2, F2 used as temporaries

IF_LE(`OPN_XXXY(vperm, LE_MASK, S0,S1,S2,S3)')

    stxvd2x VSR(S0),0,SDST
    stxvd2x VSR(S1),r25,SDST
    stxvd2x VSR(S2),r26,SDST
    stxvd2x VSR(S3),r27,SDST

    xxlxor VSR(S4), VSR(S4), vs5
    xxlxor VSR(S5), VSR(S5), vs6
    xxlxor VSR(S6), VSR(S6), vs7
    xxlxor VSR(S7), VSR(S7), vs8

    C previous digest combining
    vxor D,S4,D

    GF_MUL(F2, R2, H3L, H3M, S5)
    GF_MUL(F, R, H4L, H4M, D)
    vxor           F,F,F2
    vxor           R,R,R2

    GF_MUL(F2, R2, H2L, H2M, S6)
    vxor	   F, F, F2
    vxor	   R, R, R2
    GF_MUL(F2, R2, H1L, H1M, S7)
    vxor	   F, F, F2
    vxor	   D, R, R2

    GHASH_REDUCE(D, F, POLY_L, R2, F2)  C R2, F2 used as temporaries

IF_LE(`OPN_XXXY(vperm, LE_MASK, S4,S5,S6,S7)')

    stxvd2x VSR(S4),r28,SDST
    stxvd2x VSR(S5),r29,SDST
    stxvd2x VSR(S6),r30,SDST
    stxvd2x VSR(S7),r31,SDST

gcm_aes_out:
    vadduwm LASTCNT, LASTCNT, CNT1		C increase ctr

    C byte-reverse of each doubleword permuting on little-endian mode
IF_LE(`
    vperm          D,D,D,LE_MASK
')
    stxvd2x        VSR(D),r9,HT			C store digest 'D'

IF_LE(`
    vperm LASTCNT,LASTCNT,LASTCNT,LE_MASK
')
    stxvd2x VSR(LASTCNT), 0, HT		C store ctr

    ld r25, 112(SP)
    ld r26, 120(SP)
    ld r27, 128(SP)
    ld r28, 136(SP)
    ld r29, 144(SP)
    ld r30, 152(SP)
    ld r31, 160(SP)
    ld r30, 176(SP)
    ld r31, 184(SP)
    lxv VSR(v20), 208(SP)
    lxv VSR(v21), 224(SP)
    lxv VSR(v22), 240(SP)
    lxv VSR(v28), 256(SP)
    lxv VSR(v29), 272(SP)
    lxv VSR(v30), 288(SP)
    lxv VSR(v31), 304(SP)

    addi 1, 1, 336
    ld 0, 16(1)
    mtlr r0

    mr 3, SLEN
    blr

No_encrypt_out:
    li 3, 0
    blr
EPILOGUE(_nettle_gcm_aes_encrypt)

 .data
    C 0xC2000000000000000000000000000001
.polynomial:
.align 4
IF_BE(`
.byte 0xC2
.rept 14
.byte 0x00
.endr
.byte 0x01
',`
.byte 0x01
.rept 14
.byte 0x00
.endr
.byte 0xC2
')
