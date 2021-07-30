C arm64/crypto/aes256-decrypt.asm

ifelse(`
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

.file "aes256-decrypt.asm"
.arch armv8-a+crypto

.text

C Register usage:

define(`KEYS', `x0')
define(`LENGTH', `x1')
define(`DST', `x2')
define(`SRC', `x3')

define(`S0', `v0')
define(`S1', `v1')
define(`S2', `v2')
define(`S3', `v3')
define(`K0', `v16')
define(`K1', `v17')
define(`K2', `v18')
define(`K3', `v19')
define(`K4', `v20')
define(`K5', `v21')
define(`K6', `v22')
define(`K7', `v23')
define(`K8', `v24')
define(`K9', `v25')
define(`K10', `v26')
define(`K11', `v27')
define(`K12', `v28')
define(`K13', `v29')
define(`K14', `v30')

C AES decryption round of 4-blocks
C AESD_ROUND_4B(KEY)
define(`AESD_ROUND_4B', m4_assert_numargs(1)`
    aesd           S0.16b,$1.16b
    aesimc         S0.16b,S0.16b
    aesd           S1.16b,$1.16b
    aesimc         S1.16b,S1.16b
    aesd           S2.16b,$1.16b
    aesimc         S2.16b,S2.16b
    aesd           S3.16b,$1.16b
    aesimc         S3.16b,S3.16b
')

C AES last decryption round of 4-blocks
C AESD_LAST_ROUND_4B(KEY)
define(`AESD_LAST_ROUND_4B', m4_assert_numargs(2)`
    aesd           S0.16b,$1.16b
    eor            S0.16b,S0.16b,$2.16b
    aesd           S1.16b,$1.16b
    eor            S1.16b,S1.16b,$2.16b
    aesd           S2.16b,$1.16b
    eor            S2.16b,S2.16b,$2.16b
    aesd           S3.16b,$1.16b
    eor            S3.16b,S3.16b,$2.16b
')

C AES decryption round of 1-block
C AESD_ROUND_1B(KEY)
define(`AESD_ROUND_1B', m4_assert_numargs(1)`
    aesd           S0.16b,$1.16b
    aesimc         S0.16b,S0.16b
')

C AES last decryption round of 1-block
C AESD_LAST_ROUND_1B(KEY)
define(`AESD_LAST_ROUND_1B', m4_assert_numargs(2)`
    aesd           S0.16b,$1.16b
    eor            S0.16b,S0.16b,$2.16b
')

C void
C aes256_decrypt(const struct aes256_ctx *ctx,
C                size_t length, uint8_t *dst,
C                const uint8_t *src)

PROLOGUE(nettle_aes256_decrypt)
    ands           x4,LENGTH,#-64
    b.eq           L1B

    mov            x5,KEYS
    ld1            {K0.4s,K1.4s,K2.4s,K3.4s},[x5],#64
    ld1            {K4.4s,K5.4s,K6.4s,K7.4s},[x5],#64
    ld1            {K8.4s,K9.4s,K10.4s,K11.4s},[x5],#64
    ld1            {K12.4s,K13.4s,K14.4s},[x5]

L4B_loop:
    ld1            {S0.16b,S1.16b,S2.16b,S3.16b},[SRC],#64
    
    AESD_ROUND_4B(K0)
    AESD_ROUND_4B(K1)
    AESD_ROUND_4B(K2)
    AESD_ROUND_4B(K3)
    AESD_ROUND_4B(K4)
    AESD_ROUND_4B(K5)
    AESD_ROUND_4B(K6)
    AESD_ROUND_4B(K7)
    AESD_ROUND_4B(K8)
    AESD_ROUND_4B(K9)
    AESD_ROUND_4B(K10)
    AESD_ROUND_4B(K11)
    AESD_ROUND_4B(K12)
    AESD_LAST_ROUND_4B(K13,K14)

    st1            {S0.16b,S1.16b,S2.16b,S3.16b},[DST],#64

    subs           x4,x4,#64
    b.ne           L4B_loop

    and            LENGTH,LENGTH,#63

L1B:
    cbz            LENGTH,Ldone

    ld1            {K0.4s,K1.4s,K2.4s,K3.4s},[KEYS],#64
    ld1            {K4.4s,K5.4s,K6.4s,K7.4s},[KEYS],#64
    ld1            {K8.4s,K9.4s,K10.4s,K11.4s},[KEYS],#64
    ld1            {K12.4s,K13.4s,K14.4s},[KEYS]

L1B_loop:
    ld1            {S0.16b},[SRC],#16
    
    AESD_ROUND_1B(K0)
    AESD_ROUND_1B(K1)
    AESD_ROUND_1B(K2)
    AESD_ROUND_1B(K3)
    AESD_ROUND_1B(K4)
    AESD_ROUND_1B(K5)
    AESD_ROUND_1B(K6)
    AESD_ROUND_1B(K7)
    AESD_ROUND_1B(K8)
    AESD_ROUND_1B(K9)
    AESD_ROUND_1B(K10)
    AESD_ROUND_1B(K11)
    AESD_ROUND_1B(K12)
    AESD_LAST_ROUND_1B(K13,K14)

    st1            {S0.16b},[DST],#16

    subs           LENGTH,LENGTH,#16
    b.ne           L1B_loop

Ldone:
    ret
EPILOGUE(nettle_aes256_decrypt)
