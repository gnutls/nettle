C arm64/crypto/aes192-encrypt.asm

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

.file "aes192-encrypt.asm"
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

C AES encryption round of 4-blocks
C AESE_ROUND_4B(KEY)
define(`AESE_ROUND_4B', m4_assert_numargs(1)`
    aese           S0.16b,$1.16b
    aesmc          S0.16b,S0.16b
    aese           S1.16b,$1.16b
    aesmc          S1.16b,S1.16b
    aese           S2.16b,$1.16b
    aesmc          S2.16b,S2.16b
    aese           S3.16b,$1.16b
    aesmc          S3.16b,S3.16b
')

C AES last encryption round of 4-blocks
C AESE_LAST_ROUND_4B(KEY)
define(`AESE_LAST_ROUND_4B', m4_assert_numargs(2)`
    aese           S0.16b,$1.16b
    eor            S0.16b,S0.16b,$2.16b
    aese           S1.16b,$1.16b
    eor            S1.16b,S1.16b,$2.16b
    aese           S2.16b,$1.16b
    eor            S2.16b,S2.16b,$2.16b
    aese           S3.16b,$1.16b
    eor            S3.16b,S3.16b,$2.16b
')

C AES encryption round of 1-block
C AESE_ROUND_1B(KEY)
define(`AESE_ROUND_1B', m4_assert_numargs(1)`
    aese           S0.16b,$1.16b
    aesmc          S0.16b,S0.16b
')

C AES last encryption round of 1-block
C AESE_LAST_ROUND_1B(KEY)
define(`AESE_LAST_ROUND_1B', m4_assert_numargs(2)`
    aese           S0.16b,$1.16b
    eor            S0.16b,S0.16b,$2.16b
')

C void
C aes192_encrypt(const struct aes192_ctx *ctx,
C                size_t length, uint8_t *dst,
C                const uint8_t *src)

PROLOGUE(nettle_aes192_encrypt)
    ands           x4,LENGTH,#-64
    b.eq           L1B

    mov            x5,KEYS
    ld1            {K0.4s,K1.4s,K2.4s,K3.4s},[x5],#64
    ld1            {K4.4s,K5.4s,K6.4s,K7.4s},[x5],#64
    ld1            {K8.4s,K9.4s,K10.4s,K11.4s},[x5],#64
    ld1            {K12.4s},[x5]

L4B_loop:
    ld1            {S0.16b,S1.16b,S2.16b,S3.16b},[SRC],#64
    
    AESE_ROUND_4B(K0)
    AESE_ROUND_4B(K1)
    AESE_ROUND_4B(K2)
    AESE_ROUND_4B(K3)
    AESE_ROUND_4B(K4)
    AESE_ROUND_4B(K5)
    AESE_ROUND_4B(K6)
    AESE_ROUND_4B(K7)
    AESE_ROUND_4B(K8)
    AESE_ROUND_4B(K9)
    AESE_ROUND_4B(K10)
    AESE_LAST_ROUND_4B(K11,K12)

    st1            {S0.16b,S1.16b,S2.16b,S3.16b},[DST],#64

    subs           x4,x4,#64
    b.ne           L4B_loop

    and            LENGTH,LENGTH,#63

L1B:
    cbz            LENGTH,Ldone

    ld1            {K0.4s,K1.4s,K2.4s,K3.4s},[KEYS],#64
    ld1            {K4.4s,K5.4s,K6.4s,K7.4s},[KEYS],#64
    ld1            {K8.4s,K9.4s,K10.4s,K11.4s},[KEYS],#64
    ld1            {K12.4s},[KEYS]

L1B_loop:
    ld1            {S0.16b},[SRC],#16
    
    AESE_ROUND_1B(K0)
    AESE_ROUND_1B(K1)
    AESE_ROUND_1B(K2)
    AESE_ROUND_1B(K3)
    AESE_ROUND_1B(K4)
    AESE_ROUND_1B(K5)
    AESE_ROUND_1B(K6)
    AESE_ROUND_1B(K7)
    AESE_ROUND_1B(K8)
    AESE_ROUND_1B(K9)
    AESE_ROUND_1B(K10)
    AESE_LAST_ROUND_1B(K11,K12)

    st1            {S0.16b},[DST],#16

    subs           LENGTH,LENGTH,#16
    b.ne           L1B_loop

Ldone:
    ret
EPILOGUE(nettle_aes192_encrypt)
