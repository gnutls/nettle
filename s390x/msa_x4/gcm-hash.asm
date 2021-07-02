C s390x/msa_x4/gcm-hash.asm

ifelse(`
   Copyright (C) 2020 Mamone Tarsha
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

C KIMD (COMPUTE INTERMEDIATE MESSAGE DIGEST) is specefied in
C "z/Architecture Principles of Operation SA22-7832-12" as follows:
C A function specified by the function code in general register 0 is performed.
C General register 1 contains the logical address of the leftmost byte of the parameter block in storage.
C the second operand is processed as specified by the function code using an initial chaining value in
C the parameter block, and the result replaces the chaining value.

C This implementation uses KIMD-GHASH function.
C The parameter block used for the KIMD-GHASH function has the following format:
C *----------------------------------------------*
C |       Initial Chaining Value (16 bytes)      |
C |----------------------------------------------|
C |            Hash Subkey (16 bytes)            |
C *----------------------------------------------*

C Size of parameter block
define(`PB_SIZE', `32')

C gcm_set_key() assigns H value in the middle element of the table
define(`H_idx', `128*16')

.file "gcm-hash.asm"

.text

C void gcm_init_key (union gcm_block *table)

PROLOGUE(_nettle_gcm_init_key)
    C Except for Hash Subkey (H), KIMD-GHASH does not need any pre-computed values so just return to the caller.
    br             RA
EPILOGUE(_nettle_gcm_init_key)

C void gcm_hash (const struct gcm_key *key, union gcm_block *x,
C                size_t length, const uint8_t *data)

PROLOGUE(_nettle_gcm_hash)
    ldgr           %f0,%r6                       C load non-volatile general register 6 into volatile float-point register 0
    C --- allocate a stack space for parameter block in addition to 16-byte buffer to handle leftover bytes ---
    ALLOC_STACK(%r1,PB_SIZE+16)                  C parameter block (must be general register 1)
    lgr            %r6,%r3
    mvc            0(16,%r1),0(%r3)              C copy x Initial Chaining Value field
    mvc            16(16,%r1),H_idx (%r2)        C copy H to Hash Subkey field
    lghi           %r0,65                        C GHASH function code (must be general register 0)
    lgr            %r2,%r5                       C location of leftmost byte of data (must not be odd-numbered general register nor be general register 0)
    C number of bytes (must be general register of data + 1). length must be a multiple of the data block size (16).
    risbg          %r3,%r4,0,187,0               C Insert bit offsets 0-59, bit offset 0 of the fourth operand is set to clear the remaining bits.
1:  .long   0xb93e0002                           C kimd %r0,%r2
    brc            1,1b                          C safely branch back in case of partial completion
    C --- handle leftovers ---
    risbg          %r5,%r4,60,191,0              C Insert bit offsets 60-63 and clear the remaining bits.
    jz             4f
    lgr            %r4,%r2
    C --- copy the leftovers to allocated stack buffer and pad the remaining bytes with zero ---
    la             %r2,PB_SIZE (%r1)
    lghi           %r3,16
2:  mvcle          %r2,%r4,0
    brc            1,2b
    aghi           %r2,-16
    aghi           %r3,16
3:  .long   0xb93e0002                           C kimd %r0,%r2
    brc            1,3b                          C safely branch back in case of partial completion
4:
    mvc            0(16,%r6),0(%r1)              C store x
    xc             0(PB_SIZE+16,%r1),0(%r1)      C wipe parameter block content and leftover bytes of data from stack
    FREE_STACK(PB_SIZE+16)
    lgdr           %r6,%f0                       C restore general register 6
    br             RA
EPILOGUE(_nettle_gcm_hash)
