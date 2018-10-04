/* xts.c

   XEX-based tweaked-codebook mode with ciphertext stealing (XTS)

   Copyright (C) 2018 Red Hat, Inc.

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
*/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "xts.h"

#include "macros.h"
#include "memxor.h"
#include "nettle-internal.h"

/* shift one and XOR with 0x87. */
/* src and dest can point to the same buffer for in-place operations */
static void
xts_shift(union nettle_block16 *dst,
          const union nettle_block16 *src)
{
  uint8_t carry = src->b[15] >> 7;
  uint64_t b0 = LE_READ_UINT64(src->b);
  uint64_t b1 = LE_READ_UINT64(src->b+8);
  b1 = (b1 << 1) | (b0 >> 63);
  b0 = b0 << 1;
  LE_WRITE_UINT64(dst->b, b0);
  LE_WRITE_UINT64(dst->b+8, b1);
  dst->b[0] ^= 0x87 & -carry;
}

/*
 * prev is the block to steal from
 * curr is the input block to the last step
 * length is the partial block length
 * dst is the destination partial block
 * src is the source partial block
 *
 * In the Encryption case:
 *   prev -> the output of the N-1 encryption step
 *   curr -> the input to the Nth step (will be encrypted as Cn-1)
 *   dst  -> the final Cn partial block
 *   src  -> the final Pn partial block
 *
 * In the decryption case:
 *   prev -> the output of the N-1 decryption step
 *   curr -> the input to the Nth step (will be decrypted as Pn-1)
 *   dst  -> the final Pn partial block
 *   src  -> the final Cn partial block
 */
static void
xts_steal(uint8_t *prev, uint8_t *curr,
	  size_t length, uint8_t *dst, const uint8_t *src)
{
  /* copy the remaining in the current input block */
  memcpy(curr, src, length);
  /* fill the current block with the last blocksize - length
   * bytes of the previous block */
  memcpy(&curr[length], &prev[length], XTS_BLOCK_SIZE - length);

  /* This must be last or inplace operations will break
   * copy 'length' bytes of the previous block in the
   * destination block, which is the final partial block
   * returned to the caller */
  memcpy(dst, prev, length);
}

static void
check_length(size_t length, uint8_t *dst)
{
  assert(length >= XTS_BLOCK_SIZE);
  /* asserts may be compiled out, try to save the user by zeroing the dst in
   * case the buffer contains sensitive data (like the clear text for inplace
   * encryption) */
  if (length < XTS_BLOCK_SIZE)
    memset(dst, '\0', length);
}

/* works also for inplace encryption/decryption */

void
xts_encrypt_message(const void *enc_ctx, const void *twk_ctx,
	            nettle_cipher_func *encf,
	            const uint8_t *tweak, size_t length,
	            uint8_t *dst, const uint8_t *src)
{
  union nettle_block16 T;
  union nettle_block16 P;

  check_length(length, dst);

  encf(twk_ctx, XTS_BLOCK_SIZE, T.b, tweak);

  /* the zeroth power of alpha is the initial ciphertext value itself, so we
   * skip shifting and do it at the end of each block operation instead */
  for (;length >= XTS_BLOCK_SIZE;
       length -= XTS_BLOCK_SIZE, src += XTS_BLOCK_SIZE, dst += XTS_BLOCK_SIZE)
    {
      memxor3(P.b, src, T.b, XTS_BLOCK_SIZE);	/* P -> PP */
      encf(enc_ctx, XTS_BLOCK_SIZE, dst, P.b);  /* CC */
      memxor(dst, T.b, XTS_BLOCK_SIZE);	        /* CC -> C */

      /* shift T for next block */
      xts_shift(&T, &T);
    }

  /* if the last block is partial, handle via stealing */
  if (length)
    {
      uint8_t *C = dst - XTS_BLOCK_SIZE;
      /* C points to C(n-1) */
      xts_steal(C, P.b, length, dst, src);
      memxor(P.b, T.b, XTS_BLOCK_SIZE);	        /* P -> PP */
      encf(enc_ctx, XTS_BLOCK_SIZE, C, P.b);    /* CC */
      memxor(C, T.b, XTS_BLOCK_SIZE);
    }
}

void
xts_decrypt_message(const void *dec_ctx, const void *twk_ctx,
	            nettle_cipher_func *decf, nettle_cipher_func *encf,
	            const uint8_t *tweak, size_t length,
	            uint8_t *dst, const uint8_t *src)
{
  union nettle_block16 T;
  union nettle_block16 C;

  check_length(length, dst);

  encf(twk_ctx, XTS_BLOCK_SIZE, T.b, tweak);

  for (;length >= XTS_BLOCK_SIZE;
       length -= XTS_BLOCK_SIZE, src += XTS_BLOCK_SIZE, dst += XTS_BLOCK_SIZE)
    {
      if (length > XTS_BLOCK_SIZE && length < 2 * XTS_BLOCK_SIZE)
        break;                  /* must ciphersteal on last two blocks */

      memxor3(C.b, src, T.b, XTS_BLOCK_SIZE);	/* c -> CC */
      decf(dec_ctx, XTS_BLOCK_SIZE, dst, C.b);  /* PP */
      memxor(dst, T.b, XTS_BLOCK_SIZE);	        /* PP -> P */

      xts_shift(&T, &T);
    }

  /* if the last block is partial, handle via stealing */
  if (length)
    {
      union nettle_block16 T1;
      uint8_t *P;

      /* we need the last T(n) and save the T(n-1) for later */
      xts_shift(&T1, &T);

      P = dst;      /* use P(n-1) as temp storage for partial P(n) */
      memxor3(C.b, src, T1.b, XTS_BLOCK_SIZE);	/* C -> CC */
      decf(dec_ctx, XTS_BLOCK_SIZE, P, C.b);    /* PP */
      memxor(P, T1.b, XTS_BLOCK_SIZE);	        /* PP -> P */

      /* process next block (Pn-1) */
      length -= XTS_BLOCK_SIZE;
      src += XTS_BLOCK_SIZE;
      dst += XTS_BLOCK_SIZE;

      /* Fill P(n) and prepare C, P still pointing to P(n-1) */
      xts_steal(P, C.b, length, dst, src);
      memxor(C.b, T.b, XTS_BLOCK_SIZE);	        /* C -> CC */
      decf(dec_ctx, XTS_BLOCK_SIZE, P, C.b);    /* PP */
      memxor(P, T.b, XTS_BLOCK_SIZE);	        /* PP -> P */
    }
}
