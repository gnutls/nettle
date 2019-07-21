/*
   CMAC-64, NIST SP 800-38B
   Copyright (C) Stefan Metzmacher 2012
   Copyright (C) Jeremy Allison 2012
   Copyright (C) Michael Adam 2012
   Copyright (C) 2017, Red Hat Inc.
   Copyright (C) 2019, Dmitry Eremin-Solenikov

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

#include "cmac.h"

#include "memxor.h"
#include "nettle-internal.h"
#include "macros.h"

/* shift one and XOR with 0x87. */
#if WORDS_BIGENDIAN
static void
_cmac64_block_mulx(union nettle_block8 *dst,
	    const union nettle_block8 *src)
{
  uint64_t carry = src->u64 >> 63;

  dst->u64 = (src->u64 << 1) ^ (0x1b & -carry);
}
#else /* !WORDS_BIGENDIAN */
#define LE_SHIFT(x) ((((x) & 0x7f7f7f7f7f7f7f7f) << 1) | \
                     (((x) & 0x8080808080808080) >> 15))
static void
_cmac64_block_mulx(union nettle_block8 *dst,
	   const union nettle_block8 *src)
{
  uint64_t carry = (src->u64 & 0x80) >> 7;

  dst->u64 = LE_SHIFT(src->u64) ^ (0x1b00000000000000 & -carry);
}
#endif /* !WORDS_BIGENDIAN */

void
cmac64_set_key(struct cmac64_key *key, const void *cipher,
	       nettle_cipher_func *encrypt)
{
  static const union nettle_block8 zero_block;
  union nettle_block8 L;

  /* step 1 - generate subkeys k1 and k2 */
  encrypt(cipher, 8, L.b, zero_block.b);

  _cmac64_block_mulx(&key->K1, &L);
  _cmac64_block_mulx(&key->K2, &key->K1);
}

void
cmac64_init(struct cmac64_ctx *ctx)
{
  memset(&ctx->X, 0, sizeof(ctx->X));
  ctx->index = 0;
}

#define MIN(x,y) ((x)<(y)?(x):(y))

void
cmac64_update(struct cmac64_ctx *ctx, const void *cipher,
	      nettle_cipher_func *encrypt,
	      size_t msg_len, const uint8_t *msg)
{
  union nettle_block16 Y;
  /*
   * check if we expand the block
   */
  if (ctx->index < 8)
    {
      size_t len = MIN(8 - ctx->index, msg_len);
      memcpy(&ctx->block.b[ctx->index], msg, len);
      msg += len;
      msg_len -= len;
      ctx->index += len;
    }

  if (msg_len == 0) {
    /* if it is still the last block, we are done */
    return;
  }

  /*
   * now checksum everything but the last block
   */
  memxor3(Y.b, ctx->X.b, ctx->block.b, 8);
  encrypt(cipher, 8, ctx->X.b, Y.b);

  while (msg_len > 8)
    {
      memxor3(Y.b, ctx->X.b, msg, 8);
      encrypt(cipher, 8, ctx->X.b, Y.b);
      msg += 8;
      msg_len -= 8;
    }

  /*
   * copy the last block, it will be processed in
   * cmac64_digest().
   */
  memcpy(ctx->block.b, msg, msg_len);
  ctx->index = msg_len;
}

void
cmac64_digest(struct cmac64_ctx *ctx, const struct cmac64_key *key,
	      const void *cipher, nettle_cipher_func *encrypt,
	      unsigned length, uint8_t *dst)
{
  union nettle_block8 Y;

  memset(ctx->block.b+ctx->index, 0, sizeof(ctx->block.b)-ctx->index);

  /* re-use ctx->block for memxor output */
  if (ctx->index < 8)
    {
      ctx->block.b[ctx->index] = 0x80;
      memxor(ctx->block.b, key->K2.b, 8);
    }
  else
    {
      memxor(ctx->block.b, key->K1.b, 8);
    }

  memxor3(Y.b, ctx->block.b, ctx->X.b, 8);

  assert(length <= 8);
  if (length == 8)
    {
      encrypt(cipher, 8, dst, Y.b);
    }
  else
    {
      encrypt(cipher, 8, ctx->block.b, Y.b);
      memcpy(dst, ctx->block.b, length);
    }

  /* reset state for re-use */
  memset(&ctx->X, 0, sizeof(ctx->X));
  ctx->index = 0;
}
