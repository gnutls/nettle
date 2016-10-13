/* skein256.c

   Copyright (C) 2016 Niels Möller

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
#include <string.h>

#include "skein.h"

#include "nettle-write.h"

void
_skein256_expand(uint64_t keys[_SKEIN256_NKEYS],
		 uint64_t tweak[_SKEIN_NTWEAK])
{
  uint64_t sum;
  unsigned i;

  for (i = 0, sum = _SKEIN_C240; i < _SKEIN256_LENGTH; i++)
    sum ^= keys[i];
  keys[_SKEIN256_LENGTH] = sum;
  keys[_SKEIN256_LENGTH + 1] = keys[0];
  tweak[2] = tweak[0] ^ tweak[1];
  tweak[3] = tweak[0];
}

void
skein256_init(struct skein256_ctx *ctx)
{
  static const uint64_t G0[4] = {
    0xFC9DA860D048B449ull,
    0x2FCA66479FA7D833ull,
    0xB33BC3896656840Full,
    0x6A54E920FDE8DA69ull,
  };
  memcpy (ctx->state, G0, sizeof(G0));
  ctx->count = 0;
  ctx->index = 0;
}

static void
skein256_process_block(struct skein256_ctx *ctx,
		       unsigned tag, unsigned length,
		       const uint8_t *data)
{
  /* Expand key */
  uint64_t tweak[_SKEIN_NTWEAK];

  tag |= ((ctx->count == 0) << 6);

  tweak[0] = (ctx->count << 5) + length;
  tweak[1] = (ctx->count >> 59) | ((unsigned long long) tag << 56);
  _skein256_expand(ctx->state, tweak);

  _skein256_block(ctx->state, ctx->state, tweak, data);

  ctx->count++;

  /* Wraparound not handled (limited message size). */
  assert (ctx->count > 0);
}

void
skein256_update(struct skein256_ctx *ctx,
		size_t length,
		const uint8_t *data)
{
  if (ctx->index > 0)
    {
      unsigned left = SKEIN256_BLOCK_SIZE - ctx->index;
      if (length <= left)
	{
	  memcpy (ctx->block + ctx->index, data, length);
	  ctx->index += length;
	  return;
	}
      memcpy (ctx->block + ctx->index, data, left);
      data += left;
      length -= left;

      assert (length > 0);

      skein256_process_block(ctx, 0x30, SKEIN256_BLOCK_SIZE, ctx->block);
    }
  while (length > SKEIN256_BLOCK_SIZE)
    {
      skein256_process_block(ctx, 0x30, SKEIN256_BLOCK_SIZE, data);
      data += SKEIN256_BLOCK_SIZE;
      length -= SKEIN256_BLOCK_SIZE;
    }
  assert (length <= SKEIN256_BLOCK_SIZE);
  memcpy (ctx->block, data, length);
  ctx->index = length;
}

void
skein256_digest(struct skein256_ctx *ctx,
		size_t length,
		uint8_t *digest)
{
  static const uint8_t zeros[32];

  /* FIXME: Should be always true. */
  if (ctx->index > 0 || ctx->count == 0)
    {
      memset (ctx->block + ctx->index, 0,
	      SKEIN256_BLOCK_SIZE - ctx->index);
      skein256_process_block(ctx, 0xb0, ctx->index, ctx->block);
    }
  /* Reset count for output processing. */
  ctx->count = 0;
  skein256_process_block(ctx, 0xff, 8, zeros);
  _nettle_write_le64(length, digest, ctx->state);

  skein256_init(ctx);
}
