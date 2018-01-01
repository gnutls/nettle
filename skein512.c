/* skein512.c

   Copyright (C) 2016, 2017, 2018 Niels Möller

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
_skein512_expand(uint64_t keys[_SKEIN512_NKEYS])
{
  uint64_t sum;
  unsigned i;

  for (i = 0, sum = _SKEIN_C240; i < _SKEIN512_LENGTH; i++)
    sum ^= keys[i];
  keys[_SKEIN512_LENGTH] = sum;

  /* Repeat keys, for simpler indexing. */
  for (i = _SKEIN512_LENGTH + 1; i < _SKEIN512_NKEYS; i++)
    keys[i] = keys[i-9];
}

void
skein512_init(struct skein512_ctx *ctx)
{
  static const uint64_t G0[_SKEIN512_LENGTH] = {
    0x4903ADFF749C51CEull, 0x0D95DE399746DF03ull,
    0x8FD1934127C79BCEull, 0x9A255629FF352CB1ull,
    0x5DB62599DF6CA7B0ull, 0xEABE394CA9D5C3F4ull,
    0x991112C71A75B523ull, 0xAE18A40B660FCC33ull,
  };
  memcpy (ctx->state, G0, sizeof(G0));
  ctx->count = 0;
  ctx->index = 0;
}

static void
skein512_process_block(struct skein512_ctx *ctx,
		       unsigned tag, unsigned length,
		       const uint8_t *data)
{
  /* Expand key */
  uint64_t tweak[_SKEIN_NTWEAK];

  tag |= ((ctx->count == 0) << 6);

  tweak[0] = (ctx->count << 6) + length;
  tweak[1] = (ctx->count >> 58) | ((uint64_t) tag << 56);
  _skein512_expand(ctx->state);

  _skein512_block(ctx->state, ctx->state, tweak, data);

  ctx->count++;

  /* Wraparound not handled (limited message size). */
  assert (ctx->count > 0);
}

void
skein512_update(struct skein512_ctx *ctx,
		size_t length,
		const uint8_t *data)
{
  if (ctx->index > 0)
    {
      unsigned left = SKEIN512_BLOCK_SIZE - ctx->index;
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

      skein512_process_block(ctx, 0x30, SKEIN512_BLOCK_SIZE, ctx->block);
    }
  while (length > SKEIN512_BLOCK_SIZE)
    {
      skein512_process_block(ctx, 0x30, SKEIN512_BLOCK_SIZE, data);
      data += SKEIN512_BLOCK_SIZE;
      length -= SKEIN512_BLOCK_SIZE;
    }
  assert (length <= SKEIN512_BLOCK_SIZE);
  memcpy (ctx->block, data, length);
  ctx->index = length;
}

void
skein512_digest(struct skein512_ctx *ctx,
		size_t length,
		uint8_t *digest)
{
  static const uint8_t zeros[SKEIN512_BLOCK_SIZE];

  /* FIXME: Should be always true. */
  if (ctx->index > 0 || ctx->count == 0)
    {
      memset (ctx->block + ctx->index, 0,
	      SKEIN512_BLOCK_SIZE - ctx->index);
      skein512_process_block(ctx, 0xb0, ctx->index, ctx->block);
    }
  /* Reset count for output processing. */
  ctx->count = 0;
  skein512_process_block(ctx, 0xff, 8, zeros);
  _nettle_write_le64(length, digest, ctx->state);

  skein512_init(ctx);
}
