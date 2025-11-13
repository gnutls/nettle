/* blake2s.c

   Copyright (C) 2025 Niels Möller

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

#include "blake2.h"
#include "macros.h"
#include "nettle-write.h"

/* Blake2 mixing function G, similar to a chacha qround. */
/* R1, R2, R3, R4 = 16, 12, 8, 7, defined as rotation right */
#define BLAKE2S_G(x0, x1, x2, x3, w0, w1) do {		\
    x0 += x1 + (w0); x3 = ROTL32 (16, (x0 ^ x3));	\
    x2 += x3;        x1 = ROTL32 (20, (x1 ^ x2));	\
    x0 += x1 + (w1); x3 = ROTL32 (24, (x0 ^ x3));	\
    x2 += x3;        x1 = ROTL32 (25, (x1 ^ x2));	\
  } while (0)

/* Same as sha256 H0. */
static const uint32_t iv[8] =
  {
    0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
    0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL,
  };

static void
blake2s_compress (uint32_t *h, const uint8_t *input,
		  uint64_t count, int final)
{
  static const unsigned char sigma[10][16] =
    {
      { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
      { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
      { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
      { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
      { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
      { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
      { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
      { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
      { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
      { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    };
  uint32_t v[16];
  uint32_t m[16];
  unsigned i;

  for (i = 0; i < 16; i++, input += 4)
    m[i] = LE_READ_UINT32(input);

  for (i = 0; i < 8; i++)
    {
      v[i] = h[i];
      v[8+i] = iv[i];
    }
  v[12] ^= count;
  v[13] ^= (count >> 32);
  v[14] ^= - (uint32_t) final;

  for (i = 0; i < 10; i++)
    {
      BLAKE2S_G (v[0], v[4], v[ 8], v[12], m[sigma[i][ 0]], m[sigma[i][ 1]]);
      BLAKE2S_G (v[1], v[5], v[ 9], v[13], m[sigma[i][ 2]], m[sigma[i][ 3]]);
      BLAKE2S_G (v[2], v[6], v[10], v[14], m[sigma[i][ 4]], m[sigma[i][ 5]]);
      BLAKE2S_G (v[3], v[7], v[11], v[15], m[sigma[i][ 6]], m[sigma[i][ 7]]);

      BLAKE2S_G (v[0], v[5], v[10], v[15], m[sigma[i][ 8]], m[sigma[i][ 9]]);
      BLAKE2S_G (v[1], v[6], v[11], v[12], m[sigma[i][10]], m[sigma[i][11]]);
      BLAKE2S_G (v[2], v[7], v[ 8], v[13], m[sigma[i][12]], m[sigma[i][13]]);
      BLAKE2S_G (v[3], v[4], v[ 9], v[14], m[sigma[i][14]], m[sigma[i][15]]);
    }
  for (i = 0; i < 8; i++)
    h[i] ^= v[i] ^ v[8+i];
}

void
blake2s_init (struct blake2s_ctx *ctx, unsigned digest_size)
{
  assert (digest_size > 0 && digest_size <= BLAKE2S_DIGEST_SIZE);
  memcpy (ctx->state, iv, sizeof (ctx->state));
  ctx->state[0] ^= 0x01010000 ^ digest_size;
  ctx->count = ctx->index = 0;
  ctx->digest_size = digest_size;
}

void
blake2s_update (struct blake2s_ctx *ctx,
		size_t length, const uint8_t *data)
{
  if (!length)
    return;

  /* To be able to pass the finalization flag, don't call the
     compression function until we have input exceeding one block. */
  if (ctx->index)
    {
      unsigned left = BLAKE2S_BLOCK_SIZE - ctx->index;
      if (length <= left)
	{
	  memcpy (ctx->block + ctx->index, data, length);
	  ctx->index += length;
	  return;
	}
      memcpy (ctx->block + ctx->index, data, left);
      ctx->count += BLAKE2S_BLOCK_SIZE;
      blake2s_compress (ctx->state, ctx->block, ctx->count, 0);
      data += left; length -= left;
    }
  for (; length > BLAKE2S_BLOCK_SIZE;
       data += BLAKE2S_BLOCK_SIZE, length -= BLAKE2S_BLOCK_SIZE)
    {
      ctx->count += BLAKE2S_BLOCK_SIZE;
      blake2s_compress (ctx->state, data, ctx->count, 0);
    }

  memcpy (ctx->block, data, length);
  ctx->index = length;
}

void
blake2s_digest (struct blake2s_ctx *ctx, uint8_t *digest)
{
  memset (ctx->block + ctx->index, 0, BLAKE2S_BLOCK_SIZE - ctx->index);
  blake2s_compress (ctx->state, ctx->block, ctx->count + ctx->index, 1);

  assert (ctx->digest_size <= BLAKE2S_DIGEST_SIZE);
  _nettle_write_le32 (ctx->digest_size, digest, ctx->state);

  blake2s_init (ctx, ctx->digest_size);
}

void
blake2s_256_init (struct blake2s_ctx *ctx)
{
  blake2s_init (ctx, BLAKE2S_DIGEST_SIZE);
}
