/* blake2b.c

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
/* R1, R2, R3, R4 = 32, 24, 16, 63, defined as rotations right. */
#define BLAKE2B_G(x0, x1, x2, x3, w0, w1) do {		\
    x0 += x1 + (w0); x3 = ROTL64 (32, (x0 ^ x3));	\
    x2 += x3;        x1 = ROTL64 (40, (x1 ^ x2));	\
    x0 += x1 + (w1); x3 = ROTL64 (48, (x0 ^ x3));	\
    x2 += x3;        x1 = ROTL64 (1,  (x1 ^ x2));	\
  } while (0)


/* Same as sha512 H0. */
static const uint64_t iv[8] =
  {
    0x6A09E667F3BCC908ULL,0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL,0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL,0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL,0x5BE0CD19137E2179ULL,
  };

static void
blake2b_compress (uint64_t *h, const uint8_t *input,
		  uint64_t count_low, uint64_t count_high, int final)
{
  static const unsigned char sigma[12][16] =
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
      { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
      { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    };
  uint64_t v[16];
  uint64_t m[16];
  unsigned i;

  for (i = 0; i < 16; i++, input += 8)
    m[i] = LE_READ_UINT64(input);

  for (i = 0; i < 8; i++)
    {
      v[i] = h[i];
      v[8+i] = iv[i];
    }
  v[12] ^= count_low;
  v[13] ^= count_high;
  v[14] ^= - (uint64_t) final;

  for (i = 0; i < 12; i++)
    {
      BLAKE2B_G (v[0], v[4], v[ 8], v[12], m[sigma[i][ 0]], m[sigma[i][ 1]]);
      BLAKE2B_G (v[1], v[5], v[ 9], v[13], m[sigma[i][ 2]], m[sigma[i][ 3]]);
      BLAKE2B_G (v[2], v[6], v[10], v[14], m[sigma[i][ 4]], m[sigma[i][ 5]]);
      BLAKE2B_G (v[3], v[7], v[11], v[15], m[sigma[i][ 6]], m[sigma[i][ 7]]);

      BLAKE2B_G (v[0], v[5], v[10], v[15], m[sigma[i][ 8]], m[sigma[i][ 9]]);
      BLAKE2B_G (v[1], v[6], v[11], v[12], m[sigma[i][10]], m[sigma[i][11]]);
      BLAKE2B_G (v[2], v[7], v[ 8], v[13], m[sigma[i][12]], m[sigma[i][13]]);
      BLAKE2B_G (v[3], v[4], v[ 9], v[14], m[sigma[i][14]], m[sigma[i][15]]);
    }
  for (i = 0; i < 8; i++)
    h[i] ^= v[i] ^ v[8+i];
}

void
blake2b_init (struct blake2b_ctx *ctx, unsigned digest_size)
{
  assert (digest_size > 0 && digest_size <= BLAKE2B_DIGEST_SIZE);
  memcpy (ctx->state, iv, sizeof (ctx->state));
  ctx->state[0] ^= 0x01010000 ^ digest_size;
  ctx->count_low = ctx->count_high = ctx->index = 0;
  ctx->digest_size = digest_size;
}

void
blake2b_update (struct blake2b_ctx *ctx,
		size_t length, const uint8_t *data)
{
  if (!length)
    return;

  /* To be able to pass the finalization flag, don't call the
     compression function until we have input exceeding one block. */
  if (ctx->index)
    {
      unsigned left = BLAKE2B_BLOCK_SIZE - ctx->index;
      if (length <= left)
	{
	  memcpy (ctx->block + ctx->index, data, length);
	  ctx->index += length;
	  return;
	}
      memcpy (ctx->block + ctx->index, data, left);
      ctx->count_low += BLAKE2B_BLOCK_SIZE;
      ctx->count_high += ctx->count_low < BLAKE2B_BLOCK_SIZE;
      blake2b_compress (ctx->state, ctx->block, ctx->count_low, ctx->count_high, 0);
      data += left; length -= left;
    }
  for (; length > BLAKE2B_BLOCK_SIZE;
       data += BLAKE2B_BLOCK_SIZE, length -= BLAKE2B_BLOCK_SIZE)
    {
      ctx->count_low += BLAKE2B_BLOCK_SIZE;
      ctx->count_high += ctx->count_low < BLAKE2B_BLOCK_SIZE;
      blake2b_compress (ctx->state, data, ctx->count_low, ctx->count_high, 0);
    }

  memcpy (ctx->block, data, length);
  ctx->index = length;
}

void
blake2b_digest (struct blake2b_ctx *ctx, uint8_t *digest)
{
  memset (ctx->block + ctx->index, 0, BLAKE2B_BLOCK_SIZE - ctx->index);
  ctx->count_low += ctx->index;
  ctx->count_high += ctx->count_low < ctx->index;
  blake2b_compress (ctx->state, ctx->block, ctx->count_low, ctx->count_high, 1);

  assert (ctx->digest_size <= BLAKE2B_DIGEST_SIZE);
  _nettle_write_le64 (ctx->digest_size, digest, ctx->state);

  blake2b_init (ctx, ctx->digest_size);
}

void
blake2b_512_init (struct blake2b_ctx *ctx)
{
  blake2b_init (ctx, BLAKE2B_DIGEST_SIZE);
}
