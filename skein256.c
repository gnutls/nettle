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

#include "macros.h"
#include "nettle-write.h"

/*
   Subkeys used:

   Round  0 * 4: k0, k1 + t0, k2 + t1, k3
   Round  1 * 4: k1, k2 + t1, k3 + t2, k4 + 1
   Round  2 * 4: k2, k3 + t2, k4 + t0, k0 + 2
   Round  3 * 4: k3, k4 + t0, k0 + t1, k1 + 3
   Round  4 * 4: k4, k0 + t1, k1 + t2, k2 + 4
   Round  5 * 4: k0, k1 + t2, k2 + t0, k3 + 5
   Round  6 * 4: k1, k2 + t0, k3 + t1, k4 + 6
   Round  7 * 4: k2, k3 + t1, k4 + t2, k0 + 7
   Round  8 * 4: k3, k4 + t2, k0 + t0, k1 + 8
   Round  9 * 4: k4, k0 + t0, k1 + t1, k2 + 9
   Round 10 * 4: k0, k1 + t1, k2 + t2, k3 + 10
   Round 11 * 4: k1, k2 + t2, k3 + t0, k4 + 11
   Round 12 * 4: k2, k3 + t0, k4 + t1, k0 + 12
   Round 13 * 4: k3, k4 + t1, k0 + t2, k1 + 13
   Round 14 * 4: k4, k0 + t2, k1 + t0, k2 + 14
   Round 15 * 4: k0, k1 + t0, k2 + t1, k3 + 15
   Round 16 * 4: k1, k2 + t1, k3 + t2, k4 + 16
   Round 17 * 4: k2, k3 + t2, k4 + t0, k0 + 17
   Round 18 * 4: k3, k4 + t0, k0 + t1, k1 + 18

   Single round mangling:

   w0 += w1;
   w1 <<<= r_d0; { 46, 33, 17, 44, 39, 13, 25, 8 }
   w1 ^= w0

   w2 += w3;
   w3 <<<= r_d1; { 36, 27, 49, 9, 30, 50, 29, 35 }
   w3 ^= w2;

   Permute, w1 <- w3, w3 <- w1

   Pairs mixed, if we fold out the permutations

   (0,1) (2,3)
   (0,3) (2,1),
*/

#define ROUND(w0, w1, w2, w3, c0, c1) do {	\
    w0 += w1;								\
    w1 = ROTL64(c0, w1);						\
    w1 ^= w0;								\
									\
    w2 += w3;								\
    w3 = ROTL64(c1, w3);						\
    w3 ^= w2;								\
  } while(0)

#define ADD_SUBKEY(w0, w1, w2, w3, keys, tw, i) do { \
    w0 += (keys)[(i) % 5u];			    \
    w1 += (keys)[((i)+1u) % 5u] + (tw)[(i) % 3u];	    \
    w2 += (keys)[((i)+2u) % 5u] + (tw)[((i)+1u) % 3u]; \
    w3 += (keys)[((i)+3u) % 5u] + (i);		       \
  } while (0)

void
_skein256_block (uint64_t dst[_SKEIN256_LENGTH],
		 const uint64_t keys[_SKEIN256_NKEYS],
		 const uint64_t tweak[_SKEIN_NTWEAK],
		 const uint8_t src[SKEIN256_BLOCK_SIZE])
{
  uint64_t s0, s1, s2, s3;
  uint64_t w0, w1, w2, w3;
  unsigned i;

  w0 = s0 = LE_READ_UINT64(src);
  w1 = s1 = LE_READ_UINT64(src + 8);
  w2 = s2 = LE_READ_UINT64(src + 16);
  w3 = s3 = LE_READ_UINT64(src + 24);

  for (i = 0; i < 9; i++)
    {
      ADD_SUBKEY(w0, w1, w2, w3, keys, tweak, 2*i);

      ROUND(w0, w1, w2, w3, 14, 16);
      ROUND(w0, w3, w2, w1, 52, 57);
      ROUND(w0, w1, w2, w3, 23, 40);
      ROUND(w0, w3, w2, w1, 5, 37);

      ADD_SUBKEY(w0, w1, w2, w3, keys, tweak, 2*i+1);

      ROUND(w0, w1, w2, w3, 25, 33);
      ROUND(w0, w3, w2, w1, 46, 12);
      ROUND(w0, w1, w2, w3, 58, 22);
      ROUND(w0, w3, w2, w1, 32, 32);
    }
  ADD_SUBKEY(w0, w1, w2, w3, keys, tweak, 18);

  dst[0] = s0 ^ w0;
  dst[1] = s1 ^ w1;
  dst[2] = s2 ^ w2;
  dst[3] = s3 ^ w3;
}

void
_skein256_expand(uint64_t keys[_SKEIN256_NKEYS],
		 uint64_t tweak[_SKEIN_NTWEAK])
{
  uint64_t sum;
  unsigned i;

  for (i = 0, sum = _SKEIN_C240; i < _SKEIN256_LENGTH; i++)
    sum ^= keys[i];
  keys[_SKEIN256_LENGTH] = sum;
  tweak[2] = tweak[0] ^ tweak[1];
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
