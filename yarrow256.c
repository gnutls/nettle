/* yarrow256.c
 *
 * The yarrow pseudo-randomness generator.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001 Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "yarrow.h"

#include <assert.h>
#include <string.h>

/* Parameters */

/* An upper limit on the entropy (in bits) in one octet of sample
 * data. */
#define YARROW_MULTIPLIER 4

/* Generator gate threshold */
#define YARROW_GATE_THRESHOLD 10

/* Entropy estimates sticks to this value, it is treated as infinity
 * in calculations. It should fit comfortably in an uint32_t, to avoid
 * overflows. */
#define YARROW_MAX_ENTROPY 0x100000

void
yarrow256_init(struct yarrow256_ctx *ctx,
	       int n,
	       struct yarrow_source *s)
{
  sha256_init(&ctx->pools[0]);
  sha256_init(&ctx->pools[1]);

  ctx->seeded = 0;

  ctx->nsources = n;
  ctx->sources = s;
}

void
yarrow256_update(struct yarrow256_ctx *ctx,
		 unsigned source_index, unsigned entropy,
		 unsigned length, const uint8_t *data)
{
  enum yarrow_pool_id current;
  struct yarrow_source *source;
  
  assert(source_index < ctx->nsources);

  if (!length)
    /* Nothing happens */
    return;

  source = &ctx->sources[source_index];
  
  if (!ctx->seeded)
    /* While seeding, use the slow pool */
    current = YARROW_SLOW;
  else
    {
      current = source->next;
      source->next = !source->next;
    }

  sha256_update(&ctx->pools[current], length, data);
 
  /* FIXME: Use different counters for fast and slow poll? Or a total
   * for fast poll, and individual for slow poll? */

  /* NOTE: We should be careful to avoid overflows in the estimates. */
  if (source->estimate[current] < YARROW_MAX_ENTROPY)
    {
      if (entropy > YARROW_MAX_ENTROPY)
	entropy = YARROW_MAX_ENTROPY;

      if ( (length < (YARROW_MAX_ENTROPY / YARROW_MULTIPLIER))
	   && (entropy > YARROW_MULTIPLIER * length) )
	entropy = YARROW_MULTIPLIER * length;

      /* FIXME: Calling a more sophisticated estimater should be done
       * here. */

      entropy += source->estimate[current];
      if (entropy > YARROW_MAX_ENTROPY)
	entropy = YARROW_MAX_ENTROPY;

      source->estimate[current] = entropy;
    }

  /* Check for seed/reseed */
  
}

static void
yarrow_generate_block(struct yarrow256_ctx *ctx,
		      uint8_t *block)
{
  unsigned i;
  
  aes_encrypt(&ctx->key, AES_BLOCK_SIZE, block, ctx->counter);

  /* Increment counter, treating it as a big-endian number.
   *
   * We could keep a representation of th counter as 4 32-bit values,
   * and write entire words (in big-endian byteorder) into the counter
   * block, whenever they change. */
  for (i = AES_BLOCK_SIZE; i--; )
    {
      if (++ctx->counter[i])
	break;
    }
}

static void
yarrow_generate_block_with_gate(struct yarrow256_ctx *ctx,
				uint8_t *block)
{
  if (ctx->block_count < YARROW_GATE_THRESHOLD)
    {
      yarrow_generate_block(ctx, block);
      ctx->block_count++;
    }
  else
    {
      uint8_t key[AES_MAX_KEY_SIZE];
      unsigned i;

      for (i = 0; i < sizeof(key); i+= AES_BLOCK_SIZE)
	yarrow_generate_block(ctx, key + i);

      aes_set_key(&ctx->key, sizeof(key), key);

      yarrow_generate_block(ctx, block);
      ctx->block_count = 1;
    }
}

void
yarrow256_random(struct yarrow256_ctx *ctx, unsigned length, uint8_t *dst)
{
  assert(ctx->seeded);

  if (ctx->index < AES_BLOCK_SIZE)
    {
      unsigned left = AES_BLOCK_SIZE - ctx->index;

      if (length <= left)
	{
	  memcpy(dst, ctx->buffer + ctx->index, length);
	  ctx->index += length;
	  return;
	}

      memcpy(dst, ctx->buffer + ctx->index, left);
      dst += left;
      length -= left;

      assert(length);
    }

  while (length > AES_BLOCK_SIZE)
    {
      yarrow_generate_block_with_gate(ctx, dst);
      dst += AES_BLOCK_SIZE;
      length -= AES_BLOCK_SIZE;
    }
  if (length)
    {
      assert(length < AES_BLOCK_SIZE);
      yarrow_generate_block_with_gate(ctx, ctx->buffer);
      memcpy(dst, ctx->buffer, length);
      ctx->index = length;
    }
}
