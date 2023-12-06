/* drbg-ctr-aes256.c

   Copyright (C) 2023 Simon Josefsson

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
#include "config.h"
#endif

#include "drbg-ctr.h"

#include <string.h>
#include "macros.h"
#include "memxor.h"
#include "block-internal.h"

/* provided_data is either NULL or a pointer to
   DRBG_CTR_AES256_SEED_SIZE (= 48) bytes. */
static void
drbg_ctr_aes256_update (struct aes256_ctx *key,
			union nettle_block16 *V, const uint8_t *provided_data)
{
  union nettle_block16 tmp[3];

  INCREMENT (AES_BLOCK_SIZE, V->b);
  aes256_encrypt (key, AES_BLOCK_SIZE, tmp[0].b, V->b);

  INCREMENT (AES_BLOCK_SIZE, V->b);
  aes256_encrypt (key, AES_BLOCK_SIZE, tmp[1].b, V->b);

  INCREMENT (AES_BLOCK_SIZE, V->b);
  aes256_encrypt (key, AES_BLOCK_SIZE, tmp[2].b, V->b);

  if (provided_data)
    memxor (tmp[0].b, provided_data, DRBG_CTR_AES256_SEED_SIZE);

  aes256_set_encrypt_key (key, tmp[0].b);
  block16_set (V, &tmp[2]);
}

void
drbg_ctr_aes256_init (struct drbg_ctr_aes256_ctx *ctx, uint8_t *seed_material)
{
  static const uint8_t zero_key[AES256_KEY_SIZE] = {0};

  aes256_set_encrypt_key (&ctx->key, zero_key);

  block16_zero (&ctx->V);
  drbg_ctr_aes256_update (&ctx->key, &ctx->V, seed_material);
}

void
drbg_ctr_aes256_random (struct drbg_ctr_aes256_ctx *ctx,
			size_t n, uint8_t *dst)
{
  while (n >= AES_BLOCK_SIZE)
    {
      INCREMENT (AES_BLOCK_SIZE, ctx->V.b);
      aes256_encrypt (&ctx->key, AES_BLOCK_SIZE, dst, ctx->V.b);
      dst += AES_BLOCK_SIZE;
      n -= AES_BLOCK_SIZE;
    }

  if (n > 0)
    {
      union nettle_block16 block;

      INCREMENT (AES_BLOCK_SIZE, ctx->V.b);
      aes256_encrypt (&ctx->key, AES_BLOCK_SIZE, block.b, ctx->V.b);
      memcpy (dst, block.b, n);
    }

  drbg_ctr_aes256_update (&ctx->key, &ctx->V, NULL);
}
