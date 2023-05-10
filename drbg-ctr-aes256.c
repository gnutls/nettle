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

static void
drbg_ctr_aes256_update (struct aes256_ctx *Key,
			uint8_t *V, uint8_t *provided_data)
{
  uint8_t tmp[DRBG_CTR_AES256_SEED_SIZE];

  INCREMENT (AES_BLOCK_SIZE, V);
  aes256_encrypt (Key, AES_BLOCK_SIZE, tmp, V);

  INCREMENT (AES_BLOCK_SIZE, V);
  aes256_encrypt (Key, AES_BLOCK_SIZE, tmp + AES_BLOCK_SIZE, V);

  INCREMENT (AES_BLOCK_SIZE, V);
  aes256_encrypt (Key, AES_BLOCK_SIZE, tmp + 2 * AES_BLOCK_SIZE, V);

  if (provided_data)
    memxor (tmp, provided_data, 48);

  aes256_set_encrypt_key (Key, tmp);

  memcpy (V, tmp + AES256_KEY_SIZE, AES_BLOCK_SIZE);
}

void
drbg_ctr_aes256_init (struct drbg_ctr_aes256_ctx *ctx, uint8_t *seed_material)
{
  uint8_t Key[AES256_KEY_SIZE];

  memset (Key, 0, AES256_KEY_SIZE);
  aes256_set_encrypt_key (&ctx->Key, Key);

  memset (ctx->V, 0, AES_BLOCK_SIZE);

  drbg_ctr_aes256_update (&ctx->Key, ctx->V, seed_material);
}

void
drbg_ctr_aes256_random (struct drbg_ctr_aes256_ctx *ctx,
			size_t n, uint8_t *dst)
{
  while (n >= AES_BLOCK_SIZE)
    {
      INCREMENT (AES_BLOCK_SIZE, ctx->V);
      aes256_encrypt (&ctx->Key, AES_BLOCK_SIZE, dst, ctx->V);
      dst += AES_BLOCK_SIZE;
      n -= AES_BLOCK_SIZE;
    }

  if (n > 0)
    {
      uint8_t block[AES_BLOCK_SIZE];

      INCREMENT (AES_BLOCK_SIZE, ctx->V);
      aes256_encrypt (&ctx->Key, AES_BLOCK_SIZE, block, ctx->V);
      memcpy (dst, block, n);
    }

  drbg_ctr_aes256_update (&ctx->Key, ctx->V, NULL);
}
