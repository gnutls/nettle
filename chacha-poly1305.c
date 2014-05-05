/* chacha-poly1305.h

   AEAD mechanism based on chacha and poly1305.

   Copyright (C) 2014 Niels Möller

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

#include "chacha-poly1305.h"

#include "macros.h"

#define CHACHA_ROUNDS 20

/* FIXME: Also set nonce to zero, and implement nonce
   auto-increment? */
void
chacha_poly1305_set_key (struct chacha_poly1305_ctx *ctx,
			 const uint8_t *key)
{
  chacha_set_key (&ctx->chacha, key);
}

void
chacha_poly1305_set_nonce (struct chacha_poly1305_ctx *ctx,
			   const uint8_t *nonce)
{
  union {
    uint32_t x[_CHACHA_STATE_LENGTH];
    uint8_t subkey[32];
  } u;

  chacha_set_nonce (&ctx->chacha, nonce);
  /* Generate authentication key */
  _chacha_core (u.x, ctx->chacha.state, CHACHA_ROUNDS);
  poly1305_set_key (&ctx->poly1305, u.subkey);  
  /* For final poly1305 processing */
  memcpy (ctx->s.b, u.subkey + 16, 16);
  /* Increment block count */
  ctx->chacha.state[12] = 1;

  ctx->auth_size = ctx->data_size = ctx->index = 0;
}

/* FIXME: Duplicated in poly1305-aes128.c */
#define COMPRESS(ctx, data) _poly1305_block(&(ctx)->poly1305, (data), 1)

static void
poly1305_update (struct chacha_poly1305_ctx *ctx,
		 size_t length, const uint8_t *data)
{
  MD_UPDATE (ctx, length, data, COMPRESS, (void) 0);
}

void
chacha_poly1305_update (struct chacha_poly1305_ctx *ctx,
			size_t length, const uint8_t *data)
{
  assert (ctx->data_size == 0);  
  poly1305_update (ctx, length, data);
  ctx->auth_size += length;
}


void
chacha_poly1305_encrypt (struct chacha_poly1305_ctx *ctx,
			 size_t length, uint8_t *dst, const uint8_t *src)
{
  if (!length)
    return;

  assert (ctx->data_size % CHACHA_POLY1305_BLOCK_SIZE == 0);
  if (!ctx->data_size)
    {
      uint8_t buf[8];
      LE_WRITE_UINT64 (buf, ctx->auth_size);
      poly1305_update (ctx, sizeof(buf), buf);
    }
  chacha_crypt (&ctx->chacha, length, dst, src);
  poly1305_update (ctx, length, dst);
  ctx->data_size += length;
}
			 
void
chacha_poly1305_decrypt (struct chacha_poly1305_ctx *ctx,
			 size_t length, uint8_t *dst, const uint8_t *src)
{
  if (!length)
    return;

  assert (ctx->data_size % CHACHA_POLY1305_BLOCK_SIZE == 0);
  if (!ctx->data_size)
    {
      uint8_t buf[8];
      LE_WRITE_UINT64 (buf, ctx->auth_size);
      poly1305_update (ctx, sizeof(buf), buf);
    }
  poly1305_update (ctx, length, src);
  chacha_crypt (&ctx->chacha, length, dst, src);
  ctx->data_size += length;
}
			 
void
chacha_poly1305_digest (struct chacha_poly1305_ctx *ctx,
			size_t length, uint8_t *digest)
{
  uint8_t buf[8];
  if (!ctx->data_size)
    {
      LE_WRITE_UINT64 (buf, ctx->auth_size);
      poly1305_update (ctx, sizeof(buf), buf);
    }
  LE_WRITE_UINT64 (buf, ctx->data_size);
  poly1305_update (ctx, sizeof(buf), buf);

  /* Final bytes. FIXME: Duplicated in poly1305_aes128.c */
  if (ctx->index > 0)
    {
      assert (ctx->index < POLY1305_BLOCK_SIZE);

      ctx->block[ctx->index] = 1;
      memset (ctx->block + ctx->index + 1,
	      0, POLY1305_BLOCK_SIZE - 1 - ctx->index);

      _poly1305_block (&ctx->poly1305, ctx->block, 0);
    }
  
  poly1305_digest (&ctx->poly1305, &ctx->s);
  memcpy (digest, &ctx->s.b, length);
}
