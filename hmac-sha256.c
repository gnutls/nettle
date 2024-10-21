/* hmac-sha256.c

   HMAC-SHA256 message authentication code.

   Copyright (C) 2003 Niels Möller

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

#include <string.h>

#include "hmac.h"
#include "hmac-internal.h"
#include "memxor.h"
#include "sha2-internal.h"

/* Initialize for processing a new message.*/
static void 
hmac_sha256_init (struct hmac_sha256_ctx *ctx)
{
  memcpy (ctx->state.state, ctx->inner, sizeof (ctx->state.state));
  ctx->state.count = 1;
  /* index should already be zero, from previous call to sha256_init or sha256_digest. */
}

void
hmac_sha256_set_key(struct hmac_sha256_ctx *ctx,
		    size_t key_length, const uint8_t *key)
{
  sha256_init (&ctx->state);
  if (key_length > SHA256_BLOCK_SIZE)
    {
      sha256_update (&ctx->state, key_length, key);
      sha256_digest (&ctx->state, ctx->state.block);
      _nettle_hmac_outer_block_digest (SHA256_BLOCK_SIZE, ctx->state.block, SHA256_DIGEST_SIZE);
    }
  else
    _nettle_hmac_outer_block (SHA256_BLOCK_SIZE, ctx->state.block,
			      key_length, key);

  memcpy (ctx->outer, _nettle_sha256_iv, sizeof(ctx->outer));
  sha256_compress (ctx->outer, ctx->state.block);

  _nettle_hmac_inner_block (SHA256_BLOCK_SIZE, ctx->state.block);
  memcpy (ctx->inner, _nettle_sha256_iv, sizeof(ctx->inner));
  sha256_compress (ctx->inner, ctx->state.block);

  hmac_sha256_init (ctx);
}

void
hmac_sha256_update(struct hmac_sha256_ctx *ctx,
		   size_t length, const uint8_t *data)
{
  sha256_update(&ctx->state, length, data);
}

void
hmac_sha256_digest(struct hmac_sha256_ctx *ctx,
		   uint8_t *digest)
{
  sha256_digest (&ctx->state, ctx->state.block);

  memcpy (ctx->state.state, ctx->outer, sizeof (ctx->state.state));
  ctx->state.count = 1;
  ctx->state.index = SHA256_DIGEST_SIZE;
  sha256_digest (&ctx->state, digest);

  hmac_sha256_init (ctx);
}
