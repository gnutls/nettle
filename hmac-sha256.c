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
#include "memxor.h"

#define IPAD 0x36
#define OPAD 0x5c

void
hmac_sha256_set_key(struct hmac_sha256_ctx *ctx,
		    size_t key_length, const uint8_t *key)
{
  uint8_t digest[SHA256_DIGEST_SIZE];

  sha256_init (&ctx->state);
  if (key_length > SHA256_BLOCK_SIZE)
    {
      sha256_update (&ctx->state, key_length, key);
      sha256_digest (&ctx->state, digest);
      key = digest;
      key_length = SHA256_DIGEST_SIZE;
    }

  memset (ctx->state.block, OPAD, SHA256_BLOCK_SIZE);
  memxor (ctx->state.block, key, key_length);
  sha256_update (&ctx->state, SHA256_BLOCK_SIZE, ctx->state.block);
  memcpy (ctx->outer, ctx->state.state, sizeof(ctx->outer));

  sha256_init (&ctx->state);
  memset (ctx->state.block, IPAD, SHA256_BLOCK_SIZE);
  memxor (ctx->state.block, key, key_length);
  sha256_update (&ctx->state, SHA256_BLOCK_SIZE, ctx->state.block);
  memcpy (ctx->inner, ctx->state.state, sizeof(ctx->outer));
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
  uint8_t inner_digest[SHA256_DIGEST_SIZE];
  sha256_digest (&ctx->state, inner_digest);

  memcpy (ctx->state.state, ctx->outer, sizeof (ctx->state.state));
  ctx->state.count = 1;
  sha256_update (&ctx->state, SHA256_DIGEST_SIZE, inner_digest);
  sha256_digest (&ctx->state, digest);

  memcpy (ctx->state.state, ctx->inner, sizeof (ctx->state.state));
  ctx->state.count = 1;
}
