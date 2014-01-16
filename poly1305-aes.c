/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 * Copyright (C) 2014 Niels Möller
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
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "poly1305.h"
#include "macros.h"

void
poly1305_aes_set_key (struct poly1305_aes_ctx *ctx, const uint8_t * key)
{
  aes128_set_encrypt_key(&ctx->aes, (key));
  poly1305_set_key(&ctx->pctx, (key+16));
  ctx->pctx.index = 0;
}

void
poly1305_aes_set_nonce (struct poly1305_aes_ctx *ctx,
			const uint8_t * nonce)
{
  poly1305_set_nonce(&ctx->pctx, nonce);
}

void
poly1305_aes_digest (struct poly1305_aes_ctx *ctx,
		     size_t length, uint8_t * digest)
{
  uint8_t s[POLY1305_BLOCK_SIZE];
  aes128_encrypt(&ctx->aes, POLY1305_BLOCK_SIZE, s, ctx->pctx.nonce);
  poly1305_digest (&ctx->pctx, length, digest, s);
  INCREMENT (16, (ctx)->pctx.nonce);
  (ctx)->pctx.index = 0;
}
