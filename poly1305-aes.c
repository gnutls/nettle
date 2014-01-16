/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
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
#include "macros.h"
#include "nettle-types.h"
#include "poly1305-aes.h"

void
poly1305_aes_set_key (struct poly1305_aes_ctx *ctx, const uint8_t * key)
{
  POLY1305_SET_KEY(ctx, aes128_set_encrypt_key, key);
}

void
poly1305_aes_set_nonce (struct poly1305_aes_ctx *ctx,
			const uint8_t * nonce)
{
  POLY1305_SET_NONCE(ctx, nonce);
}

void
poly1305_aes_digest (struct poly1305_aes_ctx *ctx,
		     size_t length, uint8_t * digest)
{
  POLY1305_DIGEST(ctx, aes128_encrypt, length, digest);
}
