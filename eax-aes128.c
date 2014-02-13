/* eax-aes128.c
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2013, 2014 Niels Möller
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
# include "config.h"
#endif

#include "eax.h"

void
eax_aes128_set_key(struct eax_aes128_ctx *ctx, const uint8_t *key)
{
  EAX_SET_KEY(ctx,
	      aes128_set_encrypt_key, aes128_encrypt,
	      key);
}

void
eax_aes128_set_nonce(struct eax_aes128_ctx *ctx,
		     size_t length, const uint8_t *iv)
{
  EAX_SET_NONCE(ctx, aes128_encrypt, length, iv);
}

void
eax_aes128_update(struct eax_aes128_ctx *ctx, size_t length, const uint8_t *data)
{
  EAX_UPDATE(ctx, aes128_encrypt, length, data);
}

void
eax_aes128_encrypt(struct eax_aes128_ctx *ctx,
		   size_t length, uint8_t *dst, const uint8_t *src)
{
  EAX_ENCRYPT(ctx, aes128_encrypt, length, dst, src);
}

void
eax_aes128_decrypt(struct eax_aes128_ctx *ctx,
		   size_t length, uint8_t *dst, const uint8_t *src)
{
  EAX_DECRYPT(ctx, aes128_encrypt, length, dst, src);
}

void
eax_aes128_digest(struct eax_aes128_ctx *ctx,
		  size_t length, uint8_t *digest)
{
  EAX_DIGEST(ctx, aes128_encrypt, length, digest);
}
