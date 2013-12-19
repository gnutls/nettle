/* poly1305-aes.h
 *
 * Poly1305 message authentication code.
 */

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

#ifndef NETTLE_POLY1305_AES_H_INCLUDED
#define NETTLE_POLY1305_AES_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include "nettle-types.h"
#include "poly1305.h"
#include "aes.h"

#define POLY1305_AES_KEY_SIZE 32
#define POLY1305_AES_DIGEST_SIZE 16

#define poly1305_aes_set_key nettle_poly1305_aes_set_key
#define poly1305_aes_set_nonce nettle_poly1305_aes_set_nonce
#define poly1305_aes_digest nettle_poly1305_aes_digest

struct poly1305_aes_ctx POLY1305_CTX(struct aes_ctx);

/* The _set_key function initialize the nonce to zero. */
void
poly1305_aes_set_key (struct poly1305_aes_ctx *ctx, const uint8_t *key);

/* Optional, if not used, messages get incrementing nonces starting from zero. */
void
poly1305_aes_set_nonce (struct poly1305_aes_ctx *ctx,
		        const uint8_t *nonce);

#define poly1305_aes_update \
  (*(void(*)(struct poly1305_aes_ctx *, size_t, const uint8_t *))&poly1305_update)

/* The _digest functions increment the nonce */
void
poly1305_aes_digest (struct poly1305_aes_ctx *ctx,
	       	     size_t length, uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_POLY1305_AES_H_INCLUDED */
