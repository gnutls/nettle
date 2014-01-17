/* poly1305.h
 *
 * Poly1305 message authentication code.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
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

#ifndef NETTLE_POLY1305_H_INCLUDED
#define NETTLE_POLY1305_H_INCLUDED

#include "aes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define poly1305_set_key nettle_poly1305_set_key
#define poly1305_update nettle_poly1305_update
#define poly1305_block nettle_poly1305_block
#define poly1305_digest nettle_poly1305_digest

#define poly1305_aes_set_key nettle_poly1305_aes_set_key
#define poly1305_aes_set_nonce nettle_poly1305_aes_set_nonce
#define poly1305_aes_digest nettle_poly1305_aes_digest

/* Low level functions/macros for the poly1305 construction. */

#define POLY1305_DIGEST_SIZE 16
#define POLY1305_BLOCK_SIZE 16
#define POLY1305_KEY_SIZE 16

struct poly1305_ctx {
  /* Key, 128-bit value and some cached multiples. */
  union
  {
    uint32_t r32[6];
    uint64_t r64[3];
  } r;
  uint32_t s32[3];
  /* State, represented as words of 26, 32 or 64 bits, depending on
     implementation. */
  /* High bits first, to maintain alignment. */
  uint32_t hh;
  union
  {
    uint32_t h32[4];
    uint64_t h64[2];
  } h;

  uint8_t block[POLY1305_BLOCK_SIZE];
  unsigned index;
};

void poly1305_set_key(struct poly1305_ctx *ctx, const uint8_t key[POLY1305_KEY_SIZE]);
void poly1305_block (struct poly1305_ctx *ctx, const uint8_t m[POLY1305_BLOCK_SIZE]);
void poly1305_update (struct poly1305_ctx *ctx, size_t size, const uint8_t *data);
void poly1305_digest (struct poly1305_ctx *ctx,
		      size_t length, uint8_t *digest, const uint8_t *s);

/* poly1305-aes */

#define POLY1305_AES_KEY_SIZE 32
#define POLY1305_AES_DIGEST_SIZE 16
#define POLY1305_AES_NONCE_SIZE 16

struct poly1305_aes_ctx
{
  /* Must be first element, for the poly1305_aes_update cast to work. */
  struct poly1305_ctx pctx;
  uint8_t nonce[POLY1305_BLOCK_SIZE];
  struct aes128_ctx aes;
};

/* Also initialize the nonce to zero. */
void
poly1305_aes_set_key (struct poly1305_aes_ctx *ctx, const uint8_t *key);

/* Optional, if not used, messages get incrementing nonces starting from zero. */
void
poly1305_aes_set_nonce (struct poly1305_aes_ctx *ctx,
		        const uint8_t *nonce);

/* An alias, nothing aes-specific. */
#define poly1305_aes_update \
  (*(void(*)(struct poly1305_aes_ctx *, size_t, const uint8_t *))&poly1305_update)

/* Also increments the nonce */
void
poly1305_aes_digest (struct poly1305_aes_ctx *ctx,
	       	     size_t length, uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_POLY1305_H_INCLUDED */
