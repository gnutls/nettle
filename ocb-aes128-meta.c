/* ocb-aes128-meta.c

   Copyright (C) 2021 Niels Möller

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

#include "aes.h"
#include "ocb.h"
#include "nettle-meta.h"

#define OCB_NONCE_SIZE 12

struct ocb_aes128_ctx
{
  struct ocb_ctx ocb;
  struct ocb_aes128_encrypt_key key;
  struct aes128_ctx decrypt;
};

static void
set_encrypt_key_wrapper (struct ocb_aes128_ctx *ctx, const uint8_t *key)
{
  ocb_aes128_set_encrypt_key(&ctx->key, key);
}

static void
set_decrypt_key_wrapper (struct ocb_aes128_ctx *ctx, const uint8_t *key)
{
  ocb_aes128_set_decrypt_key(&ctx->key, &ctx->decrypt, key);
}

static void
set_nonce_wrapper (struct ocb_aes128_ctx *ctx, const uint8_t *nonce)
{
  ocb_aes128_set_nonce (&ctx->ocb, &ctx->key,
			OCB_DIGEST_SIZE, OCB_NONCE_SIZE, nonce);
}

static void
update_wrapper (struct ocb_aes128_ctx *ctx, size_t length, const uint8_t *data)
{
  ocb_aes128_update (&ctx->ocb, &ctx->key, length, data);
}

static void
encrypt_wrapper (struct ocb_aes128_ctx *ctx,
		 size_t length, uint8_t *dst, const uint8_t *src)
{
  ocb_aes128_encrypt (&ctx->ocb, &ctx->key, length, dst, src);
}

static void
decrypt_wrapper (struct ocb_aes128_ctx *ctx,
		 size_t length, uint8_t *dst, const uint8_t *src)
{
  ocb_aes128_decrypt (&ctx->ocb, &ctx->key, &ctx->decrypt, length, dst, src);
}

static void
digest_wrapper (struct ocb_aes128_ctx *ctx, size_t length, uint8_t *digest)
{
  ocb_aes128_digest (&ctx->ocb, &ctx->key, length, digest);
}

const struct nettle_aead
nettle_ocb_aes128 =
  { "ocb_aes128", sizeof(struct ocb_aes128_ctx),
    OCB_BLOCK_SIZE, AES128_KEY_SIZE,
    OCB_NONCE_SIZE, OCB_DIGEST_SIZE,
    (nettle_set_key_func *) set_encrypt_key_wrapper,
    (nettle_set_key_func *) set_decrypt_key_wrapper,
    (nettle_set_key_func *) set_nonce_wrapper,
    (nettle_hash_update_func *) update_wrapper,
    (nettle_crypt_func *) encrypt_wrapper,
    (nettle_crypt_func *) decrypt_wrapper,
    (nettle_hash_digest_func *) digest_wrapper
  };
