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

#define OCB_IV_SIZE 12

struct ocb_aes128_ctx
{
  struct ocb_key key;
  struct ocb_ctx ocb;
  struct aes128_ctx encrypt;
  struct aes128_ctx decrypt;
};

static void
ocb_aes128_set_key (struct ocb_aes128_ctx *ctx, const uint8_t *key)
{
  aes128_set_encrypt_key (&ctx->encrypt, key);
  aes128_invert_key (&ctx->decrypt, &ctx->encrypt);
  ocb_set_key (&ctx->key, &ctx->encrypt, (nettle_cipher_func *) aes128_encrypt);
}

static void
ocb_aes128_set_nonce (struct ocb_aes128_ctx *ctx,
		      const uint8_t *iv)
{
  ocb_set_nonce (&ctx->ocb, &ctx->encrypt, (nettle_cipher_func *) aes128_encrypt,
		 OCB_DIGEST_SIZE, OCB_IV_SIZE, iv);
}

static void
ocb_aes128_update (struct ocb_aes128_ctx *ctx,
		   size_t length, const uint8_t *data)
{
  ocb_update (&ctx->ocb, &ctx->key, &ctx->encrypt, (nettle_cipher_func *) aes128_encrypt,
	      length, data);
}

static void
ocb_aes128_encrypt(struct ocb_aes128_ctx *ctx,
		   size_t length, uint8_t *dst, const uint8_t *src)
{
  ocb_encrypt (&ctx->ocb, &ctx->key, &ctx->encrypt, (nettle_cipher_func *) aes128_encrypt,
	       length, dst, src);
}

static void
ocb_aes128_decrypt(struct ocb_aes128_ctx *ctx,
		   size_t length, uint8_t *dst, const uint8_t *src)
{
  ocb_decrypt (&ctx->ocb, &ctx->key, &ctx->encrypt, (nettle_cipher_func *) aes128_encrypt,
	       &ctx->decrypt, (nettle_cipher_func *) aes128_decrypt,
	       length, dst, src);
}

static void
ocb_aes128_digest(struct ocb_aes128_ctx *ctx, size_t length, uint8_t *digest)
{
  ocb_digest (&ctx->ocb, &ctx->key, &ctx->encrypt, (nettle_cipher_func *) aes128_encrypt,
	      length, digest);
}

const struct nettle_aead
nettle_ocb_aes128 =
  { "ocb_aes128", sizeof(struct ocb_aes128_ctx),
    OCB_BLOCK_SIZE, AES128_KEY_SIZE,
    OCB_IV_SIZE, OCB_DIGEST_SIZE,
    (nettle_set_key_func *) ocb_aes128_set_key,
    (nettle_set_key_func *) ocb_aes128_set_key,
    (nettle_set_key_func *) ocb_aes128_set_nonce,
    (nettle_hash_update_func *) ocb_aes128_update,
    (nettle_crypt_func *) ocb_aes128_encrypt,
    (nettle_crypt_func *) ocb_aes128_decrypt,
    (nettle_hash_digest_func *) ocb_aes128_digest
  };
