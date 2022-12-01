/* ocb-aes128.c

   Copyright (C) 2022 Niels Möller

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

#include "ocb.h"

void
ocb_aes128_set_key (struct ocb_aes128_ctx *ctx, const uint8_t *key)
{
  aes128_set_encrypt_key (&ctx->encrypt, key);
  aes128_invert_key (&ctx->decrypt, &ctx->encrypt);
  ocb_set_key (&ctx->key, &ctx->encrypt, (nettle_cipher_func *) aes128_encrypt);
}

void
ocb_aes128_set_nonce (struct ocb_aes128_ctx *ctx,
		      size_t nonce_length, const uint8_t *nonce)
{
  ocb_set_nonce (&ctx->ocb, &ctx->encrypt, (nettle_cipher_func *) aes128_encrypt,
		 OCB_DIGEST_SIZE, nonce_length, nonce);
}

void
ocb_aes128_update (struct ocb_aes128_ctx *ctx,
		   size_t length, const uint8_t *data)
{
  ocb_update (&ctx->ocb, &ctx->key, &ctx->encrypt, (nettle_cipher_func *) aes128_encrypt,
	      length, data);
}

void
ocb_aes128_encrypt(struct ocb_aes128_ctx *ctx,
		   size_t length, uint8_t *dst, const uint8_t *src)
{
  ocb_encrypt (&ctx->ocb, &ctx->key, &ctx->encrypt, (nettle_cipher_func *) aes128_encrypt,
	       length, dst, src);
}

void
ocb_aes128_decrypt(struct ocb_aes128_ctx *ctx,
		   size_t length, uint8_t *dst, const uint8_t *src)
{
  ocb_decrypt (&ctx->ocb, &ctx->key, &ctx->encrypt, (nettle_cipher_func *) aes128_encrypt,
	       &ctx->decrypt, (nettle_cipher_func *) aes128_decrypt,
	       length, dst, src);
}

void
ocb_aes128_digest(struct ocb_aes128_ctx *ctx, size_t length, uint8_t *digest)
{
  ocb_digest (&ctx->ocb, &ctx->key, &ctx->encrypt, (nettle_cipher_func *) aes128_encrypt,
	      length, digest);
}

void
ocb_aes128_encrypt_message (const struct aes128_ctx *cipher,
			    size_t nlength, const uint8_t *nonce,
			    size_t alength, const uint8_t *adata,
			    size_t tlength,
			    size_t clength, uint8_t *dst, const uint8_t *src)
{
  struct ocb_key key;
  ocb_set_key (&key, cipher, (nettle_cipher_func *) aes128_encrypt);
  ocb_encrypt_message (&key, cipher, (nettle_cipher_func *) aes128_encrypt,
		       nlength, nonce, alength, adata, tlength, clength, dst, src);
}

int
ocb_aes128_decrypt_message (const struct aes128_ctx *cipher,
			    size_t nlength, const uint8_t *nonce,
			    size_t alength, const uint8_t *adata,
			    size_t tlength,
			    size_t mlength, uint8_t *dst, const uint8_t *src)
{
  struct ocb_key key;
  struct aes128_ctx decrypt_ctx;
  aes128_invert_key (&decrypt_ctx, cipher);
  ocb_set_key (&key, cipher, (nettle_cipher_func *) aes128_encrypt);
  return ocb_decrypt_message (&key, cipher, (nettle_cipher_func *) aes128_encrypt,
			      &decrypt_ctx, (nettle_cipher_func *) aes128_decrypt,
			      nlength, nonce, alength, adata,
			      tlength, mlength, dst, src);
}
