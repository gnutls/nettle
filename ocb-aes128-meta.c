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

static void
ocb_aes128_set_nonce12 (struct ocb_aes128_ctx *ctx,
		      const uint8_t *nonce)
{
  ocb_aes128_set_nonce (ctx, OCB_NONCE_SIZE, nonce);
}

const struct nettle_aead
nettle_ocb_aes128 =
  { "ocb_aes128", sizeof(struct ocb_aes128_ctx),
    OCB_BLOCK_SIZE, AES128_KEY_SIZE,
    OCB_NONCE_SIZE, OCB_DIGEST_SIZE,
    (nettle_set_key_func *) ocb_aes128_set_key,
    (nettle_set_key_func *) ocb_aes128_set_key,
    (nettle_set_key_func *) ocb_aes128_set_nonce12,
    (nettle_hash_update_func *) ocb_aes128_update,
    (nettle_crypt_func *) ocb_aes128_encrypt,
    (nettle_crypt_func *) ocb_aes128_decrypt,
    (nettle_hash_digest_func *) ocb_aes128_digest
  };
