/* eax-aes128-meta.c
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
#include "nettle-meta.h"

static nettle_set_key_func eax_aes128_set_nonce_wrapper;
static void
eax_aes128_set_nonce_wrapper (void *ctx, const uint8_t *nonce)
{
  eax_aes128_set_nonce (ctx, EAX_IV_SIZE, nonce);
}

const struct nettle_aead
nettle_eax_aes128 =
  { "eax_aes128", sizeof(struct eax_aes128_ctx),
    EAX_BLOCK_SIZE, AES128_KEY_SIZE,
    EAX_IV_SIZE, EAX_DIGEST_SIZE,
    (nettle_set_key_func *) eax_aes128_set_key,
    (nettle_set_key_func *) eax_aes128_set_key,
    eax_aes128_set_nonce_wrapper,
    (nettle_hash_update_func *) eax_aes128_update,
    (nettle_crypt_func *) eax_aes128_encrypt,
    (nettle_crypt_func *) eax_aes128_decrypt,
    (nettle_hash_digest_func *) eax_aes128_digest
  };
