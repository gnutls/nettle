/* chacha-poly1305-meta.c */

/* nettle, low-level cryptographics library
 *
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
# include "config.h"
#endif

#include <assert.h>

#include "nettle-meta.h"

#include "chacha-poly1305.h"

const struct nettle_aead nettle_chacha_poly1305 =
  { "chacha_poly1305", sizeof(struct chacha_poly1305_ctx),
    CHACHA_POLY1305_BLOCK_SIZE, CHACHA_POLY1305_KEY_SIZE,
    CHACHA_POLY1305_NONCE_SIZE, CHACHA_POLY1305_DIGEST_SIZE,
    (nettle_set_key_func *) chacha_poly1305_set_key,
    (nettle_set_key_func *) chacha_poly1305_set_key,
    (nettle_set_key_func *) chacha_poly1305_set_nonce,
    (nettle_hash_update_func *) chacha_poly1305_update,
    (nettle_crypt_func *) chacha_poly1305_encrypt,
    (nettle_crypt_func *) chacha_poly1305_decrypt,
    (nettle_hash_digest_func *) chacha_poly1305_digest,
  };
