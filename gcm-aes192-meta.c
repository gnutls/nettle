/* gcm-aes192-meta.c */

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

#include "gcm.h"

static nettle_set_key_func gcm_aes192_set_nonce_wrapper;
static void
gcm_aes192_set_nonce_wrapper (void *ctx, const uint8_t *nonce)
{
  gcm_aes192_set_iv (ctx, GCM_IV_SIZE, nonce);
}

const struct nettle_aead nettle_gcm_aes192 =
  { "gcm_aes192", sizeof(struct gcm_aes192_ctx),
    GCM_BLOCK_SIZE, AES192_KEY_SIZE,
    GCM_IV_SIZE, GCM_DIGEST_SIZE,
    (nettle_set_key_func *) gcm_aes192_set_key,
    (nettle_set_key_func *) gcm_aes192_set_key,
    gcm_aes192_set_nonce_wrapper,
    (nettle_hash_update_func *) gcm_aes192_update,
    (nettle_crypt_func *) gcm_aes192_encrypt,
    (nettle_crypt_func *) gcm_aes192_decrypt,
    (nettle_hash_digest_func *) gcm_aes192_digest,
  };
