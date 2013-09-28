/* aes-set-encrypt-key.c
 *
 * Key setup for the aes/rijndael block cipher.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2000, 2001, 2002 Rafael R. Sevilla, Niels Möller
 * Copyright (C) 2013 Niels Möller
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

/* Originally written by Rafael R. Sevilla <dido@pacific.net.ph> */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>

#include "aes-internal.h"

void
aes_set_encrypt_key(struct aes_ctx *ctx,
		    size_t keysize, const uint8_t *key)
{
  unsigned nk, nr;

  assert(keysize >= AES_MIN_KEY_SIZE);
  assert(keysize <= AES_MAX_KEY_SIZE);
  
  /* Truncate keysizes to the valid key sizes provided by Rijndael */
  if (keysize == AES256_KEY_SIZE) {
    nk = 8;
    nr = _AES256_ROUNDS;
  } else if (keysize >= AES192_KEY_SIZE) {
    nk = 6;
    nr = _AES192_ROUNDS;
  } else { /* must be 16 or more */
    nk = 4;
    nr = _AES128_ROUNDS;
  }

  ctx->rounds = nr;
  _aes_set_key (nr, nk, ctx->keys, key);
}
