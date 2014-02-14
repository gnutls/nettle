/* aead-decrypt-msg.c
 */

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

#include <string.h>

#include "aead.h"

#include "nettle-internal.h"
#include "nettle-meta.h"

size_t
aead_decrypt_msg_size(const struct nettle_aead *aead, size_t size)
{
  if (size < aead->digest_size)
    /* Invalid message */
    return 0;
  else
    return size - aead->digest_size;
}

int
aead_decrypt_msg (const struct nettle_aead *aead,
		  void *ctx, const uint8_t *nonce,
		  size_t ad_size, const uint8_t *ad,
		  size_t gibberish_size,
		  uint8_t *plaintext, const uint8_t *gibberish)
{
  TMP_DECL (digest, uint8_t, NETTLE_MAX_HASH_DIGEST_SIZE);
  size_t plaintext_size;

  TMP_ALLOC (digest, aead->digest_size);
  plaintext_size = gibberish_size - aead->digest_size;

  /* Allow NULL nonce, for the case that the caller already has done
     that. E.g., if the application uses a nonce size different from
     aead->nonce_size. */
  if (nonce)
    aead->set_nonce (ctx, nonce);
  
  if (gibberish_size < aead->digest_size)
    /* Invalid message */
    return 0;

  aead->update (ctx, ad_size, ad);
  aead->decrypt (ctx, plaintext_size, plaintext, gibberish);
  aead->digest (ctx, aead->digest_size, digest);
  return memcmp (gibberish + plaintext_size,
		 digest, aead->digest_size) == 0;
}
