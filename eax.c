/* eax.c
 *
 * EAX mode, see http://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf
 */

/* nettle, low-level cryptographics library
 *
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include "eax.h"

#include "ctr.h"
#include "memxor.h"

static void
omac_init (uint8_t *state, unsigned t)
{
  memset (state, 0, EAX_BLOCK_SIZE - 1);
  state[EAX_BLOCK_SIZE - 1] = t;
}

static void
omac_update (uint8_t *state, const struct eax_key *key,
	     void *cipher, nettle_crypt_func *f,
	     size_t length, const uint8_t *data)
{
  for (; length >= EAX_BLOCK_SIZE;
       length -= EAX_BLOCK_SIZE, data += EAX_BLOCK_SIZE)
    {
      f (cipher, EAX_BLOCK_SIZE, state, state);
      memxor (state, data, EAX_BLOCK_SIZE);
    }
  if (length > 0)
    {
      /* Allowed only for the last call */
      f (cipher, EAX_BLOCK_SIZE, state, state);
      memxor (state, data, length);
      state[length] ^= 0x80;
      /* XOR with (P ^ B), since the digest processing
       * unconditionally XORs with B */
      memxor (state, key->pad_partial, EAX_BLOCK_SIZE);
    }
}

static void
omac_final (uint8_t *state, const struct eax_key *key,
	    void *cipher, nettle_crypt_func *f)
{
  memxor (state, key->pad_block, EAX_BLOCK_SIZE);
  f (cipher, EAX_BLOCK_SIZE, state, state);
}

/* Allows r == a */
static void
gf2_double (uint8_t *r, const uint8_t *a)
{
  unsigned high = - (a[0] >> 7);
  unsigned i;
  /* Shift left */
  for (i = 0; i < EAX_BLOCK_SIZE - 1; i++)
    r[i] = (a[i] << 1) + (a[i+1] >> 7);

  /* Wrap around for x^{128} = x^7 + x^2 + x + 1 */
  r[EAX_BLOCK_SIZE - 1] = (a[EAX_BLOCK_SIZE - 1] << 1) ^ (high & 0x87);
}

void
eax_set_key (struct eax_key *key, void *cipher, nettle_crypt_func *f)
{
  static const uint8_t zero_block[EAX_BLOCK_SIZE];
  f (cipher, EAX_BLOCK_SIZE, key->pad_block, zero_block);
  gf2_double (key->pad_block, key->pad_block);
  gf2_double (key->pad_partial, key->pad_block);
  memxor (key->pad_partial, key->pad_block, EAX_BLOCK_SIZE);
}

void
eax_set_nonce (struct eax_ctx *eax, const struct eax_key *key,
	       void *cipher, nettle_crypt_func *f,
	       size_t nonce_length, const uint8_t *nonce)
{
  omac_init (eax->omac_nonce, 0);
  omac_update (eax->omac_nonce, key, cipher, f, nonce_length, nonce);
  omac_final (eax->omac_nonce, key, cipher, f);
  memcpy (eax->ctr, eax->omac_nonce, EAX_BLOCK_SIZE);

  omac_init (eax->omac_data, 1);
  omac_init (eax->omac_message, 2);
}

void
eax_update (struct eax_ctx *eax, const struct eax_key *key,
	    void *cipher, nettle_crypt_func *f,
	    size_t data_length, const uint8_t *data)
{
  omac_update (eax->omac_data, key, cipher, f, data_length, data);
}

void
eax_encrypt (struct eax_ctx *eax, const struct eax_key *key,
	     void *cipher, nettle_crypt_func *f,
	     size_t length, uint8_t *dst, const uint8_t *src)
{
  ctr_crypt (cipher, f, EAX_BLOCK_SIZE, eax->ctr, length, dst, src);
  omac_update (eax->omac_message, key, cipher, f, length, dst);
}

void
eax_decrypt (struct eax_ctx *eax, const struct eax_key *key,
	     void *cipher, nettle_crypt_func *f,
	     size_t length, uint8_t *dst, const uint8_t *src)
{
  omac_update (eax->omac_message, key, cipher, f, length, src);
  ctr_crypt (cipher, f, EAX_BLOCK_SIZE, eax->ctr, length, dst, src);
}

void
eax_digest (struct eax_ctx *eax, const struct eax_key *key,
	    void *cipher, nettle_crypt_func *f,
	    size_t length, uint8_t *digest)
{
  assert (length > 0);
  assert (length <= EAX_BLOCK_SIZE);
  omac_final (eax->omac_data, key, cipher, f);
  omac_final (eax->omac_message, key, cipher, f);

  memxor (eax->omac_nonce, eax->omac_data, length);
  memxor3 (digest, eax->omac_nonce, eax->omac_message, length);
}
