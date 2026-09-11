/* ml-kem-768.c

   The ML-KEM (Kyber) key encapsulation mechanism, FIPS 203

   Copyright (C) 2024 Red Hat, Inc.
   Copyright (C) 2026 Niels Möller

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

#include "ml-kem.h"

#include "ml-kem-internal.h"

#define ML_KEM_768_K 3
#define ML_KEM_768_DU 10
#define ML_KEM_768_DV 4
#define ML_KEM_768_ETA1 2

static const struct ml_kem_params _nettle_ml_kem_768_params =
  {
    ML_KEM_768_INNER_PUBLIC_KEY_SIZE,
    ML_KEM_768_INNER_PRIVATE_KEY_SIZE,
    ML_KEM_768_PUBLIC_KEY_SIZE,
    ML_KEM_768_PRIVATE_KEY_SIZE,
    ML_KEM_768_CIPHERTEXT_SIZE,
    ML_KEM_768_K,
    ML_KEM_768_DU,
    ML_KEM_768_DV,
    ML_KEM_768_ETA1
  };

const struct ml_kem_params *nettle_get_ml_kem_768_params (void)
{
  return &_nettle_ml_kem_768_params;
}

size_t
ml_kem_768_generate_keypair_itch (void)
{
  return ml_kem_generate_keypair_itch (&_nettle_ml_kem_768_params);
}

void
ml_kem_768_generate_keypair (uint8_t *pub, uint8_t *key,
			     const uint8_t *seed,
			     uint16_t *scratch)
{
  ml_kem_generate_keypair (&_nettle_ml_kem_768_params,
			   pub, key, seed, scratch);
}

size_t
ml_kem_768_encap_itch (void)
{
  return ml_kem_encap_itch (&_nettle_ml_kem_768_params);
}

void
ml_kem_768_encap (const uint8_t *pub,
		  uint8_t *secret, uint8_t *ciphertext,
		  void *random_ctx, nettle_random_func *random,
		  uint16_t *scratch)
{
  ml_kem_encap (&_nettle_ml_kem_768_params,
		pub, secret, ciphertext,
		random_ctx, random, scratch);
}

size_t
ml_kem_768_decap_itch (void)
{
  return ml_kem_decap_itch (&_nettle_ml_kem_768_params);
}

void
ml_kem_768_decap (const uint8_t *key,
		  uint8_t *secret,
		  const uint8_t *ciphertext,
		  uint16_t *scratch)
{
  ml_kem_decap (&_nettle_ml_kem_768_params,
		key, secret, ciphertext, scratch);
}
