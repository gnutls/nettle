/* ml-kem-internal.h

   ML-KEM (Kyber) key encapsulation mechanism, FIPS 203

   Copyright (C) 2024 Red Hat, Inc.

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

#ifndef NETTLE_ML_KEM_INTERNAL_H_INCLUDED
#define NETTLE_ML_KEM_INTERNAL_H_INCLUDED

#include "ml-kem.h"

#define ML_KEM_768_INNER_PUBLIC_KEY_SIZE 1184
#define ML_KEM_768_INNER_PRIVATE_KEY_SIZE 1152

#define ML_KEM_1024_INNER_PUBLIC_KEY_SIZE 1568
#define ML_KEM_1024_INNER_PRIVATE_KEY_SIZE 1536

/* Name mangling */
#define _ml_kem_generate_keypair_itch _nettle_ml_kem_generate_keypair_itch
#define _ml_kem_generate_keypair _nettle_ml_kem_generate_keypair
#define _ml_kem_encap_itch _nettle_ml_kem_encap_itch
#define _ml_kem_encap _nettle_ml_kem_encap
#define _ml_kem_decap_itch _nettle_ml_kem_decap_itch
#define _ml_kem_decap _nettle_ml_kem_decap

struct ml_kem_params
{
  size_t inner_public_key_size;
  size_t inner_private_key_size;
  size_t public_key_size;
  size_t private_key_size;
  size_t ciphertext_size;

  unsigned k;
  unsigned du;
  unsigned dv;
  unsigned eta1;
};

size_t
_ml_kem_generate_keypair_itch (const struct ml_kem_params *params);

void
_ml_kem_generate_keypair (const struct ml_kem_params *params,
			  uint8_t *pub,
			  uint8_t *key,
			  const uint8_t *seed,
			  uint16_t *scratch);

size_t
_ml_kem_encap_itch (const struct ml_kem_params *params);

void
_ml_kem_encap (const struct ml_kem_params *params,
	       const uint8_t *pub,
	       uint8_t *secret, uint8_t *ciphertext,
	       void *random_ctx, nettle_random_func *random,
	       uint16_t *scratch);

size_t
_ml_kem_decap_itch (const struct ml_kem_params *params);

void
_ml_kem_decap (const struct ml_kem_params *params,
	       const uint8_t *key,
	       uint8_t *secret,
	       const uint8_t *ciphertext,
	       uint16_t *scratch);

#endif /* NETTLE_ML_KEM_INTERNAL_H_INCLUDED */
