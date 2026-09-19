/* ml-kem.h

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

#ifndef NETTLE_MLKEM_H_INCLUDED
#define NETTLE_MLKEM_H_INCLUDED

#include "nettle-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define ml_kem_768_generate_keypair_itch nettle_ml_kem_768_generate_keypair_itch
#define ml_kem_768_generate_keypair nettle_ml_kem_768_generate_keypair
#define ml_kem_768_encap_itch nettle_ml_kem_768_encap_itch
#define ml_kem_768_encap nettle_ml_kem_768_encap
#define ml_kem_768_decap_itch nettle_ml_kem_768_decap_itch
#define ml_kem_768_decap nettle_ml_kem_768_decap
#define ml_kem_1024_generate_keypair_itch nettle_ml_kem_1024_generate_keypair_itch
#define ml_kem_1024_generate_keypair nettle_ml_kem_1024_generate_keypair
#define ml_kem_1024_encap_itch nettle_ml_kem_1024_encap_itch
#define ml_kem_1024_encap nettle_ml_kem_1024_encap
#define ml_kem_1024_decap_itch nettle_ml_kem_1024_decap_itch
#define ml_kem_1024_decap nettle_ml_kem_1024_decap

#define ML_KEM_SEED_SIZE 64
#define ML_KEM_SESSION_KEY_SIZE 32

#define ML_KEM_768_PUBLIC_KEY_SIZE 1184
#define ML_KEM_768_PRIVATE_KEY_SIZE 2400
#define ML_KEM_768_CIPHERTEXT_SIZE 1088

#define ML_KEM_1024_PUBLIC_KEY_SIZE 1568
#define ML_KEM_1024_PRIVATE_KEY_SIZE 3168
#define ML_KEM_1024_CIPHERTEXT_SIZE 1568

size_t
ml_kem_768_generate_keypair_itch (void);

void
ml_kem_768_generate_keypair (uint8_t *pub, uint8_t *key,
			     const uint8_t *seed,
			     uint16_t *scratch);

size_t
ml_kem_768_encap_itch (void);

void
ml_kem_768_encap (const uint8_t *pub,
		  uint8_t *secret, uint8_t *ciphertext,
		  void *random_ctx, nettle_random_func *random,
		  uint16_t *scratch);

size_t
ml_kem_768_decap_itch (void);

void
ml_kem_768_decap (const uint8_t *key,
		  uint8_t *secret,
		  const uint8_t *ciphertext,
		  uint16_t *scratch);

size_t
ml_kem_1024_generate_keypair_itch (void);

void
ml_kem_1024_generate_keypair (uint8_t *pub, uint8_t *key,
			     const uint8_t *seed,
			     uint16_t *scratch);

size_t
ml_kem_1024_encap_itch (void);

void
ml_kem_1024_encap (const uint8_t *pub,
		  uint8_t *secret, uint8_t *ciphertext,
		  void *random_ctx, nettle_random_func *random,
		  uint16_t *scratch);

size_t
ml_kem_1024_decap_itch (void);

void
ml_kem_1024_decap (const uint8_t *key,
		  uint8_t *secret,
		  const uint8_t *ciphertext,
		  uint16_t *scratch);

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_ML_KEM_H_INCLUDED */
