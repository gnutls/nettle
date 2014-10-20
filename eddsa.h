/* eddsa.h

   Copyright (C) 2014 Niels Möller

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

#ifndef NETTLE_EDDSA_H
#define NETTLE_EDDSA_H

#include "nettle-types.h"

#include "bignum.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define ed25519_sha512_set_private_key nettle_ed25519_sha512_set_private_key
#define ed25519_sha512_sign nettle_ed25519_sha512_sign
#define ed25519_sha512_set_public_key nettle_ed25519_sha512_set_public_key
#define ed25519_sha512_verify nettle_ed25519_sha512_verify

#define _eddsa_compress _nettle_eddsa_compress
#define _eddsa_compress_itch _nettle_eddsa_compress_itch
#define _eddsa_decompress _nettle_eddsa_decompress
#define _eddsa_decompress_itch _nettle_eddsa_decompress_itch
#define _eddsa_hash _nettle_eddsa_hash
#define _eddsa_expand_key_itch _nettle_eddsa_expand_key_itch
#define _eddsa_expand_key _nettle_eddsa_expand_key
#define _eddsa_sign _nettle_eddsa_sign
#define _eddsa_sign_itch _nettle_eddsa_sign_itch
#define _eddsa_verify _nettle_eddsa_verify
#define _eddsa_verify_itch _nettle_eddsa_verify_itch

#define ED25519_KEY_SIZE 32
#define ED25519_SIGNATURE_SIZE 64

/* Number of limbs needed to represent a point coordinate, or a secret
   exponent (note that exponents are 254 bits, larger than q). */
#define _ED25519_LIMB_SIZE ((255 + (GMP_NUMB_BITS - 1)) / GMP_NUMB_BITS)

struct ed25519_private_key
{
  uint8_t pub[ED25519_KEY_SIZE];
  uint8_t k1[ED25519_KEY_SIZE];
  mp_limb_t k2[_ED25519_LIMB_SIZE];
};

void
ed25519_sha512_set_private_key (struct ed25519_private_key *priv,
				const uint8_t *key);

void
ed25519_sha512_sign (const struct ed25519_private_key *priv,
		     size_t length, const uint8_t *msg,
		     uint8_t *signature);

struct ed25519_public_key
{
  uint8_t pub[ED25519_KEY_SIZE];
  mp_limb_t A[2*_ED25519_LIMB_SIZE];
};

int
ed25519_sha512_set_public_key (struct ed25519_public_key *pub,
			       const uint8_t *key);

int
ed25519_sha512_verify (const struct ed25519_public_key *pub,
		       size_t length, const uint8_t *msg,
		       const uint8_t *signature);

/* Low-level internal functions */

struct ecc_curve;
struct ecc_modulo;

mp_size_t
_eddsa_compress_itch (const struct ecc_curve *ecc);
void
_eddsa_compress (const struct ecc_curve *ecc, uint8_t *r, mp_limb_t *p,
		 mp_limb_t *scratch);

mp_size_t
_eddsa_decompress_itch (const struct ecc_curve *ecc);
int
_eddsa_decompress (const struct ecc_curve *ecc, mp_limb_t *p,
		   const uint8_t *cp,
		   mp_limb_t *scratch);

void
_eddsa_hash (const struct ecc_modulo *m,
	     mp_limb_t *rp, const uint8_t *digest);

mp_size_t
_eddsa_sign_itch (const struct ecc_curve *ecc);

void
_eddsa_sign (const struct ecc_curve *ecc,
	     const struct nettle_hash *H,
	     const uint8_t *pub,
	     void *ctx,
	     const mp_limb_t *k2,
	     size_t length,
	     const uint8_t *msg,
	     uint8_t *signature,
	     mp_limb_t *scratch);

mp_size_t
_eddsa_verify_itch (const struct ecc_curve *ecc);

int
_eddsa_verify (const struct ecc_curve *ecc,
	       const struct nettle_hash *H,
	       const uint8_t *pub,
	       const mp_limb_t *A,
	       void *ctx,
	       size_t length,
	       const uint8_t *msg,
	       const uint8_t *signature,
	       mp_limb_t *scratch);

mp_size_t
_eddsa_expand_key_itch (const struct ecc_curve *ecc);

void
_eddsa_expand_key (const struct ecc_curve *ecc,
		   const struct nettle_hash *H,
		   void *ctx,
		   const uint8_t *key,
		   uint8_t *pub,
		   uint8_t *k1,
		   mp_limb_t *k2,
		   mp_limb_t *scratch);

			   
#ifdef __cplusplus
}
#endif

#endif /* NETTLE_EDDSA_H */
