/* dsa.h
 *
 * The DSA publickey algorithm.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2002 Niels Möller
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
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */
 
#ifndef NETTLE_DSA_H_INCLUDED
#define NETTLE_DSA_H_INCLUDED

#include <inttypes.h>
#include <gmp.h>

#include "sha.h"

/* For nettle_random_func */
#include "nettle-meta.h"


struct dsa_public_key
{  
  /* Modulo */
  mpz_t p;

  /* Group order */
  mpz_t q;

  /* Generator */
  mpz_t g;
  
  /* Public value */
  mpz_t y;
};

struct dsa_private_key
{
  /* Unlike an rsa public key, all the public information is needed,
   * in addition to the private information. */
  struct dsa_public_key pub;
  mpz_t x;
};

struct dsa_signature
{
  mpz_t r;
  mpz_t s;
};

/* Signing a message works as follows:
 *
 * Store the private key in a dsa_private_key struct.
 *
 * Initialize a hashing context, by callling
 *   sha1_init
 *
 * Hash the message by calling
 *   sha1_update
 *
 * Create the signature by calling
 *   dsa_sign
 *
 * The signature is represented as two mpz_t bignums. This call also
 * resets the hashing context.
 *
 * When done with the key and signature, don't forget to call
 * mpz_clear.
 */

/* Calls mpz_init to initialize bignum storage. */
void
dsa_public_key_init(struct dsa_public_key *key);

/* Calls mpz_clear to deallocate bignum storage. */
void
dsa_public_key_clear(struct dsa_public_key *key);


/* Calls mpz_init to initialize bignum storage. */
void
dsa_private_key_init(struct dsa_private_key *key);

/* Calls mpz_clear to deallocate bignum storage. */
void
dsa_private_key_clear(struct dsa_private_key *key);

/* Calls mpz_init to initialize bignum storage. */
void
dsa_signature_init(struct dsa_signature *signature);

/* Calls mpz_clear to deallocate bignum storage. */
void
dsa_signature_clear(struct dsa_signature *signature);


void
_dsa_hash(mpz_t x, struct sha1_ctx *hash);

void
dsa_sign(struct dsa_private_key *key,
	 void *random_ctx, nettle_random_func random,
	 struct sha1_ctx *hash,
	 struct dsa_signature *signature);


int
dsa_verify(struct dsa_public_key *key,
	   struct sha1_ctx *hash,
	   const struct dsa_signature *signature);

/* Key generation */

#if 0
/* Note that the key structs must be initialized first. */
int
dsa_generate_keypair(struct dsa_public_key *pub,
		     struct dsa_private_key *key,

		     void *random_ctx, nettle_random_func random,
		     void *progress_ctx, nettle_progress_func progress,

		     /* Desired size of modulo, in bits */
		     unsigned n_size,
		     
		     /* Desired size of public exponent, in bits. If
		      * zero, the passed in value pub->e is used. */
		     unsigned e_size);


#define DSA_SIGN(key, algorithm, ctx, length, data, signature) ( \
  algorithm##_update(ctx, length, data), \
  dsa_##algorithm##_sign(key, ctx, signature) \
)

#define DSA_VERIFY(key, algorithm, ctx, length, data, signature) ( \
  algorithm##_update(ctx, length, data), \
  dsa_##algorithm##_verify(key, ctx, signature) \
)
#endif

#endif /* NETTLE_DSA_H_INCLUDED */
