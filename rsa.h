/* rsa.h
 *
 * The RSA publickey algorithm.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001 Niels Möller
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
 
#ifndef NETTLE_RSA_H_INCLUDED
#define NETTLE_RSA_H_INCLUDED

#include <inttypes.h>
#include <gmp.h>

#include "md5.h"
#include "sha.h"

/* For PKCS#1 to make sense, the size of the modulo, in octets, must
 * be at least 11 + the length of the DER-encoded Digest Info.
 *
 * And a DigestInfo is 34 octets for md5, and 35 octets for sha1. 46
 * octets is 368 bits, and as the upper 7 bits may be zero, the
 * smallest useful size of n is 361 bits. */

#define RSA_MINIMUM_N_OCTETS 46
#define RSA_MINIMUM_N_BITS 361

struct rsa_public_key
{
  /* Size of the modulo, in octets. This is also the size of all
   * signatures that are created or verified with this key. */
  unsigned size;
  
  /* Modulo */
  mpz_t n;

  /* Public exponent */
  mpz_t e;
};

struct rsa_private_key
{
  unsigned size;

  /* d is filled in by the key generation function; otherwise it's
   * completely unused. */
  mpz_t d;
  
  /* The two factors */
  mpz_t p; mpz_t q;

  /* d % (p-1), i.e. a e = 1 (mod (p-1)) */
  mpz_t a;

  /* d % (q-1), i.e. b e = 1 (mod (q-1)) */
  mpz_t b;

  /* modular inverse of q , i.e. c q = 1 (mod p) */
  mpz_t c;
};

/* Signing a message works as follows:
 *
 * Store the private key in a rsa_private_key struct.
 *
 * Call rsa_prepare_private_key. This initializes the size attribute
 * to the length of a signature.
 *
 * Initialize a hashing context, by callling
 *   md5_init
 *
 * Hash the message by calling
 *   md5_update
 *
 * Create the signature by calling
 *   rsa_md5_sign
 *
 * The signature is represented as a mpz_t bignum. This call also
 * resets the hashing context.
 *
 * When done with the key and signature, don't forget to call
 * mpz_clear.
 */

/* Calls mpz_init to initialize bignum storage. */
void
rsa_init_public_key(struct rsa_public_key *key);

/* Calls mpz_clear to deallocate bignum storage. */
void
rsa_clear_public_key(struct rsa_public_key *key);

int
rsa_prepare_public_key(struct rsa_public_key *key);

/* Calls mpz_init to initialize bignum storage. */
void
rsa_init_private_key(struct rsa_private_key *key);

/* Calls mpz_clear to deallocate bignum storage. */
void
rsa_clear_private_key(struct rsa_private_key *key);

int
rsa_prepare_private_key(struct rsa_private_key *key);


/* PKCS#1 style signatures */
void
rsa_md5_sign(struct rsa_private_key *key,
             struct md5_ctx *hash,
             mpz_t signature);


int
rsa_md5_verify(struct rsa_public_key *key,
               struct md5_ctx *hash,
	       const mpz_t signature);

void
rsa_sha1_sign(struct rsa_private_key *key,
              struct sha1_ctx *hash,
              mpz_t signature);

int
rsa_sha1_verify(struct rsa_public_key *key,
                struct sha1_ctx *hash,
		const mpz_t signature);

/* Compute x, the e:th root of m. Calling it with x == m is allowed. */
void
rsa_compute_root(struct rsa_private_key *key, mpz_t x, const mpz_t m);


/* Key generation */

/* Randomness function. This typedef doesn't really belong here, but
 * so far it's used only by the rsa key generator. */
typedef void (*nettle_random_func)(void *ctx,
				   unsigned length, uint8_t *dst);

/* Progress report function. */
typedef void (*nettle_progress_func)(void *ctx,
				     int c);

/* Note that the key structs must be initialized first. */
int
rsa_generate_keypair(struct rsa_public_key *pub,
		     struct rsa_private_key *key,

		     void *random_ctx, nettle_random_func random,
		     void *progress_ctx, nettle_progress_func progress,

		     /* Desired size of modulo, in bits */
		     unsigned n_size,
		     
		     /* Desired size of public exponent, in bits. If
		      * zero, the passed in value pub->e is used. */
		     unsigned e_size);


#define RSA_SIGN(key, algorithm, ctx, length, data, signature) ( \
  algorithm##_update(ctx, length, data), \
  rsa_##algorithm##_sign(key, ctx, signature) \
)

#define RSA_VERIFY(key, algorithm, ctx, length, data, signature) ( \
  algorithm##_update(ctx, length, data), \
  rsa_##algorithm##_verify(key, ctx, signature) \
)

#endif /* NETTLE_RSA_H_INCLUDED */
