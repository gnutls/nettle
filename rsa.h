/* rsa.h
 *
 * The RSA publickey algorithm.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001, 2002 Niels Möller
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

/* For nettle_random_func */
#include "nettle-meta.h"


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

/* FIXME: For consistency, these functions ought to be renamed to
 * rsa_public_key_init, rsa_public_key_clear, rsa_private_key_init,
 * rsa_private_key_clear. Perhaps the prepare functions should be
 * renamed too. Do this for nettle-2.0? */
 
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
rsa_md5_sign(const struct rsa_private_key *key,
             struct md5_ctx *hash,
             mpz_t signature);


int
rsa_md5_verify(const struct rsa_public_key *key,
               struct md5_ctx *hash,
	       const mpz_t signature);

void
rsa_sha1_sign(const struct rsa_private_key *key,
              struct sha1_ctx *hash,
              mpz_t signature);

int
rsa_sha1_verify(const struct rsa_public_key *key,
                struct sha1_ctx *hash,
		const mpz_t signature);


/* RSA encryption, using PKCS#1 */
/* FIXME: These functions uses the v1.5 padding. What should the v2
 * (OAEP) functions be called? */

/* Returns 1 on success, 0 on failure, which happens if the
 * message is too long for the key. */
int
rsa_encrypt(const struct rsa_public_key *key,
	    /* For padding */
	    void *random_ctx, nettle_random_func random,
	    unsigned length, const uint8_t *cleartext,
	    mpz_t cipher);

/* Message must point to a buffer of size *LENGTH. KEY->size is enough
 * for all valid messages. On success, *LENGTH is updated to reflect
 * the actual length of the message. Returns 1 on success, 0 on
 * failure, which happens if decryption failed or if the message
 * didn't fit. */
int
rsa_decrypt(const struct rsa_private_key *key,
	    unsigned *length, uint8_t *cleartext,
	    const mpz_t ciphertext);


/* Compute x, the e:th root of m. Calling it with x == m is allowed. */
void
rsa_compute_root(const struct rsa_private_key *key,
		 mpz_t x, const mpz_t m);


/* Key generation */

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


/* Keys in sexp form. */

struct nettle_buffer;

/* Generates a public-key expression if PRIV is NULL .*/
int
rsa_keypair_to_sexp(struct nettle_buffer *buffer,
		    const struct rsa_public_key *pub,
		    const struct rsa_private_key *priv);

/* If PRIV is NULL, expect a public-key expression. If PUB is NULL,
 * expect a private key expression and ignore the parts not needed for
 * the public key. */
/* Keys must be initialized before calling this function, as usual. */
int
rsa_keypair_from_sexp(struct rsa_public_key *pub,
		      struct rsa_private_key *priv,
		      unsigned length, const uint8_t *expr);


/* OpenPGP format. Experimental interface, subject to change. */
int
rsa_keypair_to_openpgp(struct nettle_buffer *buffer,
		       const struct rsa_public_key *pub,
		       const struct rsa_private_key *priv,
		       /* A single user id. NUL-terminated utf8. */
		       const char userid);

#endif /* NETTLE_RSA_H_INCLUDED */
