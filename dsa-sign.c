/* dsa-sign.c
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#if WITH_PUBLIC_KEY

#include "dsa.h"

#include "bignum.h"

#include <stdlib.h>


void
dsa_sign_digest(const struct dsa_public_key *pub,
		const struct dsa_private_key *key,
		void *random_ctx, nettle_random_func random,
		const uint8_t *digest,
		struct dsa_signature *signature)
{
  mpz_t k;
  mpz_t h;
  mpz_t tmp;
  
  /* Select k, 0<k<q, randomly */
  mpz_init_set(tmp, pub->q);
  mpz_sub_ui(tmp, tmp, 1);

  mpz_init(k);
  nettle_mpz_random(k, random_ctx, random, tmp);
  mpz_add_ui(k, k, 1);

  /* Compute r = (g^k (mod p)) (mod q) */
  mpz_powm(tmp, pub->g, k, pub->p);
  mpz_fdiv_r(signature->r, tmp, pub->q);

  /* Compute hash */
  mpz_init(h);
  nettle_mpz_set_str_256_u(h, SHA1_DIGEST_SIZE, digest);

  /* Compute k^-1 (mod q) */
  if (!mpz_invert(k, k, pub->q))
    /* What do we do now? The key is invalid. */
    abort();

  /* Compute signature s = k^-1(h + xr) (mod q) */
  mpz_mul(tmp, signature->r, key->x);
  mpz_fdiv_r(tmp, tmp, pub->q);
  mpz_add(tmp, tmp, h);
  mpz_mul(tmp, tmp, k);
  mpz_fdiv_r(signature->s, tmp, pub->q);

  mpz_clear(k);
  mpz_clear(h);
  mpz_clear(tmp);
}

void
dsa_sign(const struct dsa_public_key *pub,
	 const struct dsa_private_key *key,
	 void *random_ctx, nettle_random_func random,
	 struct sha1_ctx *hash,
	 struct dsa_signature *signature)
{
  uint8_t digest[SHA1_DIGEST_SIZE];
  sha1_digest(hash, sizeof(digest), digest);

  dsa_sign_digest(pub, key, random_ctx, random,
		  digest, signature);
}

#endif /* WITH_PUBLIC_KEY */
