/* dsa-keygen.c
 *
 * Generation of DSA keypairs
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
#include "memxor.h"

#include <stdlib.h>

/* The (slow) NIST method of generating DSA primes. Algorithm 4.56 of
 * Handbook of Applied Cryptography. */

#define SEED_LENGTH SHA1_DIGEST_SIZE
#define SEED_BITS (SEED_LENGTH * 8)

static void
hash(mpz_t x, uint8_t *digest)
{
  mpz_t t;
  uint8_t data[SEED_LENGTH];
  struct sha1_ctx ctx;
  
  mpz_init_set(t, x);
  mpz_fdiv_r_2exp(t, t, SEED_BITS);
  
  nettle_mpz_get_str_256(SEED_LENGTH, data, t);
  mpz_clear(t);

  sha1_init(&ctx);
  sha1_update(&ctx, SEED_LENGTH, data);
  sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);
}

static void
dsa_nist_gen(mpz_t p, mpz_t q,
	     void *random_ctx, nettle_random_func random,
	     void *progress_ctx, nettle_progress_func progress,
	     unsigned L)
{
  unsigned n;
  unsigned b;
  mpz_t s;
  mpz_t t;
  mpz_t c;

  /* For NIS keysizes, we should have L = 512 + 65 * l */
  n = (L-1) / 160; b = (L-1) % 160;

  mpz_init(s);
  mpz_init(t);
  mpz_init(c);
  
  for (;;)
    {
      { /* Generate q */
	uint8_t h1[SHA1_DIGEST_SIZE];
	uint8_t h2[SHA1_DIGEST_SIZE];

	if (progress)
	  progress(progress_ctx, '.');
	
	nettle_mpz_random_size(s, random_ctx, random, SEED_BITS);
	
	hash(s, h1);
	
	mpz_set(t, s);
	mpz_add_ui(t, t, 1);
	
	hash(t, h2);
	
	memxor(h1, h2, SHA1_DIGEST_SIZE);
	
	h1[0] |= 0x80;
	h1[SHA1_DIGEST_SIZE - 1] |= 1;

	nettle_mpz_set_str_256(q, SHA1_DIGEST_SIZE, h1);

	/* The spec says that we should use 18 iterations of
	 * miller-rabin. For performance, we want to do some trial
	 * divisions first. The curent version of mpz_probab_prime_p
	 * does exactly that. */
	if (!mpz_probab_prime_p(q, 18))
	  /* Try new seed. */
	  continue;
      }
      /* q is a prime, with overwhelming probability. */

      if (progress)
	progress(progress_ctx, '\n');
      
      {
	unsigned size = (n+1) * SHA1_DIGEST_SIZE;
	uint8_t *buffer = alloca(size);
	unsigned i, j;
	
	for (i = 0, j = 2; i<4096; i++, j+= n+1)
	  {
	    unsigned k;

	    if (progress)
	      progress(progress_ctx, ',');
	    for (k = 0; k<=n ; k++)
	      {
		mpz_set(t, s);
		mpz_add_ui(t, t, j + k);
		hash(t, buffer + ( (n-k) * SHA1_DIGEST_SIZE));
	      }
	    nettle_mpz_set_str_256(p, size, buffer);

	    mpz_fdiv_r_2exp(p, p, L);
	    mpz_setbit(p, L-1);

	    mpz_set(t, q);
	    mpz_mul_2exp(t, t, 1);

	    mpz_fdiv_r(c, p, t);

	    mpz_sub_ui(c, c, 1);

	    mpz_sub(p, p, c);

	    if (mpz_probab_prime_p(p, 5))
	      {
		/* Done! */
		if (progress)
		  progress(progress_ctx, '\n');
		
		mpz_clear(s);
		mpz_clear(t);
		mpz_clear(c);

		return;
	      }
	  }
	if (progress)
	  progress(progress_ctx, '+');
      }
    }
}

static void
dsa_find_generator(mpz_t g,
		   void *random_ctx, nettle_random_func random,
		   void *progress_ctx, nettle_progress_func progress,
		   const mpz_t p, const mpz_t q)
{
  mpz_t e;
  mpz_t n;
  
  /* e = (p-1)/q */
  mpz_init_set(e, p);
  mpz_sub_ui(e, e, 1);
  mpz_divexact(e, e, q);

  /* n = p-2 = |2, 3, ... p-1| */
  mpz_init_set(n, p);
  mpz_sub_ui(n, n, 2);

  for (;;)
    {
      nettle_mpz_random(g, random_ctx, random, n);
      mpz_add_ui(g, g, 2);

      if (progress)
	progress(progress_ctx, 'g');
      mpz_powm(g, g, e, p);
      
      if (mpz_cmp_ui(g, 1))
	{
	  /* g != 1. Finished. */
	  if (progress)
	    progress(progress_ctx, '\n');

	  mpz_clear(e);
	  mpz_clear(n);

	  return;
	}
    }
}

int
dsa_generate_keypair(struct dsa_public_key *pub,
		     struct dsa_private_key *key,
		     void *random_ctx, nettle_random_func random,
		     void *progress_ctx, nettle_progress_func progress,
		     /* Size of key, in bits.
		      * Use size = 512 + 64 * l for the official
		      * NIS key sizes. */
		     unsigned bits)
{
  mpz_t t;
  
  if (bits < DSA_MIN_P_BITS)
    return 0;
  
  dsa_nist_gen(pub->p, pub->q,
	       random_ctx, random,
	       progress_ctx, progress,
	       bits);
  
  dsa_find_generator(pub->g,
		     random_ctx, random,
		     progress_ctx, progress,
		     pub->p, pub->q);

  mpz_init_set(t, pub->q);
  mpz_sub_ui(t, t, 2);
  nettle_mpz_random(key->x, random_ctx, random, t);

  mpz_add_ui(key->x, key->x, 1);

  mpz_powm(pub->y, pub->g, key->x, pub->p);

  mpz_clear(t);

  return 1;
}

#endif /* WITH_PUBLIC_KEY */
