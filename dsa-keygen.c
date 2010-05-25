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
# include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>

#include "dsa.h"

#include "bignum.h"
#include "memxor.h"
#include "nettle-internal.h"


/* Valid sizes, according to FIPS 186-3 are (1024, 160), (2048. 224),
   (2048, 256), (3072, 256). Currenty, we use only q_bits of 160 or
   256. */
int
dsa_generate_keypair(struct dsa_public_key *pub,
		     struct dsa_private_key *key,
		     void *ctx, nettle_random_func random,
		     void *progress_ctx, nettle_progress_func progress,
		     unsigned p_bits, unsigned q_bits)
{
  mpz_t p0, p0q, i, r, pm1, y;
  unsigned p0_bits;
  unsigned a;

  switch (q_bits)
    {
    case 160:
      if (p_bits < 512)
	return 0;
      break;
    case 256:
      if (p_bits < 1024)
	return 0;
      break;
    default:
      return 0;
    }

  nettle_random_prime (pub->q, q_bits, ctx, random);

  mpz_init (p0);
  p0_bits = (p_bits + 3)/2;
  
  nettle_random_prime (p0, p0_bits, ctx, random);
  
  /* Generate p = 2 r q p0 + 1, such that 2^{n-1} < p < 2^n.
   *
   * We select r in the range i + 1 < r <= 2i, with i = floor (2^{n-2} / (p0 q). */

  mpz_init (p0q);
  mpz_mul (p0q, p0, pub->q);
  
  mpz_init_set_ui (i, 1);
  mpz_mul_2exp (i, i, p_bits-2);
  mpz_fdiv_q (i, i, p0q);

  mpz_init (r);
  mpz_init (pm1);
  mpz_init (y);

  for (;;)
    {
      uint8_t buf[1];

      /* Generate r in the range i + 1 <= r <= 2*i */
      nettle_mpz_random (r, ctx, random, i);
      mpz_add (r, r, i);
      mpz_add_ui (r, r, 1);

      /* Set p = 2*r*q*p0 + 1 */
      mpz_mul_2exp(r, r, 1);
      mpz_mul (pm1, r, p0q);
      mpz_add_ui (pub->p, pm1, 1);

      assert(mpz_sizeinbase(pub->p, 2) == p_bits);

      if (!mpz_probab_prime_p (pub->p, 1))
	continue;

      random(ctx, sizeof(buf), buf);

      a = buf[0] + 2;
      mpz_set_ui (y, a);

      /* Pocklington's theorem. Check
       *
       *  a^{p-1} = 1 (mod p)
       *  gcd(a^{p-1} / p0, p) = 1
       */

      mpz_powm (y, y, pm1, pub->p);
      if (mpz_cmp_ui (y, 1) != 0)
	continue;

      /* (p-1) / p0 = q * r */
      mpz_set_ui (y, a);
      mpz_powm (y, y, pub->q, pub->p);
      mpz_powm (y, y, r, pub->p);
      mpz_sub_ui (y, y, 1);
      mpz_gcd (y, y, pub->p);
      if (mpz_cmp_ui (y, 1) == 0)
	break;      
    }

  mpz_mul (r, r, p0);

  for (a = 2; ; a++)
    {
      mpz_set_ui (y, a);
      mpz_powm (pub->g, y, r, pub->p);
      if (mpz_cmp_ui (pub->g, 1) != 0)
	break;
    }

  mpz_init_set(r, pub->q);
  mpz_sub_ui(r, r, 2);
  nettle_mpz_random(key->x, ctx, random, r);

  mpz_add_ui(key->x, key->x, 1);

  mpz_powm(pub->y, pub->g, key->x, pub->p);
  
  mpz_clear (p0);
  mpz_clear (p0q);
  mpz_clear (r);
  mpz_clear (pm1);
  mpz_clear (y);

  return 1;
}
#if 0

/* FIXME: Update for fips186-3. p,q: A.1, g: A.2, x,y: B.1,
   Shawe-Taylor: C.6 */

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

  /* For NIS keysizes, we should have L = 512 + 64 * l */
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

	nettle_mpz_set_str_256_u(q, SHA1_DIGEST_SIZE, h1);

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
	/* Official maximum key size: L = 1024 => n = 6 */
	TMP_DECL(buffer, uint8_t, (6 + 1) * SHA1_DIGEST_SIZE);
	unsigned size = (n+1) * SHA1_DIGEST_SIZE;
	unsigned i, j;

	TMP_ALLOC(buffer, size);
	
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
	    nettle_mpz_set_str_256_u(p, size, buffer);

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
#endif
