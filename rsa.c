/* rsa.c
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#if HAVE_LIBGMP

#include "rsa.h"

#include "bignum.h"

/* FIXME: Perhaps we should split this into several functions, so that
 * one can link in the signature functions without also getting the
 * verify functions. */

void
rsa_init_public_key(struct rsa_public_key *key)
{
  mpz_init(key->n);
  mpz_init(key->e);

  /* Not really necessary, but it seems cleaner to initialize all the
   * storage. */
  key->size = 0;
}

void
rsa_clear_public_key(struct rsa_public_key *key)
{
  mpz_clear(key->n);
  mpz_clear(key->e);
}

/* Computes the size, in octets, of a size BITS modulo.
 * Returns 0 if the modulo is too small to be useful. */

static unsigned
rsa_check_size(unsigned bits)
{
  /* Round upwards */
  unsigned size = (bits + 7) / 8;

  /* For PKCS#1 to make sense, the size of the modulo, in octets, must
   * be at least 11 + the length of the DER-encoded Digest Info.
   *
   * And a DigestInfo is 34 octets for md5, and 35 octets for sha1.
   * 46 octets is 368 bits. */
  
  if (size < 46)
    return 0;

  return size;
}

int
rsa_prepare_public_key(struct rsa_public_key *key)
{
  /* FIXME: Add further sanity checks, like 0 < e < n. */
#if 0
  if ( (mpz_sgn(key->e) <= 0)
       || mpz_cmp(key->e, key->n) >= 0)
    return 0;
#endif
  
  key->size = rsa_check_size(mpz_sizeinbase(key->n, 2));
  
  return (key->size > 0);
}

void
rsa_init_private_key(struct rsa_private_key *key)
{
  mpz_init(key->p);
  mpz_init(key->q);
  mpz_init(key->a);
  mpz_init(key->b);
  mpz_init(key->c);

  /* Not really necessary, but it seems cleaner to initialize all the
   * storage. */
  key->size = 0;
}

void
rsa_clear_private_key(struct rsa_private_key *key)
{
  mpz_clear(key->p);
  mpz_clear(key->q);
  mpz_clear(key->a);
  mpz_clear(key->b);
  mpz_clear(key->c);
}

int
rsa_prepare_private_key(struct rsa_private_key *key)
{
  /* FIXME: Add further sanity checks. */

  /* The size of the product is the sum of the sizes of the factors. */
  key->size = rsa_check_size(mpz_sizeinbase(key->p, 2)
			     + mpz_sizeinbase(key->p, 2));

  return (key->size > 0);
}

/* Computing an rsa root. */
void
rsa_compute_root(struct rsa_private_key *key, mpz_t x, const mpz_t m)
{
  mpz_t xp; /* modulo p */
  mpz_t xq; /* modulo q */

  mpz_init(xp); mpz_init(xq);    

  /* Compute xq = m^d % q = (m%q)^b % q */
  mpz_fdiv_r(xq, m, key->q);
  mpz_powm(xq, xq, key->b, key->q);

  /* Compute xp = m^d % p = (m%p)^a % p */
  mpz_fdiv_r(xp, m, key->p);
  mpz_powm(xp, xp, key->a, key->p);

  /* Set xp' = (xp - xq) c % p. */
  mpz_sub(xp, xp, xq);
  mpz_mul(xp, xp, key->c);
  mpz_fdiv_r(xp, xp, key->p);

  /* Finally, compute x = xq + q xp'
   *
   * To prove that this works, note that
   *
   *   xp  = x + i p,
   *   xq  = x + j q,
   *   c q = 1 + k p
   *
   * for some integers i, j and k. Now, for some integer l,
   *
   *   xp' = (xp - xq) c + l p
   *       = (x + i p - (x + j q)) c + l p
   *       = (i p - j q) c + l p
   *       = (i c + l) p - j (c q)
   *       = (i c + l) p - j (1 + kp)
   *       = (i c + l - j k) p - j
   *
   * which shows that xp' = -j (mod p). We get
   *
   *   xq + q xp' = x + j q + (i c + l - j k) p q - j q
   *              = x + (i c + l - j k) p q
   *
   * so that
   *
   *   xq + q xp' = x (mod pq)
   *
   * We also get 0 <= xq + q xp' < p q, because
   *
   *   0 <= xq < q and 0 <= xp' < p.
   */
  mpz_mul(x, key->q, xp);
  mpz_add(x, x, xq);

  mpz_clear(xp); mpz_clear(xq);
}

#endif /* HAVE_LIBGMP */
