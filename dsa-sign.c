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

/* Returns a number x, almost uniformly random in the range
 * 0 <= x < n. */
static void
nettle_mpz_random(mpz_t x, const mpz_t n,
		  void *ctx, nettle_random_func random)
{
  /* FIXME: This leaves some bias, which may be bad for DSA. A better
   * way might to generate a random number of mpz_sizeinbase(n, 2)
   * bits, and loop until one smaller than n is found. */

  /* From Daniel Bleichenbacher (via coderpunks):
   *
   * There is still a theoretical attack possible with 8 extra bits.
   * But, the attack would need about 2^66 signatures 2^66 memory and
   * 2^66 time (if I remember that correctly). Compare that to DSA,
   * where the attack requires 2^22 signatures 2^40 memory and 2^64
   * time. And of course, the numbers above are not a real threat for
   * PGP. Using 16 extra bits (i.e. generating a 176 bit random number
   * and reducing it modulo q) will defeat even this theoretical
   * attack.
   * 
   * More generally log_2(q)/8 extra bits are enough to defeat my
   * attack. NIST also plans to update the standard.
   */

  /* Add a few bits extra, to decrease the bias from the final modulo
   * operation. */
  unsigned ndigits = (mpz_sizeinbase(n, 2) + 7) / 8 + 2;
  uint8_t *digits = alloca(ndigits);

  random(ctx, ndigits, digits);
  nettle_mpz_set_str_256(x, ndigits, digits);

  mpz_fdiv_r(x, x, n);
}

void
dsa_sign(struct dsa_private_key *key,
	 void *random_ctx, nettle_random_func random,
	 struct sha1_ctx *hash,
	 struct dsa_signature *signature)
{
  mpz_t k;
  mpz_t h;
  mpz_t tmp;
  
  /* Select k, 0<k<q, randomly */
  mpz_init_set(tmp, key->pub.q);
  mpz_sub_ui(tmp, tmp, 1);

  mpz_init(k);
  nettle_mpz_random(k, tmp, random_ctx, random);
  mpz_add_ui(k, k, 1);

  /* Compute r = (g^k (mod p)) (mod q) */
  mpz_powm(tmp, key->pub.g, k, key->pub.p);
  mpz_fdiv_r(signature->r, tmp, key->pub.q);

  /* Compute hash */
  mpz_init(h);
  _dsa_hash(h, hash);

  /* Compute k^-1 (mod q) */
  if (!mpz_invert(k, k, key->pub.q))
    /* What do we do now? The key is invalid. */
    abort();

  /* Compute signature s = k^-1(h + xr) (mod q) */
  mpz_mul(tmp, signature->r, key->x);
  mpz_fdiv_r(tmp, tmp, key->pub.q);
  mpz_add(tmp, tmp, h);
  mpz_mul(tmp, tmp, k);
  mpz_fdiv_r(signature->s, tmp, key->pub.q);

  mpz_clear(k);
  mpz_clear(h);
  mpz_clear(tmp);
}

#endif /* WITH_PUBLIC_KEY */
