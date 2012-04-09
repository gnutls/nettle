/* rsa-decrypt-tr.c
 *
 * RSA decryption, using randomized RSA blinding to be more resistant
 * to timing attacks.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001, 2012 Niels Möller, Nikos Mavrogiannopoulos
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

#include "rsa.h"

#include "bignum.h"
#include "pkcs1.h"

/* Blinds the c, by computing c *= r^e (mod n), for a random r. Also
   returns the inverse (ri), for use by rsa_unblind. */
static void
rsa_blind (const struct rsa_public_key *pub,
	   void *random_ctx, nettle_random_func random,
	   mpz_t c, mpz_t ri)
{
  mpz_t r;

  mpz_init(r);

  /* c = c*(r^e)
   * ri = r^(-1)
   */
  do 
    {
      nettle_mpz_random(r, random_ctx, random, pub->n);
      /* invert r */
    }
  while (!mpz_invert (ri, r, pub->n));

  /* c = c*(r^e) mod n */
  mpz_powm(r, r, pub->e, pub->n);
  mpz_mul(c, c, r);
  mpz_fdiv_r(c, c, pub->n);

  mpz_clear(r);
}

/* c *= ri mod n */
static void
rsa_unblind (const struct rsa_public_key *pub, mpz_t c, const mpz_t ri)
{
  mpz_mul(c, c, ri);
  mpz_fdiv_r(c, c, pub->n);
}

int
rsa_decrypt_tr(const struct rsa_public_key *pub,
	       const struct rsa_private_key *key,
	       void *random_ctx, nettle_random_func random,	       
	       unsigned *length, uint8_t *message,
	       const mpz_t gibberish)
{
  mpz_t m, ri;
  int res;

  mpz_init_set(m, gibberish);
  mpz_init (ri);

  rsa_blind (pub, random_ctx, random, m, ri);
  rsa_compute_root(key, m, m);
  rsa_unblind (pub, m, ri);
  
  res = pkcs1_decrypt (key->size, m, length, message);
  mpz_clear(m);
  return res;
}
