/* rsa-pkcs1-sign-tr.c

   Creating timing resistant RSA signatures.

   Copyright (C) 2012 Nikos Mavrogiannopoulos

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

#if HAVE_CONFIG_H
# include "config.h"
#endif
#include "rsa.h"

#include "pkcs1.h"

/* Checks for any errors done in the RSA computation. That avoids
 * attacks which rely on faults on hardware, or even software MPI
 * implementation. */
static int
rsa_verify_res(const struct rsa_public_key *pub,
	       mpz_t s, mpz_t m)
{
  mpz_t t;
  int res;

  mpz_init(t);

  mpz_powm(t, s, pub->e, pub->n);

  res = !mpz_cmp(m, t);

  mpz_clear(t);
  return res;
}

/* Side-channel resistant version of rsa_pkcs1_sign() */
int
rsa_pkcs1_sign_tr(const struct rsa_public_key *pub,
  	          const struct rsa_private_key *key,
	          void *random_ctx, nettle_random_func *random,
	          size_t length, const uint8_t *digest_info,
   	          mpz_t s)
{
  mpz_t ri, m;
  int ret;

  mpz_init(m);

  if (pkcs1_rsa_digest_encode (m, key->size, length, digest_info))
    {
      mpz_init (ri);

      _rsa_blind (pub, random_ctx, random, m, ri);
      rsa_compute_root(key, s, m);

      if (rsa_verify_res(pub, s, m) == 0)
        {
          mpz_set_ui(s, 0);
          ret = 0;
        }
      else
        ret = 1;

      _rsa_unblind (pub, s, ri);
      mpz_clear (ri);
    }
  else
    {
      mpz_set_ui(s, 0);
      ret = 0;
    }    
  mpz_clear(m);
  return ret;
}
