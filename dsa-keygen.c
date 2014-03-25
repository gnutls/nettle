/* dsa-keygen.c
 *
 * Generation of DSA keypairs
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2002, 2014 Niels Möller
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
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include "dsa.h"

#include "bignum.h"


/* Valid sizes, according to FIPS 186-3 are (1024, 160), (2048, 224),
   (2048, 256), (3072, 256). Currenty, we use only q_bits of 160 or
   256. */
void
dsa_generate_keypair (const struct dsa_params *params,
		      mpz_t pub, mpz_t key,

		      void *random_ctx, nettle_random_func *random)
{
  mpz_t r;

  mpz_init_set(r, params->q);
  mpz_sub_ui(r, r, 2);
  nettle_mpz_random(key, random_ctx, random, r);

  mpz_add_ui(key, key, 1);
  mpz_powm(pub, params->g, key, params->p);
  mpz_clear (r);
}
