/* dsa-compat-keygen.c
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

#include <assert.h>
#include <stdlib.h>

#include "dsa-compat.h"

#include "bignum.h"


/* Valid sizes, according to FIPS 186-3 are (1024, 160), (2048, 224),
   (2048, 256), (3072, 256). */
int
dsa_compat_generate_keypair(struct dsa_public_key *pub,
			    struct dsa_private_key *key,
			    void *random_ctx, nettle_random_func *random,
			    void *progress_ctx, nettle_progress_func *progress,
			    unsigned p_bits, unsigned q_bits)
{
  struct dsa_params *params;

  switch (q_bits)
    {
    case 160:
      if (p_bits < DSA_SHA1_MIN_P_BITS)
	return 0;
      break;
    case 224:
    case 256:
      if (p_bits < DSA_SHA256_MIN_P_BITS)
	return 0;
      break;
    default:
      return 0;
    }

  /* NOTE: Depends on identical layout! */
  params = (struct dsa_params *) pub;

  if (!dsa_generate_params (params,
			    random_ctx, random,
			    progress_ctx, progress,
			    p_bits, q_bits))
    return 0;

  dsa_generate_keypair_new (params, pub->y, key->x, random_ctx, random);

  return 1;
}
