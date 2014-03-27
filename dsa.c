/* dsa.c
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
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "dsa.h"

#include "bignum.h"

void
dsa_params_init (struct dsa_params *params)
{
  mpz_init(params->p);
  mpz_init(params->q);
  mpz_init(params->g);
}

void
dsa_params_clear (struct dsa_params *params)
{
  mpz_clear(params->p);
  mpz_clear(params->q);
  mpz_clear(params->g);
}

void
dsa_signature_init(struct dsa_signature *signature)
{
  mpz_init(signature->r);
  mpz_init(signature->s);
}

void
dsa_signature_clear(struct dsa_signature *signature)
{
  mpz_clear(signature->r);
  mpz_clear(signature->s);
}
