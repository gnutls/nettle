/* sexp2rsa.h
 *
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

#if HAVE_LIBGMP

#include "rsa.h"

#include "bignum.h"
#include "sexp.h"

#include <string.h>

static int
get_value(mpz_t x, struct sexp_iterator *i)
{
  if (sexp_iterator_next(i)
      && i->type == SEXP_ATOM
      && !i->display)
    {
      nettle_mpz_set_str_256(x, i->atom_length, i->atom);
      return 1;
    }
  else
    return 0;
}

#define GET(x, v) do { if (!get_value(x, v)) return 0; } while(0)

int
rsa_keypair_from_sexp(struct rsa_public_key *pub,
		      struct rsa_private_key *priv,
		      unsigned length, const uint8_t *expr)
{
  struct sexp_iterator i;

  static const uint8_t *inner[8]
    = { "n", "e", "d", "p", "q", "a", "b", "c" };
  static const uint8_t *names[3]
    = { "rsa", "rsa-pkcs1", "rsa-pkcs1-sha1" };
  const uint8_t *outer;
  struct sexp_iterator values[8];
  unsigned nvalues;
  
  sexp_iterator_init(&i, length, expr);

  if (!sexp_iterator_next(&i))
    return 0;
  
  if (priv)
    {
      outer = "private-key";
      nvalues = 8;
    }
  else
    {
      outer = "public-key";
      nvalues = 2;
    }

  if (!sexp_iterator_check_type(&i, outer))
    return 0;

  if (!sexp_iterator_next(&i))
    return 0;

  if (!sexp_iterator_check_types(&i, 3, names))
    return 0;
  
  if (!sexp_iterator_assoc(&i, nvalues, inner, values))
    return 0;

  if (priv)
    {
      GET(priv->d, &values[2]);
      GET(priv->p, &values[3]);
      GET(priv->q, &values[4]);
      GET(priv->a, &values[5]);
      GET(priv->b, &values[6]);
      GET(priv->c, &values[7]);

      if (!rsa_prepare_private_key(priv))
	return 0;
    }

  if (pub)
    {
      GET(pub->n, &values[0]);
      GET(pub->e, &values[1]);

      if (!rsa_prepare_public_key(pub))
	return 0;
    }
    
  return 1;
}

#endif /* HAVE_LIBGMP */
