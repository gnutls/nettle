/* sexp2dsa.c
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

#if WITH_PUBLIC_KEY

#include "dsa.h"

#include "bignum.h"
#include "sexp.h"

#include <string.h>

#define GET(x, l, v) \
do { if (!nettle_mpz_set_sexp((x), (l), (v))) return 0; } while(0)

/* Iterator should point past the algorithm tag, e.g.
 *
 *   (public-key (dsa (p |xxxx|) ...)
 *                    ^ here
 */

int
dsa_keypair_from_sexp_alist(struct dsa_public_key *pub,
			    struct dsa_private_key *priv,
			    unsigned limit,
			    struct sexp_iterator *i)
{
  static const uint8_t *names[5]
    = { "p", "q", "g", "y", "x" };
  struct sexp_iterator values[5];
  unsigned nvalues = priv ? 5 : 4;
  
  if (!sexp_iterator_assoc(i, nvalues, names, values))
    return 0;

  if (priv)
    GET(priv->x, limit, &values[4]);
  
  GET(pub->p, limit, &values[0]);
  GET(pub->q, DSA_Q_BITS, &values[1]);
  GET(pub->g, limit, &values[2]);
  GET(pub->y, limit, &values[3]);
  
  return 1;
}

int
dsa_keypair_from_sexp(struct dsa_public_key *pub,
		      struct dsa_private_key *priv,
		      unsigned limit, 
		      unsigned length, const uint8_t *expr)
{
  struct sexp_iterator i;

  return sexp_iterator_first(&i, length, expr)
    && sexp_iterator_check_type(&i, priv ? "private-key" : "public-key")
    && sexp_iterator_check_type(&i, "dsa")
    && dsa_keypair_from_sexp_alist(pub, priv, limit, &i);
}

#endif /* WITH_PUBLIC_KEY */
