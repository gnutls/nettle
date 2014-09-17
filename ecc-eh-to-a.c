/* ecc-eh-to-a.c

   Copyright (C) 2014 Niels Möller

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

#include <assert.h>

#include "ecc.h"
#include "ecc-internal.h"

mp_size_t
ecc_eh_to_a_itch (const struct ecc_curve *ecc)
{
  /* Needs ecc->size + scratch for ecc_modq_inv */
  return ECC_EH_TO_A_ITCH (ecc->size);
}

/* Convert from homogeneous coordinates on the Edwards curve to affine
   coordinates. */
void
ecc_eh_to_a (const struct ecc_curve *ecc,
	     int op,
	     mp_limb_t *r, const mp_limb_t *p,
	     mp_limb_t *scratch)
{
#define izp scratch
#define tp (scratch + ecc->size)


#define xp p
#define yp (p + ecc->size)
#define zp (p + 2*ecc->size)

  mp_limb_t cy;

  mpn_copyi (tp, zp, ecc->size);
  /* Needs 3*size scratch */
  ecc_modp_inv (ecc, izp, tp, tp + ecc->size);

  ecc_modp_mul (ecc, tp, xp, izp);
  cy = mpn_sub_n (r, tp, ecc->p, ecc->size);
  cnd_copy (cy, r, tp, ecc->size);

  if (op)
    {
      /* Skip y coordinate */
      if (op > 1)
	{
	  /* Reduce modulo q. FIXME: Hardcoded for curve25519,
	     duplicates end of ecc_25519_modq. FIXME: Is this needed
	     at all? Full reduction mod p is maybe sufficient. */
	  mp_limb_t cy;
	  unsigned shift;
	  assert (ecc->bit_size == 255);
	  shift = 252 - GMP_NUMB_BITS * (ecc->size - 1);
	  cy = mpn_submul_1 (r, ecc->q, ecc->size,
			     r[ecc->size-1] >> shift);
	  assert (cy < 2);
	  cnd_add_n (cy, r, ecc->q, ecc->size);
	}
      return;
    }
  ecc_modp_mul (ecc, tp, yp, izp);
  cy = mpn_sub_n (r + ecc->size, tp, ecc->p, ecc->size);
  cnd_copy (cy, r + ecc->size, tp, ecc->size);
}
