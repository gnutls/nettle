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
  /* Needs 2*ecc->size + scratch for ecc_modq_inv */
  return ECC_EH_TO_A_ITCH (ecc->size);
}

/* Convert from homogeneous coordinates on the Edwards curve to affine
   coordinates on the corresponding Montgomery curve. */
void
ecc_eh_to_a (const struct ecc_curve *ecc,
	     int op,
	     mp_limb_t *r, const mp_limb_t *p,
	     mp_limb_t *scratch)
{
#define izp scratch
#define sp (scratch + ecc->size)
#define tp (scratch + 2*ecc->size)

#define xp r
#define yp (r + ecc->size)
#define up p
#define vp (p + ecc->size)
#define wp (p + 2*ecc->size)
  /* x = (v+1)/(v-1), y = t x / u (with t = sqrt(b+2))

     In homogeneous coordinates,

     X = (W + V) U
     Y = t (W + V) W
     Z = (W - V) U
  */
  /* FIXME: Simplify for common case that only x-coordinate is wanted. */

  mp_limb_t cy;

  /* NOTE: For the infinity point, this subtraction gives zero (mod
     p), which isn't invertible. For curve25519, the desired output is
     x = 0, and we should be fine, since ecc_modp_inv returns 0
     in this case. */
  ecc_modp_sub (ecc, izp, wp, vp);
  ecc_modp_mul (ecc, izp + ecc->size, izp, up);
  /* Needs 3*size scratch */
  ecc_modp_inv (ecc, izp, izp + ecc->size, izp + 2*ecc->size);

  ecc_modp_add (ecc, sp, wp, vp);
  ecc_modp_mul (ecc, tp, sp, up);
  mpn_copyi (sp, tp, ecc->size); /* FIXME: Eliminate copy */
  ecc_modp_mul (ecc, tp, sp, izp);
  cy = mpn_sub_n (xp, tp, ecc->p, ecc->size);
  cnd_copy (cy, xp, tp, ecc->size);

  if (op)
    {
      /* Skip y coordinate */
      if (op > 1)
	{
	  /* Reduce modulo q. FIXME: Hardcoded for curve25519,
	     duplicates end of ecc_25519_modq. */
	  mp_limb_t cy;
	  unsigned shift;
	  assert (ecc->bit_size == 255);
	  shift = 252 - GMP_NUMB_BITS * (ecc->size - 1);
	  cy = mpn_submul_1 (xp, ecc->q, ecc->size,
			     xp[ecc->size-1] >> shift);
	  assert (cy < 2);
	  cnd_add_n (cy, xp, ecc->q, ecc->size);
	}
      return;
    }
  ecc_modp_add (ecc, sp, wp, vp); /* FIXME: Redundant. Also the (W +
				     V) Z^-1 multiplication is
				     redundant. */
  ecc_modp_mul (ecc, tp, sp, wp);
  mpn_copyi (sp, tp, ecc->size); /* FIXME: Eliminate copy */
  ecc_modp_mul (ecc, tp, sp, ecc->edwards_root);
  mpn_copyi (sp, tp, ecc->size); /* FIXME: Eliminate copy */
  ecc_modp_mul (ecc, tp, sp, izp);
  cy = mpn_sub_n (yp, tp, ecc->p, ecc->size);
  cnd_copy (cy, yp, tp, ecc->size);
}
