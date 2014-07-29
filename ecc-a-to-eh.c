/* ecc-a-to-eh.c

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

#include "ecc.h"
#include "ecc-internal.h"

mp_size_t
ecc_a_to_eh_itch (const struct ecc_curve *ecc)
{
  return ECC_A_TO_EH_ITCH (ecc->size);
}

/* Convert from affine coordinates to homogeneous coordinates on the
   corresponding Edwards curve. */
void
ecc_a_to_eh (const struct ecc_curve *ecc,
	     mp_limb_t *r, const mp_limb_t *p,
	     mp_limb_t *scratch)
{
#define xp p
#define yp (p + ecc->size)

#define up r
#define vp (r + ecc->size)
#define wp (r + 2*ecc->size)

  /* u = t x / y
     v = (x-1) / (x+1)

     or in homogeneous coordinates

     U = t x (x+1)
     V = (x-1) y
     W = (x+1) y
  */

  ecc_modp_mul (ecc, scratch, xp, yp);
  ecc_modp_add (ecc, wp, scratch, yp);
  ecc_modp_sub (ecc, vp, scratch, yp);

  ecc_modp_sqr (ecc, scratch, xp);
  ecc_modp_add (ecc, up, scratch, xp);
  ecc_modp_mul (ecc, scratch, up, ecc->edwards_root);
  mpn_copyi (up, scratch, ecc->size);
}
