/* ecc-add-ehh.c

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
ecc_add_ehh_itch (const struct ecc_curve *ecc)
{
  return ECC_ADD_EHH_ITCH (ecc->size);
}

/* Add two points on an Edwards curve, in homogeneous coordinates */
void
ecc_add_ehh (const struct ecc_curve *ecc,
	     mp_limb_t *r, const mp_limb_t *p, const mp_limb_t *q,
	     mp_limb_t *scratch)
{
#define x1 p
#define y1 (p + ecc->size)
#define z1 (p + 2*ecc->size)

#define x2 q
#define y2 (q + ecc->size)
#define z2 (q + 2*ecc->size)

#define x3 r
#define y3 (r + ecc->size)
#define z3 (r + 2*ecc->size)

  /* Formulas (from djb,
     http://www.hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#doubling-dbl-2007-bl):

     Computation	Operation	Live variables

     A = z1*z2		mul		A
     B = A^2		sqr		A, B
     C = x1*x2		mul		A, B, C
     D = y1*y2		mul		A, B, C, D
     E = b*C*D		2 mul		A, B, C, D, E
     F = B - E				A, B, C, D, E, F
     G = B + E     			A, C, D, F, G
     x3 = A*F*[(x1+y1)(x2+y2) - C - D] 3 mul	A, C, D, G
     y3 = A*G*(D-C)	2 mul		F, G
     z3 = F*G		mul
  */
#define A scratch
#define B (scratch + ecc->size)
#define C (scratch + 2*ecc->size)
#define D (scratch + 3*ecc->size)
#define E (scratch + 4*ecc->size) 
#define F (scratch + 5*ecc->size)
#define G (scratch + 6*ecc->size)
#define T (scratch + 7*ecc->size)
 
  ecc_modp_mul (ecc, A, z1, z2);
  ecc_modp_sqr (ecc, B, A);
  ecc_modp_mul (ecc, C, x1, x2);
  ecc_modp_mul (ecc, D, y1, y2);
  ecc_modp_mul (ecc, T, C, D);
  ecc_modp_mul (ecc, E, T, ecc->b);
  ecc_modp_sub (ecc, F, B, E);
  ecc_modp_add (ecc, G, B, E);

  /* x3 */
  ecc_modp_add (ecc, B, x1, y1);
  ecc_modp_add (ecc, E, x2, y2);
  ecc_modp_mul (ecc, T, B, E);
  ecc_modp_sub (ecc, T, T, C);
  ecc_modp_sub (ecc, x3, T, D);
  ecc_modp_mul (ecc, T, x3, A);
  ecc_modp_mul (ecc, x3, T, F);

  /* y3 */
  ecc_modp_sub (ecc, C, D, C);
  ecc_modp_mul (ecc, T, A, C);
  ecc_modp_mul (ecc, y3, T, G);

  /* z3 */
  ecc_modp_mul (ecc, T, F, G);
  mpn_copyi (z3, T, ecc->size);
}
