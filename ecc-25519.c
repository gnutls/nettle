/* ecc-25519

   Arithmetic and tables for curve25519,

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

#include "ecc-internal.h"

#define USE_REDC 0

#include "ecc-25519.h"

#define HIGH_BITS (GMP_NUMB_BITS * ECC_LIMB_SIZE - 255)

#if HIGH_BITS == 0
#error Unsupported limb size */
#endif

static void
ecc_25519_modp(const struct ecc_curve *ecc UNUSED, mp_limb_t *rp)
{
  mp_limb_t hi, cy;

  cy = mpn_addmul_1 (rp, rp + ECC_LIMB_SIZE, ECC_LIMB_SIZE,
		     (mp_limb_t) 19 << HIGH_BITS);
  hi = rp[ECC_LIMB_SIZE-1];
  cy = (cy << HIGH_BITS) + (hi >> (GMP_NUMB_BITS - HIGH_BITS));
  rp[ECC_LIMB_SIZE-1] = (hi & (GMP_NUMB_MASK >> HIGH_BITS))
    + sec_add_1 (rp, rp, ECC_LIMB_SIZE - 1, 19 * cy);
}

const struct ecc_curve nettle_curve25519 =
{
  255,
  ECC_LIMB_SIZE,
  ECC_BMODP_SIZE,
  ECC_BMODQ_SIZE,
  0, /* No redc */
  0,
  ECC_PIPPENGER_K,
  ECC_PIPPENGER_C,
  ecc_p,
  ecc_b,
  ecc_q,
  ecc_g,
  ecc_redc_g,
  ecc_edwards,
  ecc_25519_modp,
  NULL,
  ecc_25519_modp,
  NULL,
  ecc_Bmodp,
  ecc_Bmodp_shifted,
  ecc_pp1h,
  ecc_redc_ppm1,
  ecc_unit,
  ecc_Bmodq,
  ecc_Bmodq_shifted,
  ecc_qp1h,
  ecc_table
};
