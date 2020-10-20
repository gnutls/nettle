/* ecc-secp224r1.c

   Compile time constant (but machine dependent) tables.

   Copyright (C) 2013, 2014 Niels Möller

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

/* Development of Nettle's ECC support was funded by the .SE Internet Fund. */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "ecc.h"
#include "ecc-internal.h"

#if HAVE_NATIVE_ecc_secp224r1_modp

#define USE_REDC 0
#define ecc_secp224r1_modp _nettle_ecc_secp224r1_modp
void
ecc_secp224r1_modp (const struct ecc_modulo *m, mp_limb_t *rp);

#else
#define USE_REDC (ECC_REDC_SIZE != 0)
#define ecc_secp224r1_modp ecc_mod
#endif

#include "ecc-secp224r1.h"

#if ECC_REDC_SIZE < 0
# define ecc_secp224r1_redc ecc_pm1_redc
#elif ECC_REDC_SIZE == 0
# define ecc_secp224r1_redc NULL
#else
# error Configuration error
#endif

#define ECC_SECP224R1_INV_ITCH (6*ECC_LIMB_SIZE)

static void
ecc_secp224r1_inv (const struct ecc_modulo *p,
		   mp_limb_t *rp, const mp_limb_t *ap,
		   mp_limb_t *scratch)
{
#define a7 scratch
#define a31m1 (scratch + ECC_LIMB_SIZE)
#define a96m1 (scratch + 2*ECC_LIMB_SIZE)
  /* t0 overlaps a96m1. */
#define t0 (scratch + 2*ECC_LIMB_SIZE)
#define t1 (scratch + 4*ECC_LIMB_SIZE)
  /* t2 overlaps a7 and a31m1, and is used when those values are no
     longer needed. */
#define t2 scratch

  /* Addition chain for p - 2 = 2^{224} - 2^{96} - 1

       7           = 1 + 2 (2+1)                       2 S + 2 M
       2^{31} - 1  = 1 + 2 (2^{15} + 1)(1 + 2 (2^7 + 1) (1 + 2 (2^3+1) * 7))
                                                      28 S + 6 M
       2^{34} - 1  = 2^3 (2^{31} - 1) + 7              3 S +   M
       2^{65} - 1  = 2^{31}(2^{34} - 1) + 2^{31} - 1  31 S +   M
       2^{96} - 1  = 2^{31}(2^{65} - 1) + 2^{31} - 1  31 S +   M
       2^{127} - 1 = 2^{31}(2^{96} - 1) + 2^{31} - 1  31 S +   M

       2^{224} - 2^{96} - 1                           97 S +   M
                   = 2^{97}(2^{127} - 1) + 2^{96} - 1

       This addition chain needs 223 squarings and 13 multiplies.
  */
  ecc_mod_sqr (p, rp, ap);	        /* a^2 */
  ecc_mod_mul (p, t0, ap, rp);		/* a^3 */
  ecc_mod_sqr (p, rp, t0);		/* a^6 */
  ecc_mod_mul (p, a7, ap, rp);		/* a^{2^3-1} a7 */

  ecc_mod_pow_2kp1 (p, t0, a7, 3, rp);	/* a^{2^6 - 1} */
  ecc_mod_sqr (p, rp, t0);		/* a^{2^7 - 2} */
  ecc_mod_mul (p, t0, rp, ap);		/* a^{2^7 - 1} */
  ecc_mod_pow_2kp1 (p, rp, t0, 7, t1);	/* a^{2^14 - 1} */
  ecc_mod_sqr (p, t0, rp);		/* a^{2^15 - 2} */
  ecc_mod_mul (p, rp, t0, ap);		/* a^{2^15 - 1} */
  ecc_mod_pow_2kp1 (p, t0, rp, 15, t1);	/* a^{2^30 - 1} */
  ecc_mod_sqr (p, rp, t0);		/* a^{2^31 - 2} */
  ecc_mod_mul (p, a31m1, rp, ap);	/* a^{2^31 - 1} a7, a31m1 */

  ecc_mod_pow_2k_mul (p, rp, a31m1, 3, a7, t0); /* a^{2^34 - 1} a31m1 */
  ecc_mod_pow_2k_mul (p, t1, rp, 31, a31m1, t0); /* a^{2^65 - 1} a31m1 */
  ecc_mod_pow_2k_mul (p, a96m1, t1, 31, a31m1, rp); /* a^{2^96 - 1} a31m1, a96m1 */
  ecc_mod_pow_2k_mul (p, t1, a96m1, 31, a31m1, rp); /* a^{2^{127} - 1} a96m1 */
  ecc_mod_pow_2k_mul (p, rp, t1, 97, a96m1, t2); /* a^{2^{224} - 2^{96} - 1 */
}


const struct ecc_curve _nettle_secp_224r1 =
{
  {
    224,
    ECC_LIMB_SIZE,    
    ECC_BMODP_SIZE,
    -ECC_REDC_SIZE,
    ECC_SECP224R1_INV_ITCH,
    0,

    ecc_p,
    ecc_Bmodp,
    ecc_Bmodp_shifted,
    ecc_redc_ppm1,
    ecc_pp1h,

    ecc_secp224r1_modp,
    USE_REDC ? ecc_secp224r1_redc : ecc_secp224r1_modp,
    ecc_secp224r1_inv,
    NULL,
  },
  {
    224,
    ECC_LIMB_SIZE,    
    ECC_BMODQ_SIZE,
    0,
    ECC_MOD_INV_ITCH (ECC_LIMB_SIZE),
    0,

    ecc_q,
    ecc_Bmodq,
    ecc_Bmodq_shifted,
    NULL,
    ecc_qp1h,

    ecc_mod,
    ecc_mod,
    ecc_mod_inv,
    NULL,
  },
  
  USE_REDC,
  ECC_PIPPENGER_K,
  ECC_PIPPENGER_C,

  ECC_ADD_JJA_ITCH (ECC_LIMB_SIZE),
  ECC_ADD_JJJ_ITCH (ECC_LIMB_SIZE),
  ECC_DUP_JJ_ITCH (ECC_LIMB_SIZE),
  ECC_MUL_A_ITCH (ECC_LIMB_SIZE),
  ECC_MUL_G_ITCH (ECC_LIMB_SIZE),
  2*ECC_LIMB_SIZE + ECC_SECP224R1_INV_ITCH,

  ecc_add_jja,
  ecc_add_jjj,
  ecc_dup_jj,
  ecc_mul_a,
  ecc_mul_g,
  ecc_j_to_a,

  ecc_b,
  ecc_unit,
  ecc_table
};

const struct ecc_curve *nettle_get_secp_224r1(void)
{
  return &_nettle_secp_224r1;
}
