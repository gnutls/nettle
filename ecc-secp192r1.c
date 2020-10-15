/* ecc-secp192r1.c

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

#include <assert.h>

/* FIXME: Remove ecc.h include, once prototypes of more internal
   functions are moved to ecc-internal.h */
#include "ecc.h"
#include "ecc-internal.h"

#define USE_REDC 0

#include "ecc-secp192r1.h"

#if HAVE_NATIVE_ecc_secp192r1_modp

#define ecc_secp192r1_modp _nettle_ecc_secp192r1_modp
void
ecc_secp192r1_modp (const struct ecc_modulo *m, mp_limb_t *rp);

/* Use that p = 2^{192} - 2^64 - 1, to eliminate 128 bits at a time. */

#elif GMP_NUMB_BITS == 32
/* p is 6 limbs, p = B^6 - B^2 - 1 */
static void
ecc_secp192r1_modp (const struct ecc_modulo *m UNUSED, mp_limb_t *rp)
{
  mp_limb_t cy;

  /* Reduce from 12 to 9 limbs (top limb small)*/
  cy = mpn_add_n (rp + 2, rp + 2, rp + 8, 4);
  cy = sec_add_1 (rp + 6, rp + 6, 2, cy);
  cy += mpn_add_n (rp + 4, rp + 4, rp + 8, 4);
  assert (cy <= 2);

  rp[8] = cy;

  /* Reduce from 9 to 6 limbs */
  cy = mpn_add_n (rp, rp, rp + 6, 3);
  cy = sec_add_1 (rp + 3, rp + 3, 2, cy);
  cy += mpn_add_n (rp + 2, rp + 2, rp + 6, 3);
  cy = sec_add_1 (rp + 5, rp + 5, 1, cy);
  
  assert (cy <= 1);
  cy = cnd_add_n (cy, rp, ecc_Bmodp, 6);
  assert (cy == 0);  
}
#elif GMP_NUMB_BITS == 64
/* p is 3 limbs, p = B^3 - B - 1 */
static void
ecc_secp192r1_modp (const struct ecc_modulo *m UNUSED, mp_limb_t *rp)
{
  mp_limb_t cy;

  /* Reduce from 6 to 5 limbs (top limb small)*/
  cy = mpn_add_n (rp + 1, rp + 1, rp + 4, 2);
  cy = sec_add_1 (rp + 3, rp + 3, 1, cy);
  cy += mpn_add_n (rp + 2, rp + 2, rp + 4, 2);
  assert (cy <= 2);

  rp[4] = cy;

  /* Reduce from 5 to 4 limbs (high limb small) */
  cy = mpn_add_n (rp, rp, rp + 3, 2);
  cy = sec_add_1 (rp + 2, rp + 2, 1, cy);
  cy += mpn_add_n (rp + 1, rp + 1, rp + 3, 2);

  assert (cy <= 1);
  cy = cnd_add_n (cy, rp, ecc_Bmodp, 3);
  assert (cy == 0);  
}
  
#else
#define ecc_secp192r1_modp ecc_mod
#endif

#define ECC_SECP192R1_INV_ITCH (4*ECC_LIMB_SIZE)

static void ecc_secp192r1_inv (const struct ecc_modulo *p,
			       mp_limb_t *rp, const mp_limb_t *ap,
			       mp_limb_t *scratch)
{
#define t0 scratch
#define t1 (scratch + 2*ECC_LIMB_SIZE)
  /* Overlap means that using a62m1 as destination (or scratch)
     clobbers t0, and using t2 as destination clobbers t1. The tricky
     operations are the powering operations while a62m1 is live. They
     can use only rp and t1 as scratch and destination, and hence the
     input must be stored at t2.
  */
#define a62m1 scratch
#define t2 (scratch + ECC_LIMB_SIZE) /* Never used as scratch */

  /* Addition chain

       p - 2 = 2^{192} - 2^{64} - 3
             = 1 + 2^{192} - 2^{64} - 4
	     = 1 + 2^2 (2^{190} - 2^{62} - 1)
	     = 1 + 2^2 (2^{62} - 1 + 2^{190} - 2^63)
	     = 1 + 2^2 (2^{62} - 1 + 2^{63}(2^{127} - 1))
	     = 1 + 2^2 (2^{62} - 1 + 2^{63}(1 + 2 (2^{126} - 1)))
	     = 1 + 2^2 (2^{62} - 1 + 2^{63}(1 + 2 (2^{63} + 1)(2^{63} - 1)))
	     = 1 + 2^2 (2^{62} - 1 + 2^{63}(1 + 2 (2^{63} + 1)(1 + 2(2^{62} - 1))))

       2^{62} - 1 = (2^{31}+1)(2^{31}-1)
		  = (2^{31}+1)(1 + 2(1 + 2^{30} - 1))
		  = (2^{31}+1)(1 + 2(1 + (2^{15}+1)(2^15-1))
		  = (2^{31}+1)(1 + 2(1 + (2^{15}+1)(1 + 2(1 + (2^{14}-1)))
		  = (2^{31}+1)(1 + 2(1 + (2^{15}+1)(1 + 2(1 + (2^7+1)(2^7-1))))
		  = (2^{31}+1)(1 + 2(1 + (2^{15}+1)(1 + 2(1 + (2^7+1)(1+2(2^3+1)(2^3-1)))))
		  = (2^{31}+1)(1 + 2(1 + (2^{15}+1)(1 + 2(1 + (2^7+1)(1+2(2^3+1)(1 + 2 (2+1))))))

  */

  ecc_mod_sqr (p, rp, ap);	        /* a^2 */
  ecc_mod_mul (p, t0, ap, rp);		/* a^3 */
  ecc_mod_sqr (p, rp, t0);		/* a^6 */
  ecc_mod_mul (p, t0, ap, rp);		/* a^{2^3-1} */
  ecc_mod_pow_2kp1 (p, rp, t0, 3, t1);	/* a^{2^6-1} */
  ecc_mod_sqr (p, t0, rp);		/* a^{2^7-2} */
  ecc_mod_mul (p, rp, ap, t0);		/* a^{2^7-1} */
  ecc_mod_pow_2kp1 (p, t0, rp, 7, t1);	/* a^{2^14-1} */
  ecc_mod_sqr (p, rp, t0);		/* a^{2^15-2} */
  ecc_mod_mul (p, t0, ap, rp);		/* a^{2^15-1} */
  ecc_mod_pow_2kp1 (p, rp, t0, 15, t1);	/* a^{2^30-1} */
  ecc_mod_sqr (p, t0, rp);		/* a^{2^31-2} */
  ecc_mod_mul (p, rp, ap, t0);		/* a^{2^31-1} */
  ecc_mod_pow_2kp1 (p, a62m1, rp, 31, t1);	/* a^{2^62-1} Overlaps t0 */

  ecc_mod_sqr (p, rp, a62m1);		/* a^{2^63-2} */
  ecc_mod_mul (p, t2, ap, rp);		/* a^{2^63-1} Clobbers t1 */
  ecc_mod_pow_2kp1 (p, t1, t2, 63, rp);	/* a^{2^126-1} */
  ecc_mod_sqr (p, rp, t1);		/* a^{2^127-2} */
  ecc_mod_mul (p, t2, rp, ap);		/* a^{2^127-1} Clobbers t1 */
  ecc_mod_pow_2k_mul (p, rp, t2, 63, a62m1, t1); /* a^{2^190 - 2^62 - 1} */
  ecc_mod_sqr (p, t0, rp);		/* a^{2^191 - 2^63 - 2} */
  ecc_mod_sqr (p, t1, t0);		/* a^{2^192 - 2^64 - 4} */
  ecc_mod_mul (p, rp, t1, ap);
}

const struct ecc_curve _nettle_secp_192r1 =
{
  {
    192,
    ECC_LIMB_SIZE,
    ECC_BMODP_SIZE,
    ECC_REDC_SIZE,
    ECC_SECP192R1_INV_ITCH,
    0,

    ecc_p,
    ecc_Bmodp,
    ecc_Bmodp_shifted,    
    ecc_redc_ppm1,
    ecc_pp1h,

    ecc_secp192r1_modp,
    ecc_secp192r1_modp,
    ecc_secp192r1_inv,
    NULL,
  },
  {
    192,
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
  2*ECC_LIMB_SIZE + ECC_SECP192R1_INV_ITCH,

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

const struct ecc_curve *nettle_get_secp_192r1(void)
{
  return &_nettle_secp_192r1;
}
