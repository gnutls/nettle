/* ecc-25519.c

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

#include <assert.h>

#include "ecc.h"
#include "ecc-internal.h"

#define USE_REDC 0

#include "ecc-25519.h"

#if HAVE_NATIVE_ecc_25519_modp

#define ecc_25519_modp nettle_ecc_25519_modp
void
ecc_25519_modp (const struct ecc_curve *ecc, mp_limb_t *rp);
#else

#define PHIGH_BITS (GMP_NUMB_BITS * ECC_LIMB_SIZE - 255)

#if PHIGH_BITS == 0
#error Unsupported limb size */
#endif

static void
ecc_25519_modp(const struct ecc_curve *ecc UNUSED, mp_limb_t *rp)
{
  mp_limb_t hi, cy;

  cy = mpn_addmul_1 (rp, rp + ECC_LIMB_SIZE, ECC_LIMB_SIZE,
		     (mp_limb_t) 19 << PHIGH_BITS);
  hi = rp[ECC_LIMB_SIZE-1];
  cy = (cy << PHIGH_BITS) + (hi >> (GMP_NUMB_BITS - PHIGH_BITS));
  rp[ECC_LIMB_SIZE-1] = (hi & (GMP_NUMB_MASK >> PHIGH_BITS))
    + sec_add_1 (rp, rp, ECC_LIMB_SIZE - 1, 19 * cy);
}
#endif /* HAVE_NATIVE_ecc_25519_modp */

#define QHIGH_BITS (GMP_NUMB_BITS * ECC_LIMB_SIZE - 252)

#if QHIGH_BITS == 0
#error Unsupported limb size */
#endif

static void
ecc_25519_modq (const struct ecc_curve *ecc, mp_limb_t *rp)
{
  mp_size_t n;
  mp_limb_t cy;

  /* n is the offset where we add in the next term */
  for (n = ECC_LIMB_SIZE; n-- > 0;)
    {
      mp_limb_t cy;

      cy = mpn_submul_1 (rp + n,
			 ecc->Bmodq_shifted, ECC_LIMB_SIZE,
			 rp[n + ECC_LIMB_SIZE]);
      /* Top limb of mBmodq_shifted is zero, so we get cy == 0 or 1 */
      assert (cy < 2);
      cnd_add_n (cy, rp+n, ecc_q, ECC_LIMB_SIZE);
    }

  cy = mpn_submul_1 (rp, ecc_q, ECC_LIMB_SIZE,
		     rp[ECC_LIMB_SIZE-1] >> (GMP_NUMB_BITS - QHIGH_BITS));
  assert (cy < 2);
  cnd_add_n (cy, rp, ecc_q, ECC_LIMB_SIZE);
}

/* Needs 2*ecc->size limbs at rp, and 2*ecc->size additional limbs of
   scratch space. No overlap allowed. */
static void
ecc_modp_powm_2kp1 (const struct ecc_curve *ecc,
		    mp_limb_t *rp, const mp_limb_t *xp,
		    unsigned k, mp_limb_t *tp)
{
  if (k & 1)
    {
      ecc_modp_sqr (ecc, tp, xp);
      k--;
    }
  else
    {
      ecc_modp_sqr (ecc, rp, xp);
      ecc_modp_sqr (ecc, tp, rp);
      k -= 2;
    }
  while (k > 0)
    {
      ecc_modp_sqr (ecc, rp, tp);
      ecc_modp_sqr (ecc, tp, rp);
      k -= 2;
    }
  ecc_modp_mul (ecc, rp, tp, xp);
#undef t1
#undef t2
}

/* Compute x such that x^2 = a (mod p). Returns one on success, zero
   on failure. using the e == 2 special case of the Shanks-Tonelli
   algorithm (see http://www.math.vt.edu/people/brown/doc/sqrts.pdf,
   or Henri Cohen, Computational Algebraic Number Theory, 1.5.1.

   NOTE: Not side-channel silent. FIXME: Compute square root in the
   extended field if a isn't a square (mod p)? FIXME: Accept scratch
   space from caller (could allow scratch == rp). */
#if ECC_SQRT_E != 2
#error Broken curve25519 parameters
#endif
int
ecc_25519_sqrt(mp_limb_t *rp, const mp_limb_t *ap)
{
  mp_size_t itch;
  mp_limb_t *scratch;
  int res;
  const struct ecc_curve *ecc = &nettle_curve25519;

  itch = 7*ECC_LIMB_SIZE;
  scratch = gmp_alloc_limbs (itch);

#define t0 scratch
#define a7 (scratch + 2*ECC_LIMB_SIZE)
#define t1 (scratch + 3*ECC_LIMB_SIZE)
#define t2 (scratch + 5*ECC_LIMB_SIZE)
#define scratch_out (scratch + 3*ECC_LIMB_SIZE) /* overlap t1, t2 */

#define xp (scratch + ECC_LIMB_SIZE)
#define bp (scratch + 2*ECC_LIMB_SIZE)

  /* a^{2^252 - 3} = a^{(p-5)/8}, using the addition chain
     2^252 - 3
     = 1 + (2^252-4)
     = 1 + 4 (2^250-1)
     = 1 + 4 (2^125+1)(2^125-1)
     = 1 + 4 (2^125+1)(1+2(2^124-1))
     = 1 + 4 (2^125+1)(1+2(2^62+1)(2^62-1))
     = 1 + 4 (2^125+1)(1+2(2^62+1)(2^31+1)(2^31-1))
     = 1 + 4 (2^125+1)(1+2(2^62+1)(2^31+1)(7+8(2^28-1)))
     = 1 + 4 (2^125+1)(1+2(2^62+1)(2^31+1)(7+8(2^14+1)(2^14-1)))
     = 1 + 4 (2^125+1)(1+2(2^62+1)(2^31+1)(7+8(2^14+1)(2^7+1)(2^7-1)))
     = 1 + 4 (2^125+1)(1+2(2^62+1)(2^31+1)(7+8(2^14+1)(2^7+1)(1+2(2^6-1))))
     = 1 + 4 (2^125+1)(1+2(2^62+1)(2^31+1)(7+8(2^14+1)(2^7+1)(1+2(2^3+1)*7)))
  */ 
     
  ecc_modp_powm_2kp1 (ecc, t1, ap, 1, t2);  /* a^3 */
  ecc_modp_sqr (ecc, t0, t1);		    /* a^6 */
  ecc_modp_mul (ecc, a7, t0, ap);	    /* a^7 */
  ecc_modp_powm_2kp1 (ecc, t0, a7, 3, t1);  /* a^63 = a^{2^6-1} */
  ecc_modp_sqr (ecc, t1, t0);		    /* a^{2^7-2} */
  ecc_modp_mul (ecc, t0, t1, ap);	    /* a^{2^7-1} */
  ecc_modp_powm_2kp1 (ecc, t1, t0, 7, t2);  /* a^{2^14-1}*/
  ecc_modp_powm_2kp1 (ecc, t0, t1, 14, t2); /* a^{2^28-1} */
  ecc_modp_sqr (ecc, t1, t0);		    /* a^{2^29-2} */
  ecc_modp_sqr (ecc, t2, t1);		    /* a^{2^30-4} */
  ecc_modp_sqr (ecc, t1, t2);		    /* a^{2^31-8} */
  ecc_modp_mul (ecc, t0, t1, a7);	    /* a^{2^31-1} */
  ecc_modp_powm_2kp1 (ecc, t1, t0, 31, t2); /* a^{2^62-1} */  
  ecc_modp_powm_2kp1 (ecc, t0, t1, 62, t2); /* a^{2^124-1}*/
  ecc_modp_sqr (ecc, t1, t0);		    /* a^{2^125-2} */
  ecc_modp_mul (ecc, t0, t1, ap);	    /* a^{2^125-1} */
  ecc_modp_powm_2kp1 (ecc, t1, t0, 125, t2); /* a^{2^250-1} */
  ecc_modp_sqr (ecc, t0, t1);		    /* a^{2^251-2} */
  ecc_modp_sqr (ecc, t1, t0);		    /* a^{2^252-4} */
  ecc_modp_mul (ecc, t0, t1, ap);	    /* a^{2^252-3} */

  /* Compute candidate root x and fudgefactor b. */
  ecc_modp_mul (ecc, xp, t0, ap); /* a^{(p+3)/8 */
  ecc_modp_mul (ecc, bp, t0, xp); /* a^{(p-1)/4} */
  /* Check if b == 1 (mod p) */
  if (mpn_cmp (bp, ecc->p, ECC_LIMB_SIZE) >= 0)
    mpn_sub_n (bp, bp, ecc->p, ECC_LIMB_SIZE);
  if (mpn_cmp (bp, ecc->unit, ECC_LIMB_SIZE) == 0)
    {
      mpn_copyi (rp, xp, ECC_LIMB_SIZE);
      res = 1;
    }
  else
    {
      mpn_add_1 (bp, bp, ECC_LIMB_SIZE, 1);
      if (mpn_cmp (bp, ecc->p, ECC_LIMB_SIZE) == 0)
	{
	  ecc_modp_mul (&nettle_curve25519, bp, xp, ecc_sqrt_z);
	  mpn_copyi (rp, bp, ECC_LIMB_SIZE);
	  res = 1;
	}
      else
	res = 0;
    }
  gmp_free_limbs (scratch, itch);
  return res;
#undef t0
#undef t1
#undef t2
#undef a7
#undef xp
#undef bp
#undef scratch_out
}

const struct ecc_curve nettle_curve25519 =
{
  255,
  ECC_LIMB_SIZE,
  ECC_BMODP_SIZE,
  253,
  ECC_BMODQ_SIZE,
  0, /* No redc */
  0,
  ECC_PIPPENGER_K,
  ECC_PIPPENGER_C,

  ECC_MUL_A_EH_ITCH (ECC_LIMB_SIZE),
  ECC_MUL_G_EH_ITCH (ECC_LIMB_SIZE),
  ECC_EH_TO_A_ITCH (ECC_LIMB_SIZE),

  ecc_25519_modp,
  NULL,
  ecc_25519_modp,
  ecc_25519_modq,


  ecc_mul_a_eh,
  ecc_mul_g_eh,
  ecc_eh_to_a,

  ecc_p,
  ecc_d, /* Use the Edwards curve constant. */
  ecc_q,
  ecc_g,
  ecc_edwards,
  ecc_Bmodp,
  ecc_Bmodp_shifted,
  ecc_pp1h,
  ecc_redc_ppm1,
  ecc_unit,
  ecc_Bmodq,  
  ecc_mBmodq_shifted, /* Use q - 2^{252} instead. */ 
  ecc_qp1h,
  ecc_table
};
