/* ecc-modp.c

   Copyright (C) 2013 Niels Möller

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

#include "ecc-internal.h"

/* Routines for modp arithmetic. All values are ecc->size limbs, but
   not necessarily < p. */

void
ecc_modp_add (const struct ecc_curve *ecc, mp_limb_t *rp,
	      const mp_limb_t *ap, const mp_limb_t *bp)
{
  mp_limb_t cy;
  cy = mpn_add_n (rp, ap, bp, ecc->size);
  cy = cnd_add_n (cy, rp, ecc->Bmodp, ecc->size);
  cy = cnd_add_n (cy, rp, ecc->Bmodp, ecc->size);
  assert (cy == 0);  
}

void
ecc_modp_sub (const struct ecc_curve *ecc, mp_limb_t *rp,
	      const mp_limb_t *ap, const mp_limb_t *bp)
{
  mp_limb_t cy;
  cy = mpn_sub_n (rp, ap, bp, ecc->size);
  cy = cnd_sub_n (cy, rp, ecc->Bmodp, ecc->size);
  cy = cnd_sub_n (cy, rp, ecc->Bmodp, ecc->size);
  assert (cy == 0);  
}

void
ecc_modp_sub_1 (const struct ecc_curve *ecc, mp_limb_t *rp,
		const mp_limb_t *ap, mp_limb_t b)
{
  mp_size_t i;

  for (i = 0; i < ecc->size; i++)
    {
      mp_limb_t cy = ap[i] < b;
      rp[i] = ap[i] - b;
      b = cy;
    }
  b = cnd_sub_n (b, rp, ecc->Bmodp, ecc->size);
  assert (b == 0);    
}

void
ecc_modp_mul_1 (const struct ecc_curve *ecc, mp_limb_t *rp,
		const mp_limb_t *ap, mp_limb_t b)
{
  mp_limb_t hi;

  assert (b <= 0xffffffff);
  hi = mpn_mul_1 (rp, ap, ecc->size, b);
  hi = mpn_addmul_1 (rp, ecc->Bmodp, ecc->size, hi);
  assert (hi <= 1);
  hi = cnd_add_n (hi, rp, ecc->Bmodp, ecc->size);
  /* Sufficient if b < B^size / p */
  assert (hi == 0);
}

void
ecc_modp_addmul_1 (const struct ecc_curve *ecc, mp_limb_t *rp,
		   const mp_limb_t *ap, mp_limb_t b)
{
  mp_limb_t hi;

  assert (b <= 0xffffffff);
  hi = mpn_addmul_1 (rp, ap, ecc->size, b);
  hi = mpn_addmul_1 (rp, ecc->Bmodp, ecc->size, hi);
  assert (hi <= 1);
  hi = cnd_add_n (hi, rp, ecc->Bmodp, ecc->size);
  /* Sufficient roughly if b < B^size / p */
  assert (hi == 0);
}
  
void
ecc_modp_submul_1 (const struct ecc_curve *ecc, mp_limb_t *rp,
		   const mp_limb_t *ap, mp_limb_t b)
{
  mp_limb_t hi;

  assert (b <= 0xffffffff);
  hi = mpn_submul_1 (rp, ap, ecc->size, b);
  hi = mpn_submul_1 (rp, ecc->Bmodp, ecc->size, hi);
  assert (hi <= 1);
  hi = cnd_sub_n (hi, rp, ecc->Bmodp, ecc->size);
  /* Sufficient roughly if b < B^size / p */
  assert (hi == 0);
}

/* NOTE: mul and sqr needs 2*ecc->size limbs at rp */
void
ecc_modp_mul (const struct ecc_curve *ecc, mp_limb_t *rp,
	      const mp_limb_t *ap, const mp_limb_t *bp)
{
  mpn_mul_n (rp, ap, bp, ecc->size);
  ecc->reduce (ecc, rp);
}

void
ecc_modp_sqr (const struct ecc_curve *ecc, mp_limb_t *rp,
	      const mp_limb_t *ap)
{
  mpn_sqr (rp, ap, ecc->size);
  ecc->reduce (ecc, rp);
}

void
ecc_modp_inv (const struct ecc_curve *ecc, mp_limb_t *rp, mp_limb_t *ap,
	      mp_limb_t *scratch)
{
  sec_modinv (rp, ap, ecc->size, ecc->p, ecc->pp1h, ecc->bit_size, scratch);
}

