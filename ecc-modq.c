/* ecc-modq.c

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

/* Arithmetic mod q, the group order. */

void
ecc_modq_add (const struct ecc_curve *ecc, mp_limb_t *rp,
	      const mp_limb_t *ap, const mp_limb_t *bp)
{
  mp_limb_t cy;
  cy = mpn_add_n (rp, ap, bp, ecc->size);
  cy = cnd_add_n (cy, rp, ecc->Bmodq, ecc->size);
  cy = cnd_add_n (cy, rp, ecc->Bmodq, ecc->size);
  assert (cy == 0);  
}

void
ecc_modq_mul (const struct ecc_curve *ecc, mp_limb_t *rp,
	      const mp_limb_t *ap, const mp_limb_t *bp)
{
  mpn_mul_n (rp, ap, bp, ecc->size);
  ecc->modq (ecc, rp);
}

void
ecc_modq_inv (const struct ecc_curve *ecc, mp_limb_t *rp, mp_limb_t *ap,
	      mp_limb_t *scratch)
{
  sec_modinv (rp, ap, ecc->size, ecc->q, ecc->qp1h, ecc->bit_size, scratch);
}
