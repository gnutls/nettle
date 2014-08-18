/* curve25519-mul.c

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

#include <string.h>

#include "curve25519.h"

#include "ecc.h"
#include "ecc-internal.h"

/* Intended to be compatible with NaCl's crypto_scalarmult. NOTE: Not
   side-channel silent, due to the sqrt. */
int
curve25519_mul (uint8_t *q, const uint8_t *n, const uint8_t *p)
{
  uint8_t t[CURVE25519_SIZE];
  mp_size_t itch;
  mp_limb_t *scratch;
  const struct ecc_curve *ecc = &nettle_curve25519;

#define x scratch
#define y (scratch + ecc->size)
#define s (scratch + 3*ecc->size)
#define scratch_out (scratch + 4*ecc->size)
  
  itch = 5*ecc->size + ECC_MUL_A_EH_ITCH (ecc->size);
  scratch = gmp_alloc_limbs (itch);

  mpn_set_base256_le (x, ecc->size, p, CURVE25519_SIZE);

  /* First compute y coordinate, from

       y^2 = x^3 + b x^2 + x = (x^2 + bx + 1) x
  */
  ecc_modp_sqr (&nettle_curve25519, y, x);
  ecc_modp_addmul_1 (&nettle_curve25519, y, x, 0x76d06ULL);
  ecc_modp_add (ecc, s, y, ecc->unit);
  ecc_modp_mul (ecc, y, s, x);

  /* FIXME: Pass s as scratch space to ecc_25519_sqrt */
  if (!ecc_25519_sqrt (y, y))
    /* y-coordinate doesn't belong to base field F_p. FIXME: Implement
       case of y in F_{p^2}? */
    return 0;

  memcpy (t, n, sizeof(t));
  t[0] &= ~7;
  t[CURVE25519_SIZE-1] = (t[CURVE25519_SIZE-1] & 0x3f) | 0x40;

  mpn_set_base256_le (s, ecc->size, t, CURVE25519_SIZE);
  
  ecc_mul_a_eh (ecc, x, s, x, scratch_out);
  ecc_eh_to_a (ecc, 2, s, x, scratch_out);
  mpn_get_base256_le (q, CURVE25519_SIZE, s, ecc->size);

  gmp_free_limbs (scratch, itch);
  return 1;
}
