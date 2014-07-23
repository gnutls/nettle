/* curve25519-dh-test.c

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

#include "testutils.h"

/* Computes the x coordinate of s G, where g is a scalar, and G is the
   base point on the curve. If x is non-NULL, it gives the X
   coordinate of the point G, otherwise, G is the specified
   generator. */
static void
curve_25519 (const struct ecc_curve *ecc,
	     mp_limb_t *r, const mp_limb_t *s, const mp_limb_t *x)
{
  mp_limb_t *p;
  mp_limb_t *scratch;
  mp_size_t itch;

  if (x)
    die ("Not yet implemented.\n");

  itch = ECC_MUL_G_EH_ITCH (ecc->size);
  p = gmp_alloc_limbs (3*ecc->size);
  scratch = gmp_alloc_limbs (itch);
  ecc_mul_g_eh (ecc, p, s, scratch);
  ecc_eh_to_a (ecc, 2, r,  p, scratch);

  /* FIXME: Convert to little-endian here? */
  gmp_free_limbs (p, 3*ecc->size);
  gmp_free_limbs (scratch, itch);
}

static void
test_g (const char *sz, const char *pz)
{
  mpz_t S, R, X;
  const struct ecc_curve *ecc = &nettle_curve25519;

  mpz_init (S);
  mpz_init (R);
  mpz_init (X);

  mpz_set_str (S, sz, 16);
  mpz_set_str (R, pz, 16);

  ASSERT (mpz_size (S) == ecc->size);
  
  curve_25519 (ecc, mpz_limbs_write (X, ecc->size),
	       mpz_limbs_read (S), NULL);

  mpz_limbs_finish (X, ecc->size);
  if (mpz_cmp (X, R) != 0)
    {
      fprintf (stderr, "curve25519 failure:\ns = ");
      mpz_out_str (stderr, 16, S);
      fprintf (stderr, "\nX = ");
      mpz_out_str (stderr, 16, X);
      fprintf (stderr, " (bad)\nR = ");
      mpz_out_str (stderr, 16, R);
      fprintf (stderr, " (expected)\n");
      abort ();
    }

  mpz_clear (S);
  mpz_clear (R);
  mpz_clear (X);
}

void
test_main (void)
{
  /* From draft-josefsson-tls-curve25519-05. Different endianness for
     the P values, though. */
  test_g ("6A2CB91DA5FB77B12A99C0EB872F4CDF"
	  "4566B25172C1163C7DA518730A6D0770",
	  "6A4E9BAA8EA9A4EBF41A38260D3ABF0D"
	  "5AF73EB4DC7D8B7454A7308909F02085");

  test_g ("6BE088FF278B2F1CFDB6182629B13B6F"
	  "E60E80838B7FE1794B8A4A627E08AB58",
	  "4F2B886F147EFCAD4D67785BC843833F"
	  "3735E4ECC2615BD3B4C17D7B7DDB9EDE");
}
