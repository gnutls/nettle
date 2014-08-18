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

#include "curve25519.h"

static
int curve25519_sqrt (const struct ecc_curve *ecc,
		     mp_limb_t *rp, const mp_limb_t *ap)
{
  /* p-1 = 2^{255} - 20 = 4 (2^{253] - 5), s = 2^{253} - 5, e = 2 */

  mpz_t g;
  mpz_t sm1h; /* (s-1)/2 */
  mpz_t x;
  mpz_t a;
  mpz_t p;
  mpz_t b;
  mpz_t t;
  int success;

  mpz_init_set_str (g,
		    "2b8324804fc1df0b2b4d00993dfbd7a7"
		    "2f431806ad2fe478c4ee1b274a0ea0b0", 16);
  mpz_init_set_str (sm1h,
		    "fffffffffffffffffffffffffffffff"
		    "fffffffffffffffffffffffffffffffd", 16);

  mpz_init (x);
  mpz_init (b);
  mpz_init (t);
  mpz_roinit_n (p, ecc->p, ecc->size);
  mpz_roinit_n (a, ap, ecc->size);

  mpz_powm (x, a, sm1h, p);
  mpz_mul (b, x, x); /* s-1 */
  mpz_mul (b, b, a); /* s */
  mpz_mod (b, b, p);
  mpz_mul (x, x, a); /* (s+1)/2 */
  mpz_mod (x, x, p);

  if (mpz_cmp_ui (b, 1) != 0)
    {
      mpz_t t;
      unsigned m, e;
      mpz_init (t);
      e = 2;
      do
	{
	  mpz_set (t, b);
	  m = 0;
	  do
	    {	  
	      m++;
	      if (m == e)
		{
		  mpz_clear (t);
		  success = 0;
		  goto done;
		}
	      mpz_mul (t, t, t);
	      mpz_mod (t, t, p);
	    }
	  while (mpz_cmp_ui (t, 1) != 0);
	  ASSERT (m < e);
	  mpz_set_ui (t, 1UL << (e - m - 1));
	  mpz_powm (t, g, t, p);
	  mpz_mul (x, x, t);
	  mpz_mod (x, x, p);
	  mpz_mul (g, t, t);
	  mpz_mod (g, g, p);
	  mpz_mul (b, b, g);
	  mpz_mod (b, b, p);
	  e = m-1;
	}
      while (mpz_cmp_ui (b, 1) != 0);

      mpz_clear (t);
    }
  mpz_limbs_copy (rp, x, ecc->size);
  success = 1;
 done:
  mpz_clear (g);
  mpz_clear (sm1h);
  mpz_clear (x);
  mpz_clear (b);
  mpz_clear (t);
  return success;
}

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

  p = gmp_alloc_limbs (3*ecc->size);
  
  if (x)
    {
      itch = ECC_MUL_A_EH_ITCH (ecc->size);
      scratch = gmp_alloc_limbs (itch);
      mpn_copyi (p, x, ecc->size);
      /* y^2 = x^3 + b x^2 + x = (x^2 + bx + 1) x = ((x+b)x + 1) x */
      ecc_modp_sqr (ecc, scratch, x);
      ecc_modp_addmul_1 (ecc, scratch, x, 0x76d06ULL);
      ecc_modp_add (ecc, scratch, scratch, ecc->unit);
      ecc_modp_mul (ecc, scratch + ecc->size, scratch, x);

      if (!curve25519_sqrt (ecc, p + ecc->size, scratch + ecc->size))
	die ("Point not on curve.\n");
      mpn_copyi (p, x, ecc->size);
      ecc_mul_a_eh (ecc, p, s, p, scratch);
    }
  else
    {
      itch = ECC_MUL_G_EH_ITCH (ecc->size);
      scratch = gmp_alloc_limbs (itch);
      ecc_mul_g_eh (ecc, p, s, scratch);
    }

  ecc_eh_to_a (ecc, 2, r,  p, scratch);

  /* FIXME: Convert to little-endian here? */
  gmp_free_limbs (p, 3*ecc->size);
  gmp_free_limbs (scratch, itch);
}

static void
test_g (const uint8_t *s, const uint8_t *r)
{
  uint8_t p[CURVE25519_SIZE];
  curve25519_mul_g (p, s);
  if (!MEMEQ (CURVE25519_SIZE, p, r))
    {
      printf ("curve25519_mul_g failure:\ns = ");
      print_hex (CURVE25519_SIZE, s);
      printf ("\np = ");
      print_hex (CURVE25519_SIZE, p);
      printf (" (bad)\nr = ");
      print_hex (CURVE25519_SIZE, r);
      printf (" (expected)\n");
      abort ();
    }
}

static void
test_a (const char *bz, const char *sz, const char *pz)
{
  mpz_t B, S, R, X;
  const struct ecc_curve *ecc = &nettle_curve25519;

  mpz_init (B);
  mpz_init (S);
  mpz_init (R);
  mpz_init (X);

  mpz_set_str (B, bz, 16);
  mpz_set_str (S, sz, 16);
  mpz_set_str (R, pz, 16);

  ASSERT (mpz_size (S) == ecc->size);
  ASSERT (mpz_size (B) == ecc->size);
  
  curve_25519 (ecc, mpz_limbs_write (X, ecc->size),
	       mpz_limbs_read (S), mpz_limbs_read (B));

  mpz_limbs_finish (X, ecc->size);
  if (mpz_cmp (X, R) != 0)
    {
      fprintf (stderr, "curve25519 failure:\nB = ");
      mpz_out_str (stderr, 16, B);
      fprintf (stderr, "\nS = ");
      mpz_out_str (stderr, 16, S);
      fprintf (stderr, "\nX = ");
      mpz_out_str (stderr, 16, X);
      fprintf (stderr, " (bad)\nR = ");
      mpz_out_str (stderr, 16, R);
      fprintf (stderr, " (expected)\n");
      abort ();
    }

  mpz_clear (B);
  mpz_clear (S);
  mpz_clear (R);
  mpz_clear (X);
}

void
test_main (void)
{
  /* From draft-turner-thecurve25519function-00 (same also in
     draft-josefsson-tls-curve25519-05, but the latter uses different
     endianness). */
  test_g (H("77076d0a7318a57d3c16c17251b26645"
	    "df4c2f87ebc0992ab177fba51db92c2a"),
	  H("8520f0098930a754748b7ddcb43ef75a"
	    "0dbf3a0d26381af4eba4a98eaa9b4e6a"));
  test_g (H("5dab087e624a8a4b79e17f8b83800ee6"
	    "6f3bb1292618b6fd1c2f8b27ff88e0eb"),
	  H("de9edb7d7b7dc1b4d35b61c2ece43537"
	    "3f8343c85b78674dadfc7e146f882b4f"));

  test_a ("4F2B886F147EFCAD4D67785BC843833F"
	  "3735E4ECC2615BD3B4C17D7B7DDB9EDE",

	  "6A2CB91DA5FB77B12A99C0EB872F4CDF"
	  "4566B25172C1163C7DA518730A6D0770",
	  
	  "4217161E3C9BF076339ED147C9217EE0"
	  "250F3580F43B8E72E12DCEA45B9D5D4A");

  test_a ("6A4E9BAA8EA9A4EBF41A38260D3ABF0D"
	  "5AF73EB4DC7D8B7454A7308909F02085",
	  
	  "6BE088FF278B2F1CFDB6182629B13B6F"
	  "E60E80838B7FE1794B8A4A627E08AB58",

	  "4217161E3C9BF076339ED147C9217EE0"
	  "250F3580F43B8E72E12DCEA45B9D5D4A");
}
