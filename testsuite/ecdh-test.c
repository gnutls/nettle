/* ecdh-test.c

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

static void
set_point (struct ecc_point *p,
	   const char *x, const char *y)
{
  mpz_t X, Y;
  mpz_init_set_str (X, x, 0);
  mpz_init_set_str (Y, y, 0);
  ecc_point_set (p, X, Y);
  mpz_clear (X);
  mpz_clear (Y);
}
  
static void
set_scalar (struct ecc_scalar *s,
	    const char *x)
{
  mpz_t X;
  mpz_init_set_str (X, x, 0);
  ecc_scalar_set (s, X);
  mpz_clear (X);
}

static void
check_point (const char *label,
	     const struct ecc_point *P,
	     const struct ecc_point *R)
{
  mpz_t px, py, rx, ry;

  mpz_init (px);
  mpz_init (py);
  mpz_init (rx);
  mpz_init (ry);

  ecc_point_get (P, px, py);
  ecc_point_get (R, rx, ry);

  /* FIXME: Should have a public point compare function */
  if (mpz_cmp (px, rx) != 0 ||  mpz_cmp (py, ry) != 0)
    {
      fprintf (stderr, "Failed %s\np_x = ", label);
      mpz_out_str (stderr, 10, px);
      fprintf (stderr, "\nr_x = ");
      mpz_out_str (stderr, 10, rx);
      fprintf (stderr, " (expected)\np_y = ");
      mpz_out_str (stderr, 10, py);
      fprintf (stderr, "\nr_y = ");
      mpz_out_str (stderr, 10, ry);
      fprintf (stderr, " (expected)\n");
      abort ();      
    }
  mpz_clear (px);
  mpz_clear (py);
  mpz_clear (rx);
  mpz_clear (ry);
}

static void
test_dh (const struct ecc_curve *ecc,
	 const char *a_priv, const char *ax, const char *ay,
	 const char *b_priv, const char *bx, const char *by,
	 const char *sx, const char *sy)
{
  struct ecc_point A, B, S, T;
  struct ecc_scalar A_priv, B_priv;

  ecc_scalar_init (&A_priv, ecc);
  set_scalar (&A_priv, a_priv);
  ecc_point_init (&A, ecc);
  set_point (&A, ax, ay);

  ecc_scalar_init (&B_priv, ecc);
  set_scalar (&B_priv, b_priv);
  ecc_point_init (&B, ecc);
  set_point (&B, bx, by);

  ecc_point_init (&S, ecc);
  set_point (&S, sx, sy);

  ecc_point_init (&T, ecc);

  ecc_point_mul_g (&T, &A_priv);
  check_point ("a g", &T, &A);

  ecc_point_mul (&T, &B_priv, &T);
  check_point ("b (a g)", &T, &S);

  ecc_point_mul_g (&T, &B_priv);
  check_point ("b g", &T, &B);

  ecc_point_mul (&T, &A_priv,  &T);
  check_point ("a (b g)", &T, &S);

  ecc_scalar_clear (&A_priv);
  ecc_scalar_clear (&B_priv);

  ecc_point_clear (&A);
  ecc_point_clear (&B);
  ecc_point_clear (&S);
  ecc_point_clear (&T);  
}

void
test_main(void)
{
  test_dh (&nettle_secp_192r1,
	   "3406157206141798348095184987208239421004566462391397236532",
	   "1050363442265225480786760666329560655512990381040021438562",
	   "5298249600854377235107392014200406283816103564916230704184",
	   "738368960171459956677260317271477822683777845013274506165",
	   "2585840779771604687467445319428618542927556223024046979917",
	   "293088185788565313717816218507714888251468410990708684573",
	   "149293809021051532782730990145509724807636529827149481690",
	   "2891131861147398318714693938158856874319184314120776776192");
}
