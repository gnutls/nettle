/* bignum-random-prime.c
 *
 * Generation of random provable primes.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2010 Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef RANDOM_PRIME_VERBOSE
#define RANDOM_PRIME_VERBOSE 0
#endif

#include <assert.h>
#include <stdlib.h>

#if RANDOM_PRIME_VERBOSE
#include <stdio.h>
#define VERBOSE(x) (fputs((x), stderr))
#else
#define VERBOSE(x)
#endif

#include "bignum.h"

#include "macros.h"

/* Use a table of p_2 = 3 to p_{172} = 1021, multiplied to 32-bit or
   64-bit size. */

struct sieve_element {
  /* Product of some small primes. */
  unsigned long prod;
  /* Square of the smallest one. */
  unsigned long p2;
};

static const struct sieve_element
sieve_table[] = {
  {111546435, 9}, /* 3 -- 23 */
  {58642669, 841}, /* 29 -- 43 */
  {600662303, 2209}, /* 47 -- 67 */
  {33984931, 5041}, /* 71 -- 83 */
  {89809099, 7921}, /* 89 -- 103 */
  {167375713, 11449}, /* 107 -- 127 */
  {371700317, 17161}, /* 131 -- 149 */
  {645328247, 22801}, /* 151 -- 167 */
  {1070560157, 29929}, /* 173 -- 191 */
  {1596463769, 37249}, /* 193 -- 211 */
  {11592209, 49729}, /* 223 -- 229 */
  {13420567, 54289}, /* 233 -- 241 */
  {16965341, 63001}, /* 251 -- 263 */
  {20193023, 72361}, /* 269 -- 277 */
  {23300239, 78961}, /* 281 -- 293 */
  {29884301, 94249}, /* 307 -- 313 */
  {35360399, 100489}, /* 317 -- 337 */
  {42749359, 120409}, /* 347 -- 353 */
  {49143869, 128881}, /* 359 -- 373 */
  {56466073, 143641}, /* 379 -- 389 */
  {65111573, 157609}, /* 397 -- 409 */
  {76027969, 175561}, /* 419 -- 431 */
  {84208541, 187489}, /* 433 -- 443 */
  {94593973, 201601}, /* 449 -- 461 */
  {103569859, 214369}, /* 463 -- 479 */
  {119319383, 237169}, /* 487 -- 499 */
  {133390067, 253009}, /* 503 -- 521 */
  {154769821, 273529}, /* 523 -- 547 */
  {178433279, 310249}, /* 557 -- 569 */
  {193397129, 326041}, /* 571 -- 587 */
  {213479407, 351649}, /* 593 -- 601 */
  {229580147, 368449}, /* 607 -- 617 */
  {250367549, 383161}, /* 619 -- 641 */
  {271661713, 413449}, /* 643 -- 653 */
  {293158127, 434281}, /* 659 -- 673 */
  {319512181, 458329}, /* 677 -- 691 */
  {357349471, 491401}, /* 701 -- 719 */
  {393806449, 528529}, /* 727 -- 739 */
  {422400701, 552049}, /* 743 -- 757 */
  {452366557, 579121}, /* 761 -- 773 */
  {507436351, 619369}, /* 787 -- 809 */
  {547978913, 657721}, /* 811 -- 823 */
  {575204137, 683929}, /* 827 -- 839 */
  {627947039, 727609}, /* 853 -- 859 */
  {666785731, 744769}, /* 863 -- 881 */
  {710381447, 779689}, /* 883 -- 907 */
  {777767161, 829921}, /* 911 -- 929 */
  {834985999, 877969}, /* 937 -- 947 */
  {894826021, 908209}, /* 953 -- 971 */
  {951747481, 954529}, /* 977 -- 991 */
  {1019050649, 994009}, /* 997 -- 1013 */
  {1040399, 1038361}, /* 1019 -- 1021 */
};

#define SIEVE_SIZE (sizeof(sieve_table) / sizeof(sieve_table[0]))

/* Combined Miller-Rabin test to the base a, and checking the
   conditions from Pocklington's theorem. */
static int
miller_rabin_pocklington(mpz_t n, mpz_t nm1, mpz_t nm1dq, mpz_t a)
{
  mpz_t r;
  mpz_t y;
  int is_prime = 0;

  /* Avoid the mp_bitcnt_t type for compatibility with older GMP
     versions. */
  unsigned k;
  unsigned j;

  VERBOSE(".");

  if (mpz_even_p(n) || mpz_cmp_ui(n, 3) < 0)
    return 0;

  mpz_init(r);
  mpz_init(y);

  k = mpz_scan1(nm1, 0);
  assert(k > 0);

  mpz_fdiv_q_2exp (r, nm1, k);

  mpz_powm(y, a, r, n);

  if (mpz_cmp_ui(y, 1) == 0 || mpz_cmp(y, nm1) == 0)
    goto passed_miller_rabin;
    
  for (j = 1; j < k; j++)
    {
      mpz_powm_ui (y, y, 2, n);

      if (mpz_cmp_ui (y, 1) == 0)
	break;

      if (mpz_cmp (y, nm1) == 0)
	{
	passed_miller_rabin:
	  /* We know that a^{n-1} = 1 (mod n)

	     Remains to check that gcd(a^{(n-1)/q} - 1, n) == 1 */      
	  VERBOSE("x");

	  mpz_powm(y, a, nm1dq, n);
	  mpz_sub_ui(y, y, 1);
	  mpz_gcd(y, y, n);
	  is_prime = mpz_cmp_ui (y, 1) == 0;
	  VERBOSE(is_prime ? "\n" : "");
	  break;
	}

    }

  mpz_clear(r);
  mpz_clear(y);

  return is_prime;
}

/* Generate random prime of a given size. Maurer's algorithm (Alg.
   6.42 Handbook of applied cryptography), but with ratio = 1/2 (like
   the variant in fips186-3). FIXME: Force primes to start with two
   one bits? */
void
nettle_random_prime(mpz_t p, unsigned bits,
		    void *ctx, nettle_random_func random)
{
  assert (bits >= 6);
  if (bits < 20)
    {
      unsigned long highbit;
      uint8_t buf[3];
      unsigned long x;
      unsigned j;

      /* Small cases:

	 3 bits: 5 or 7
	 4 bits: 11, 13, 15
	 5 bits: 17, 19, 23, 29, 31

	 With 3 bits, no sieving is done, since candidates are smaller
	 than 3^2 = 9 (and this is ok; all odd 3-bit numbers are
	 prime).

	 With 4 bits, sieving with the first value, 3*5*...*23 doesn't
	 work, since this includes the primes 11 and 13 in the
	 interval. Of the odd numbers in the interval, 9, 11, 13, 15,
	 only the factors of three need be discarded.

	 With 5 bits, we still sieve with only the first value, which
	 includes three of the primes in the interval. Of the odd
	 numbers in the interval, 17, 19, (21), 23, (25), (27), 29,
	 31, we need to discard multiples of 3 and 5 only.

	 With 6 bits, we sieve with only the first value (since 63 <
	 29^2), and there's no problem.
       */
      
      highbit = 1L << (bits - 1);

    again:
      random (ctx, sizeof(buf), buf);
      x = READ_UINT24(buf);
      x &= (highbit - 1);
      x |= highbit | 1;

      mpz_set_ui (p, x);      
      for (j = 0; j < SIEVE_SIZE && x >= sieve_table[j].p2; j++)
	if (mpz_gcd_ui (NULL, p, sieve_table[j].prod) != 1)
	  goto again;
    }
  else
    {
      mpz_t q, r, nm1, t, a, i;
      unsigned j;

      mpz_init (q);
      mpz_init (r);
      mpz_init (nm1);
      mpz_init (t);
      mpz_init (a);
      mpz_init (i);

     /* Bit size ceil(k/2) + 1, slightly larger than used in Alg.
         4.62. */
      nettle_random_prime (q, (bits+3)/2, ctx, random);

      /* i = floor (2^{bits-2} / q) */
      mpz_init_set_ui (i, 1);
      mpz_mul_2exp (i, i, bits-2);
      mpz_fdiv_q (i, i, q);

      for (;;)
	{
	  uint8_t buf[1];

	  /* Generate r in the range i + 1 <= r <= 2*i */
	  nettle_mpz_random (r, ctx, random, i);
	  mpz_add (r, r, i);
	  mpz_add_ui (r, r, 1);

	  /* Set p = 2*r*q + 1 */
	  mpz_mul_2exp(r, r, 1);
	  mpz_mul (nm1, r, q);
	  mpz_add_ui (p, nm1, 1);

	  assert(mpz_sizeinbase(p, 2) == bits);

	  for (j = 0; j < SIEVE_SIZE; j++)
	    {
	      if (mpz_gcd_ui (NULL, p, sieve_table[j].prod) != 1)
		goto composite;
	    }

	  random(ctx, sizeof(buf), buf);
	  
	  mpz_set_ui (a, buf[0] + 2);

	  if (miller_rabin_pocklington(p, nm1, r, a))
	    break;
	composite:
	  ;
	}
      mpz_clear (q);
      mpz_clear (r);
      mpz_clear (nm1);
      mpz_clear (t);
      mpz_clear (a);
      mpz_clear (i);
    }
}
