/* bignum.c
 *
 * bignum operations that are missing from gmp.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001 Niels Möller
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
#include "config.h"
#endif

#if HAVE_LIBGMP

#include "bignum.h"

#include <assert.h>
#include <string.h>

void
nettle_mpz_get_str_256(unsigned length, uint8_t *s, mpz_t x)
{
  uint8_t *dst = s + length - 1;
  unsigned size = mpz_size(x);
  unsigned i;

  if (!length)
    {
      /* x must be zero */
      assert(!mpz_sgn(x));
      return;
    }
  
  assert(mpz_sgn(x) >= 0);
  assert( (mpz_sizeinbase(x, 2) + 7) / 8 <= length);

  for (i = 0; i<size; i++)
    {
      mp_limb_t limb = mpz_getlimbn(x, i);
      unsigned j;

      for (j = 0; length && j < sizeof(mp_limb_t); j++)
        {
          *dst-- = limb & 0xff;
          limb >>= 8;
          length--;
	}
    }
  
  if (length)
    memset(dst, 0, length);
}

void
nettle_mpz_set_str_256(mpz_t x,
                       unsigned length, const uint8_t *s)
{
  size_t i;
  mpz_t digit;

  mpz_init(digit);
  mpz_set_ui(x, 0);
  for (i = 0; i < length; i++)
    {
      mpz_set_ui(digit, s[i]);
      mpz_mul_2exp(digit, digit, (length - i - 1) * 8);
      mpz_ior(x, x, digit);
    }
  mpz_clear(digit);
}

void
nettle_mpz_init_set_str_256(mpz_t x,
                            unsigned length, const uint8_t *s)
{
  mpz_init(x);
  nettle_mpz_set_str_256(x, length, s);
}

#endif /* HAVE_LIBGMP */
