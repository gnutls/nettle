/* dsa-hash.c */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2013 Niels Möller
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
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "dsa.h"

#include "bignum.h"

/* Convert hash value to an integer. The general description of DSA in
   FIPS186-3 allows both larger and smaller q; in the the latter case,
   the hash must be truncated to the right number of bits. */
void
_dsa_hash (mpz_t h, unsigned bit_size,
	   size_t length, const uint8_t *digest)
{
  
  if (length > (bit_size + 7) / 8)
    length = (bit_size + 7) / 8;

  nettle_mpz_set_str_256_u(h, length, digest);

  if (8 * length > bit_size)
    /* We got a few extra bits, at the low end. Discard them. */
    mpz_tdiv_q_2exp (h, h, 8*length - bit_size);
}
