/* bignum.h
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
 
#ifndef NETTLE_BIGNUM_H_INCLUDED
#define NETTLE_BIGNUM_H_INCLUDED

#include "nettle-meta.h"

#include <gmp.h>
#include <inttypes.h>

unsigned
nettle_mpz_sizeinbase_256(const mpz_t x);

/* Writes an unsigned integer as length octets, using big endian byte
 * order. */
void
nettle_mpz_get_str_256(unsigned length, uint8_t *s, const mpz_t x);

void
nettle_mpz_set_str_256(mpz_t x,
                       unsigned length, const uint8_t *s);

void
nettle_mpz_init_set_str_256(mpz_t x,
                            unsigned length, const uint8_t *s);

/* Returns a uniformly distributed random number 0 <= x < 2^n */
void
nettle_mpz_random_size(mpz_t x,
		       void *ctx, nettle_random_func random,
		       unsigned bits);

/* Returns a number x, almost uniformly random in the range
 * 0 <= x < n. */
void
nettle_mpz_random(mpz_t x, 
		  void *ctx, nettle_random_func random,
		  const mpz_t n);

#endif /* NETTLE_BIGNUM_H_INCLUDED */
