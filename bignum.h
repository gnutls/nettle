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

#include <gmp.h>
#include <inttypes.h>

/* Writes an unsigned integer as length octets, using big endian byte
 * order. */
void
nettle_mpz_get_str_256(unsigned length, uint8_t *s, mpz_t x);

void
nettle_mpz_set_str_256(mpz_t x,
                       unsigned length, const uint8_t *s);

void
nettle_mpz_init_set_str_256(mpz_t x,
                            unsigned length, const uint8_t *s);

#endif /* NETTLE_BIGNUM_H_INCLUDED */
