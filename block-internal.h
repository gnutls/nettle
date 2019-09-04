/* block-internal.h

   Internal implementations of nettle_blockZ-related functions.

   Copyright (C) 2011 Katholieke Universiteit Leuven
   Copyright (C) 2011, 2013, 2018 Niels Möller
   Copyright (C) 2018 Red Hat, Inc.
   Copyright (C) 2019 Dmitry Eremin-Solenikov

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

#ifndef NETTLE_BLOCK_INTERNAL_H_INCLUDED
#define NETTLE_BLOCK_INTERNAL_H_INCLUDED

#include <assert.h>

#include "nettle-types.h"
#include "memxor.h"

static inline void
block16_xor (union nettle_block16 *r,
	     const union nettle_block16 *x)
{
  r->u64[0] ^= x->u64[0];
  r->u64[1] ^= x->u64[1];
}

static inline void
block16_xor3 (union nettle_block16 *r,
	      const union nettle_block16 *x,
	      const union nettle_block16 *y)
{
  r->u64[0] = x->u64[0] ^ y->u64[0];
  r->u64[1] = x->u64[1] ^ y->u64[1];
}

static inline void
block16_xor_bytes (union nettle_block16 *r,
		   const union nettle_block16 *x,
		   const uint8_t *bytes)
{
  memxor3 (r->b, x->b, bytes, 16);
}

static inline void
block8_xor (union nettle_block8 *r,
	    const union nettle_block8 *x)
{
  r->u64 ^= x->u64;
}

static inline void
block8_xor3 (union nettle_block8 *r,
	     const union nettle_block8 *x,
	     const union nettle_block8 *y)
{
  r->u64 = x->u64 ^ y->u64;
}

static inline void
block8_xor_bytes (union nettle_block8 *r,
		  const union nettle_block8 *x,
		  const uint8_t *bytes)
{
  memxor3 (r->b, x->b, bytes, 8);
}

#endif /* NETTLE_BLOCK_INTERNAL_H_INCLUDED */
