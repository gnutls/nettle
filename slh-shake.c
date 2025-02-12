/* slh-prf.c

   Copyright (C) 2025 Niels Möller

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

#include "sha3.h"
#include "slh-dsa-internal.h"

void
_slh_shake_init (struct sha3_256_ctx *ctx, const uint8_t *public_seed,
		 const struct slh_address_tree *at, const struct slh_address_hash *ah)
{
  sha3_256_init (ctx);
  sha3_256_update (ctx, _SLH_DSA_128_SIZE, public_seed);
  sha3_256_update (ctx, sizeof(*at), (const uint8_t *) at);
  sha3_256_update (ctx, sizeof(*ah), (const uint8_t *) ah);
}

void
_slh_shake (const uint8_t *public_seed,
	    const struct slh_address_tree *at, const struct slh_address_hash *ah,
	    const uint8_t *secret, uint8_t *out)
{
  struct sha3_256_ctx ctx;
  _slh_shake_init (&ctx, public_seed, at, ah);
  sha3_256_update (&ctx, _SLH_DSA_128_SIZE, secret);
  sha3_256_shake (&ctx, _SLH_DSA_128_SIZE, out);
}
