/* camellia128-set-decrypt-key.c
 *
 * Inverse key setup for the camellia block cipher.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2010, 2013 Niels Möller
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

#include "camellia-internal.h"

void
camellia128_invert_key(struct camellia128_ctx *dst,
		       const struct camellia128_ctx *src)
{
  _camellia_invert_key (_CAMELLIA128_NKEYS, dst->keys, src->keys);
}

void
camellia128_set_decrypt_key(struct camellia128_ctx *ctx,
			    const uint8_t *key)
{
  camellia128_set_encrypt_key(ctx, key);
  camellia128_invert_key(ctx, ctx);
}
