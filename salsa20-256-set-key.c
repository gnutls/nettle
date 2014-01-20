/*
 * The Salsa20 stream cipher.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2012 Simon Josefsson
 * Copyright (C) 2012-2014 Niels Möller
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

/* Based on:
   salsa20-ref.c version 20051118
   D. J. Bernstein
   Public domain.
*/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "salsa20.h"

#include "macros.h"

void
salsa20_256_set_key(struct salsa20_ctx *ctx, const uint8_t *key)
{
  ctx->input[1] = LE_READ_UINT32(key + 0);
  ctx->input[2] = LE_READ_UINT32(key + 4);
  ctx->input[3] = LE_READ_UINT32(key + 8);
  ctx->input[4] = LE_READ_UINT32(key + 12);

  ctx->input[11] = LE_READ_UINT32(key + 16);
  ctx->input[12] = LE_READ_UINT32(key + 20);
  ctx->input[13] = LE_READ_UINT32(key + 24);
  ctx->input[14] = LE_READ_UINT32(key + 28);

  /* "expand 32-byte k" */
  ctx->input[0]  = 0x61707865;
  ctx->input[5]  = 0x3320646e;
  ctx->input[10] = 0x79622d32;
  ctx->input[15] = 0x6b206574;
}
