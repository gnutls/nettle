/* chacha128-set-key.c
 *
 * ChaCha key setup for 128-bit keys.
 * Based on the Salsa20 implementation in Nettle.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2013 Joachim Strömbergon
 * Copyright (C) 2012 Simon Josefsson
 * Copyright (C) 2012, 2014 Niels Möller
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
   ChaCha specification (doc id: 4027b5256e17b9796842e6d0f68b0b5e) and reference 
   implementation dated 2008.01.20
   D. J. Bernstein
   Public domain.
*/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include "chacha.h"

#include "macros.h"

void
chacha128_set_key(struct chacha_ctx *ctx, const uint8_t *key)
{
  static const uint32_t tau[4] = {
    /* "expand 16-byte k" */
    0x61707865, 0x3120646e, 0x79622d36, 0x6b206574
  };

  ctx->state[8]  = ctx->state[4] = LE_READ_UINT32(key + 0);
  ctx->state[9]  = ctx->state[5] = LE_READ_UINT32(key + 4);
  ctx->state[10] = ctx->state[6] = LE_READ_UINT32(key + 8);
  ctx->state[11] = ctx->state[7] = LE_READ_UINT32(key + 12);

  memcpy (ctx->state, tau, sizeof(tau));
}
