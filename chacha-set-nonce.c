/* chacha-set-nonce.c
 *
 * Setting the nonce the ChaCha stream cipher.
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

#include "chacha.h"

#include "macros.h"

void
chacha_set_nonce(struct chacha_ctx *ctx, const uint8_t *nonce)
{
  ctx->state[12] = 0;
  ctx->state[13] = 0;
  ctx->state[14] = LE_READ_UINT32(nonce + 0);
  ctx->state[15] = LE_READ_UINT32(nonce + 4);
}
