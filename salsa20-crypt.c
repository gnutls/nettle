/* salsa20-crypt.c
 *
 * The Salsa20 stream cipher.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2012 Simon Josefsson
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

/* Based on:
   salsa20-ref.c version 20051118
   D. J. Bernstein
   Public domain.
*/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include "salsa20.h"

#include "macros.h"
#include "memxor.h"

#ifdef WORDS_BIGENDIAN
#define LE_SWAP32(v)				\
  ((ROTL32(8,  v) & 0x00FF00FFUL) |		\
   (ROTL32(24, v) & 0xFF00FF00UL))
#else
#define LE_SWAP32(v) (v)
#endif

#define QROUND(x0, x1, x2, x3) do { \
  x1 ^= ROTL32(7, x0 + x3);	    \
  x2 ^= ROTL32(9, x1 + x0);	    \
  x3 ^= ROTL32(13, x2 + x1);	    \
  x0 ^= ROTL32(18, x3 + x2);	    \
  } while(0)

void
salsa20_crypt(struct salsa20_ctx *ctx,
	      unsigned length,
	      uint8_t *c,
	      const uint8_t *m)
{
  if (!length)
    return;
  
  for (;;)
    {
      uint32_t x[_SALSA20_INPUT_LENGTH];
      int i;
      memcpy (x, ctx->input, sizeof(x));
      for (i = 0;i < 10;i ++)
	{
	  QROUND(x[0], x[4], x[8], x[12]);
	  QROUND(x[5], x[9], x[13], x[1]);
	  QROUND(x[10], x[14], x[2], x[6]);
	  QROUND(x[15], x[3], x[7], x[11]);

	  QROUND(x[0], x[1], x[2], x[3]);
	  QROUND(x[5], x[6], x[7], x[4]);
	  QROUND(x[10], x[11], x[8], x[9]);
	  QROUND(x[15], x[12], x[13], x[14]);
	}

      for (i = 0;i < _SALSA20_INPUT_LENGTH;++i)
	{
	  uint32_t t = x[i] + ctx->input[i];
	  x[i] = LE_SWAP32 (t);
	}

      ctx->input[9] += (++ctx->input[8] == 0);

      /* stopping at 2^70 length per nonce is user's responsibility */
      
      if (length <= SALSA20_BLOCK_SIZE)
	{
	  memxor3 (c, m, (uint8_t *) x, length);
	  return;
	}
      memxor3 (c, m, (uint8_t *) x, SALSA20_BLOCK_SIZE);

      length -= SALSA20_BLOCK_SIZE;
      c += SALSA20_BLOCK_SIZE;
      m += SALSA20_BLOCK_SIZE;
  }
}
