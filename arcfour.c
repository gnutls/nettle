/* arcfour.c
 *
 * This implements the Arcfour stream cipher with 128 bit keys. 
 *
 * The Arcfour cipher is believed to be compatible with the RC4 cipher. 
 * RC4 is a registered trademark of RSA Data Security Inc.
 *   
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "arcfour.h"

#ifdef RCSID
RCSID("$Id$");
#endif

#define SWAP(a,b) do { int _t = a; a = b; b = _t; } while(0)

void arcfour_set_key(struct arcfour_ctx *ctx, const UINT8 *key, UINT32 len)
{
  register UINT8 j; /* Depends on the eight-bitness of these variables. */
  unsigned i;
  UINT32 k;

  /* Initialize context */
  i = 0;
  do ctx->S[i] = i; while (++i < 256);

  /* Expand key */
  i = j = k = 0;
  do {
    j += ctx->S[i] + key[k];
    SWAP(ctx->S[i], ctx->S[j]);
    k = (k+1) % len; /* Repeat key if needed */
  } while(++i < 256);
  
  ctx->i = ctx->j = 0;
}

void arcfour_crypt(struct arcfour_ctx *ctx, UINT8 *dest,
		   const UINT8 *src, UINT32 len)
{
  register UINT8 i, j;

  i = ctx->i; j = ctx->j;
  while(len--)
    {
      i++; i &= 0xff;
      j += ctx->S[i]; j &= 0xff;
      SWAP(ctx->S[i], ctx->S[j]);
      *dest++ = *src++ ^ ctx->S[ (ctx->S[i] + ctx->S[j]) & 0xff ];
    }
  ctx->i = i; ctx->j = j;
}
