/* base64-encode.c
 *
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2002 Niels Möller
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

#include "base64.h"

#include <assert.h>
#include <stdlib.h>

#define TABLE_INVALID -1
#define TABLE_SPACE -2
#define TABLE_END -3

/* FIXME: Make sure that all whitespace characters, SPC, HT, VT, FF,
 * CR and LF are ignored. */
static const signed char
decode_table[0x100] =
{
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -1, -1, -2, -1, -1, 
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -3, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

void
base64_decode_init(struct base64_decode_ctx *ctx)
{
  ctx->word = ctx->bits = 0;
  ctx->status = BASE64_DECODE_OK;
}

unsigned
base64_decode_single(struct base64_decode_ctx *ctx,
		     uint8_t *dst,
		     uint8_t src)
{
  int data;
  
  if (ctx->status == BASE64_DECODE_ERROR)
    return 0;

  data = decode_table[src];

  switch(data)
    {
    default:
      assert(data >= 0 && data < 0x40);
	  
      if (ctx->status != BASE64_DECODE_OK)
	goto invalid;
	  
      ctx->word = ctx->word << 6 | data;
      ctx->bits += 6;

      if (ctx->bits >= 8)
	{
	  ctx->bits -= 8;
	  dst[0] = ctx->word >> ctx->bits;
	  return 1;
	}
      else return 0;

    case TABLE_INVALID:
    invalid:
      ctx->status = BASE64_DECODE_ERROR;
      /* Fall through */
      
    case TABLE_SPACE:
      return 0;
      
    case TABLE_END:
      if (!ctx->bits)
	goto invalid;
      if (ctx->word & ( (1<<ctx->bits) - 1))
	/* We shouldn't have any leftover bits */
	goto invalid;
      
      ctx->status = BASE64_DECODE_END;
      ctx->bits -= 2;
      return 0;
    }
}

unsigned
base64_decode_update(struct base64_decode_ctx *ctx,
		     uint8_t *dst,
		     unsigned length,
		     const uint8_t *src)
{
  unsigned done;
  unsigned i;
  
  if (ctx->status == BASE64_DECODE_ERROR)
    return 0;

  for (i = 0, done = 0; i<length; i++)
    done += base64_decode_single(ctx, dst + done, src[i]);

  assert(done <= BASE64_DECODE_LENGTH(length));
  
  return done;
}

int
base64_decode_status(struct base64_decode_ctx *ctx)
{
  switch (ctx->status)
    {
    case BASE64_DECODE_END:
    case BASE64_DECODE_OK:
      return ctx->bits == 0;
    case BASE64_DECODE_ERROR:
      return 0;
    }
  abort();
}
