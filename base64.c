/* base64.c
 *
 * Base64 "ASCII armor" codec.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2002 Niels Möller, Dan Egnor
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

static const uint8_t encode_table[64] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz"
  "0123456789+/";

static const signed char decode_table[256] =
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

#define ENCODE(x) (encode_table[0x3F & (x)])

unsigned 
base64_encode(uint8_t *dst,
              unsigned src_length,
              const uint8_t *src)
{
  unsigned dst_length = BASE64_ENCODE_LENGTH(src_length);
  const uint8_t *in = src + src_length;
  uint8_t *out = dst + dst_length;
  unsigned left_over = src_length % 3;

  if (left_over)
    {
      switch(left_over)
	{
	case 1:
	  in--;
	  *--out = '=';
	  *--out = '=';
	  *--out = ENCODE(in[0] << 4);
	  *--out = ENCODE(in[0] >> 2);
	  break;
	  
	case 2:
	  in-= 2;
	  *--out = '=';
	  *--out = ENCODE( in[1] << 2);
	  *--out = ENCODE((in[0] << 4) | (in[1] >> 4));
	  *--out = ENCODE( in[0] >> 2);
	  break;

	default:
	  abort();
	}
    }
  
  while (in > src)
    {
      in -= 3;
      *--out = ENCODE( in[2]);
      *--out = ENCODE((in[1] << 2) | (in[2] >> 6));
      *--out = ENCODE((in[0] << 4) | (in[1] >> 4));
      *--out = ENCODE( in[0] >> 2);
    }

  assert(out == dst);

  return dst_length;
}

void
base64_decode_init(struct base64_ctx *ctx)
{
  ctx->shift = 10;
  ctx->accum = 0;
}

unsigned
base64_decode_update(struct base64_ctx *ctx,
                     uint8_t *dst,
                     unsigned src_length,
                     const uint8_t *src)
{
  uint8_t *out = dst;

  for (;;) 
    {
      int data;
      if (src_length == 0) return out - dst;
      data = decode_table[*src];
      switch (data)
        {
        default:
          ctx->accum |= data << ctx->shift;
          ctx->shift -= 6;
          if (ctx->shift <= 2)
            {
              *out++ = ctx->accum >> 8;
              ctx->accum <<= 8;
              ctx->shift += 8;
            }
	  /* Fall through */
        case TABLE_INVALID:
        case TABLE_SPACE:
        case TABLE_END:
	  /* FIXME: Silently ignores any invalid characters.
	   * We need to detect and return errors, in some way. */
          ++src;
          --src_length;
        }
    }
}
