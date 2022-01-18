/* poly1305-update.c

   Copyright (C) 2021 Mamone Tarsha

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

#include <string.h>

#include "poly1305.h"
#include "poly1305-internal.h"

#if HAVE_NATIVE_poly1305_2core
#define _nettle_poly1305_update_2core _nettle_poly1305_update
#elif !HAVE_NATIVE_fat_poly1305_2core
#define _nettle_poly1305_update_1core _nettle_poly1305_update
#endif

#if HAVE_NATIVE_poly1305_2core || HAVE_NATIVE_fat_poly1305_2core
void _nettle_poly1305_2core(struct poly1305_ctx *ctx, const uint8_t *m, size_t len, unsigned t4);
unsigned
_nettle_poly1305_update_2core(struct poly1305_ctx *ctx,
			   uint8_t *block, unsigned pos,
			   size_t length, const uint8_t *data)
{
  if (pos)
  {
    if (pos + length < POLY1305_BLOCK_SIZE)
    {
      memcpy (block + pos, data, length);
      return pos + length;
    }
    else
    {
      unsigned left = POLY1305_BLOCK_SIZE - pos;
      memcpy (block + pos, data, left);
      data += left;
      length -= left;
      _nettle_poly1305_block(ctx, block, 1);
    }
  }
  if (length >= 2*POLY1305_BLOCK_SIZE)
  {
    size_t rlen = length & -(2*POLY1305_BLOCK_SIZE);
    _nettle_poly1305_2core(ctx, data, rlen, 1);
    data += rlen;
    length -= rlen;
  }
  if (length >= POLY1305_BLOCK_SIZE)
  {
    _nettle_poly1305_block(ctx, data, 1);
    data += POLY1305_BLOCK_SIZE;
    length -= POLY1305_BLOCK_SIZE;
  }
  memcpy (block, data, length);
  return length;
}
#endif
#if !HAVE_NATIVE_poly1305_2core
unsigned
_nettle_poly1305_update_1core(struct poly1305_ctx *ctx,
			   uint8_t *block, unsigned pos,
			   size_t length, const uint8_t *data)
{
  if (pos)
  {
    if (pos + length < POLY1305_BLOCK_SIZE)
    {
      memcpy (block + pos, data, length);
      return pos + length;
    }
    else
    {
      unsigned left = POLY1305_BLOCK_SIZE - pos;
      memcpy (block + pos, data, left);
      data += left;
      length -= left;
      _nettle_poly1305_block(ctx, block, 1);
    }
  }
  for (; length >= POLY1305_BLOCK_SIZE; length -= POLY1305_BLOCK_SIZE, data += POLY1305_BLOCK_SIZE)
    _nettle_poly1305_block(ctx, data, 1);
  memcpy (block, data, length);
  return length;
}
#endif
