/* hmac-internal.c

   Copyright (C) 2024 Niels Möller

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

#include <assert.h>
#include <string.h>

#include "hmac-internal.h"
#include "memxor.h"

static void
memxor_byte (uint8_t *p, uint8_t b, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++)
    p[i] ^= b;
}

void
_nettle_hmac_outer_block (size_t block_size, uint8_t *block, size_t key_size, const uint8_t *key)
{
  assert (key_size <= block_size);
  memset (block, OPAD, block_size);
  memxor (block, key, key_size);
}

void
_nettle_hmac_outer_block_digest (size_t block_size, uint8_t *block, size_t key_size)
{
  assert (key_size <= block_size);

  memxor_byte (block, OPAD, key_size);
  memset (block + key_size, OPAD, block_size - key_size);
}

void
_nettle_hmac_inner_block (size_t block_size, uint8_t *block)
{
  memxor_byte (block, OPAD ^ IPAD, block_size);
}
