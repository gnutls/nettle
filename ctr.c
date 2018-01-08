/* ctr.c

   Cipher counter mode.

   Copyright (C) 2005 Niels Möller

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
#include <stdlib.h>
#include <string.h>

#include "ctr.h"

#include "macros.h"
#include "memxor.h"
#include "nettle-internal.h"

/* Don't allocate any more space than this on the stack */
#define CTR_BUFFER_LIMIT 512

void
ctr_crypt(const void *ctx, nettle_cipher_func *f,
	  size_t block_size, uint8_t *ctr,
	  size_t length, uint8_t *dst,
	  const uint8_t *src)
{
  if (src != dst)
    {
      if (length == block_size)
	{
	  f(ctx, block_size, dst, ctr);
	  INCREMENT(block_size, ctr);
	  memxor(dst, src, block_size);
	}
      else
	{
	  size_t left;
	  uint8_t *p;	  

	  for (p = dst, left = length;
	       left >= block_size;
	       left -= block_size, p += block_size)
	    {
	      memcpy (p, ctr, block_size);
	      INCREMENT(block_size, ctr);
	    }

	  f(ctx, length - left, dst, dst);
	  memxor(dst, src, length - left);

	  if (left)
	    {
	      TMP_DECL(buffer, uint8_t, NETTLE_MAX_CIPHER_BLOCK_SIZE);
	      TMP_ALLOC(buffer, block_size);

	      f(ctx, block_size, buffer, ctr);
	      INCREMENT(block_size, ctr);
	      memxor3(dst + length - left, src + length - left, buffer, left);
	    }
	}
    }
  else
    {
      /* For in-place CTR, construct a buffer of consecutive counter
	 values, of size at most CTR_BUFFER_LIMIT. */
      TMP_DECL(buffer, uint8_t, CTR_BUFFER_LIMIT);

      size_t buffer_size;
      if (length < block_size)
	buffer_size = block_size;
      else if (length <= CTR_BUFFER_LIMIT)
	buffer_size = length;
      else
	buffer_size = CTR_BUFFER_LIMIT;

      TMP_ALLOC(buffer, buffer_size);

      while (length >= block_size)
	{
	  size_t i;
	  for (i = 0;
	       i + block_size <= buffer_size && i + block_size <= length;
	       i += block_size)
	    {
	      memcpy (buffer + i, ctr, block_size);
	      INCREMENT(block_size, ctr);
	    }
	  assert (i > 0);
	  f(ctx, i, buffer, buffer);
	  memxor(dst, buffer, i);
	  length -= i;
	  dst += i;
	}

      /* Final, possibly partial, block. */
      if (length > 0)
	{
	  f(ctx, block_size, buffer, ctr);
	  INCREMENT(block_size, ctr);
	  memxor(dst, buffer, length);
	}
    }
}
