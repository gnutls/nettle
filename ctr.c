/* ctr.c
 *
 * Cipher counter mode.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2005 Niels Möller
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "ctr.h"

#include "memxor.h"
#include "nettle-internal.h"

#define INCREMENT(size, counter, i)		\
do {						\
  if (++(ctr)[(size) - 1] == 0)			\
    {						\
      unsigned i = size - 1;			\
      while (i > 0 && ++(ctr)[--i] == 0)	\
	;					\
    }						\
} while (0)
  
void
ctr_crypt(void *ctx, nettle_crypt_func f,
	  unsigned block_size, uint8_t *ctr,
	  unsigned length, uint8_t *dst,
	  const uint8_t *src)
{
  TMP_DECL(buffer, uint8_t, NETTLE_MAX_CIPHER_BLOCK_SIZE);
  TMP_ALLOC(buffer, block_size);

  if (src != dst)
    {
      for (; length >= block_size; length -= block_size, src += block_size, dst += block_size)
	{
	  f(ctx, block_size, dst, ctr);
	  memxor(dst, src, block_size);
	  INCREMENT(block_size, ctr, i);
	}
    }
  else
    {
      for (; length >= block_size; length -= block_size, src += block_size, dst += block_size)
	{
	  f(ctx, block_size, buffer, ctr);
	  memxor3(dst, src, buffer, block_size);
	  INCREMENT(block_size, ctr, i);
	}      
    }
  if (length > 0)
    {
      /* A final partial block */

      f(ctx, block_size, buffer, ctr);
      memxor3(dst, src, buffer, length);
      INCREMENT(block_size, ctr, i);
    }
}
