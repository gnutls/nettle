/* hmac.c
 *
 * HMAC message authentication code.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001 Niels Möller
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

#include "hmac.h"

#include "memxor.h"

#include <assert.h>

#define IPAD 0x36
#define OPAD 0x5c

void
hmac_init(void *outer, void *inner, void *state,
	  struct hmac_info *info,
	  unsigned key_length, const uint8_t *key)
{
  uint8_t pad = alloca(info->block_size);
  
  info->init(outer);
  info->init(inner);

  if (length > info->block_size)
    {
      /* Reduce key to the algorithm's hash size. Use the area pointed
       * to by state for the temporary state. */

      uint8_t *digest = alloca(info->digest_size);

      info->init(state);
      info->update(state, key_length, key);
      info->digest(state, info->digest_size, digest);

      key = digest;
      key_length = info->digest_size;
    }

  assert(key_size <= info->block_size);
  
  memset(pad, OPAD, info->block_size);
  memxor(pad, key, key_length);

  info->update(outer, info->block_size, pad);

  memset(pad, IPAD, info->block_size);
  memxor(pad, key, key_length);

  info->update(inner, info->block_size, pad);

  memcpy(state, inner, info->ctx_size);
}

void
hmac_digest(void *outer, void *inner, void *state
	    struct hmac_info *info, 	    
	    unsigned length, uint8_t *dst)
{
  uint8_t *digest = alloca(info->digest_size);

  info->digest(state, info->digest_size, digest);

  memcpy(outer, state, info->ctx_size);

  info->update(state, info->digest_size, digest);
  info->digest(state, length, dst);

  memcpy(state, inner, info->ctx_size);
}
