/* buffer.c
 *
 * A bare-bones string stream.
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

#include "buffer.h"

#include <stdlib.h>
#include <string.h>

static int
grow_realloc(struct nettle_buffer *buffer,
	     unsigned length)
{
  if (!length)
    {
      realloc(buffer->contents, 0);
      buffer->contents = NULL;
      buffer->alloc = 0;
      buffer->size = 0;

      return 1;
    }
  else
    {
      unsigned alloc = buffer->alloc * 2 + length + 100;
      uint8_t *p = realloc(buffer->contents, alloc);
      if (!p)
	return 0;
      
      buffer->contents = p;
      buffer->alloc = alloc;
      
      return 1;
    }
}

void
nettle_buffer_init(struct nettle_buffer *buffer)
{
  buffer->contents = NULL;
  buffer->alloc = 0;
  buffer->grow = grow_realloc;
  buffer->size = 0;
}

void
nettle_buffer_init_size(struct nettle_buffer *buffer,
			unsigned length, uint8_t *space)
{
  buffer->contents = space;
  buffer->alloc = length;
  buffer->grow = NULL;
  buffer->size = 0;
}

void
nettle_buffer_clear(struct nettle_buffer *buffer)
{
  NETTLE_BUFFER_GROW(buffer, 0);
}

uint8_t *
nettle_buffer_space(struct nettle_buffer *buffer,
		    unsigned length)
{
  uint8_t *p;
  if (buffer->size + length > buffer->alloc)
    if (!NETTLE_BUFFER_GROW(buffer, length))
      return NULL;

  p = buffer->contents + buffer->size;
  buffer->size += length;
  return p;
}
     
int
nettle_buffer_write(struct nettle_buffer *buffer,
		    unsigned length, const uint8_t *data)
{
  uint8_t *p = nettle_buffer_space(buffer, length);
  if (p)
    {
      memcpy(p, data, length);
      return 1;
    }
  else
    return 0;
}
