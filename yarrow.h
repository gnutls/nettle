/* yarrow.h
 *
 * The yarrow pseudo-randomness generator.
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
 
#ifndef NETTLE_YARROW_COMPAT_H_INCLUDED
#define NETTLE_YARROW_COMPAT_H_INCLUDED

#include "sha1.h"
#include "des.h"

enum yarrow_pool_id { YARROW_FAST = 0, YARROW_SLOW = 1 };

struct yarrow_source
{
  uint32_t estimate;
  
  /* The pool next sample should go to. */
  enum yarrow_pool_id next;
};

struct yarrow160_ctx
{
  /* Indexed by yarrow_pool_id */
  struct sha1_ctx pools[2];

  int seeded;
  
  struct des3_ctx key;
  
  unsigned nsources;
  struct yarrow_source *sources;
};

void
yarrow160_init(struct yarrow160_ctx *ctx,
	       int nsources,
	       struct yarrow_source *sources);

void
yarrow160_update(struct yarrow160_ctx *ctx,
		 unsigned source, unsigned length, const uint8_t *data);

void
yarrow160_random(struct yarrow160_ctx *ctx, unsigned length, uint8_t dst);

int
yarrow160_seeded(struct yarrow160_ctx *ctx);


#endif /* NETTLE_YARROW_COMPAT_H_INCLUDED */
