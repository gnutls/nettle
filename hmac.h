/* hmac.h
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

#ifndef NETTLE_HMAC_H_INCLUDED
#define NETTLE_HMAC_H_INCLUDED

#include "nettle-meta.h"

#include <inttypes.h>

struct hmac_info
{
  /* Size of digests, both internal and the final MAC */
  unsigned digest_size;
  
  /* Internal block size */
  unsigned block_size;

  /* Size of the context struct for the underlying hash function. */
  unsigned ctx_size;
  
  /* Init function */
  void (*init)(void *ctx);

  /* Update function */
  void (*update)(void *ctx,
		 unsigned length,
		 const uint8_t *data);

  /* Digest extraction function */

  void (*digest)(void *ctx,
		 unsigned length,
		 uint8_t *digest);
};

#define _HMAC_INFO(name, NAME)
{
  NAME##_DIGEST_SIZE,
  NAME##_DATA_SIZE,
  sizeof(struct name##_ctx);

  (void (*)(void *ctx))			name##_init,
  (void (*)(void *ctx,
	    unsigned length,
	    const uint8_t *data))	name##_update,
  (void (*)(void *ctx,
	    unsigned length,
	    uint8_t *digest))		name##_digest
}

extern const struct hmac_info hmac_md5_info;
extern const struct hmac_info hmac_sha1_info;

#if 0
void
hmac_init(void *outer, void *inner, void *state,
	  struct hmac_info *info,
	  unsigned key_length, const uint8_t *key);

void
hmac_update(void *state, void (*update)(void *ctx,
					unsigned length,
					const uint8_t *data));
void
hmac_digest(void *outer, void *inner, void *state
	    struct hmac_info *info, 	    
	    unsigned length, uint8_t *dst);
#endif

void
hmac_set_key(void *outer, void *inner, void *state,
	     (void (*update)(void *ctx, 
			     unsigned length, 
			     const uint8_t *data))(update), 
	     (void (*digest)(void *ctx, 
			     unsigned length, 
			     uint8_t *digest))(digest),
	     unsigned block_size, unsigned digest_size,
	     unsigned context_size,
	     unsigned key_length, const uint8_t *key);

void
hmac_digest(void *outer, void *inner, void *state,
	    (void (*update)(void *ctx, 
			    unsigned length, 
			    const uint8_t *data))(update), 
	    (void (*digest)(void *ctx, 
			    unsigned length, 
			    uint8_t *digest))(digest),
	    unsigned digest_size,
	    unsigned context_size,
	    unsigned digest_length, uint8_t *digest);

		  
#define HMAC_CTX(type) \
{ type outer; type inner; type state; }

#define HMAC_INIT(ctx, init) \
((init)((ctx)->outer), (init)((ctx)->inner), (init)((ctx)->state))

#define HMAC_SET_KEY(ctx, update, digest, block_size, digest_size, length, key)	\
(0 ? ( (update)(ctx->outer, 0, NULL), (digest)(ctx->outer, 0, NULL))		\
   : hmac_set_key( (void *) (ctx)->outer,					\
		   (void *) (ctx)->inner,					\
		   (void *) (ctx)->state,					\
		   (void (*)(void *ctx,						\
			     unsigned length,					\
			     const uint8_t *data))(update),			\
		   (void (*)(void *ctx,						\
			     unsigned length,					\
			     uint8_t *digest))(digest),				\
		   (block_size), (digest_size),					\
		   sizeof(*(ctx)->state),					\
		   (length), (key)))

#define HMAC_UPDATE(ctx, f, length, data) \
((f)((ctx)->state, (length), (data)))

#define HMAC_DIGEST(ctx, update, digest, digest_size, length, digest)	\
(0 ? ( (update)(ctx->outer, 0, NULL), (digest)(ctx->outer, 0, NULL))	\
   : hmac_digest( (void *) (ctx)->outer,				\
		  (void *) (ctx)->inner,				\
		  (void *) (ctx)->state,				\
		  (void (*)(void *ctx,					\
			    unsigned length,				\
			    const uint8_t *data))(update),		\
		  (void (*)(void *ctx,					\
			    unsigned length,				\
			    uint8_t *digest))(digest),			\
		  (digest_size),					\
		  sizeof(*(ctx)->state),				\
		  (length), (digest)))

#if 0
#define HMAC_INIT(info, ctx, length, key)					\
  (hmac_init(									\
    (void *) ((ctx)->outer), (void *) ((ctx)->inner), (void *) ((ctx)->state),	\
    (info),									\
    (length), (key)))

#define HMAC_UPDATE(info, ctx, length, data)	\
  ((info)->update(				\
    (void *) ((ctx)->state),			\
    (length), (data)))

#define HMAC_DIGEST(info, ctx, length, digest)					\
  (hmac_digest(									\
    (void *) ((ctx)->outer), (void *) ((ctx)->inner), (void *) ((ctx)->state),	\
    (info),									\
    (length), (digest)))

#endif

#endif /* NETTLE_HMAC_H_INCLUDED */
