/*
 * $Id$
 */

#ifndef ARCFOUR_H_INCLUDED
#define ARCFOUR_H_INCLUDED

#include "crypto_types.h"

struct arcfour_ctx {
  UINT8 S[256];
  UINT8 i, j;
};

#if 0
void arcfour_init(struct arcfour_ctx *ctx);
#endif

/* Encryption functions */
void arcfour_set_key(struct arcfour_ctx *ctx, UINT32 length, const UINT8 *key);
void arcfour_crypt(struct arcfour_ctx *ctx, UINT8 *dest,
		   UINT32 length, const UINT8 *src);

/* Using arcfour as a randomness generator. */
void arcfour_init(struct arcfour_ctx *ctx);
void arcfour_update_key(struct arcfour_ctx *ctx,
			UINT32 length, const UINT8 *key);
void arcfour_stream(struct arcfour_ctx *ctx,
		    UINT32 length, UINT8 *dest);


#endif /* ARCFOUR_H_INCLUDED */
