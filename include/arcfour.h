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

void arcfour_set_key(struct arcfour_ctx *ctx, const UINT8 *key, UINT32 len);
void arcfour_crypt(struct arcfour_ctx *ctx, UINT8 *dest,
		   const UINT8 *src, UINT32 len);

#endif /* ARCFOUR_H_INCLUDED */
