/*
 * $Id$
 */

#ifndef RC4_H_INCLUDED
#define RC4_H_INCLUDED

#include "crypto_types.h"

struct rc4_ctx {
  UINT8 S[256];
  UINT8 i, j;
};

#if 0
void rc4_init(struct rc4_ctx *ctx);
#endif

void rc4_set_key(struct rc4_ctx *ctx, CONST UINT8 *key, UINT32 len);
void rc4_crypt(struct rc4_ctx *ctx, UINT8 *dest, CONST UINT8 *src, UINT32 len);

#endif /* RC4_H_INCLUDED */
