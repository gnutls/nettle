/* rc4.c
 *
 */

#include "crypto_types.h"
#include <rc4.h>

#ifdef RCSID
RCSID("$Id$");
#endif

#define SWAP(a,b) do { int _t = a; a = b; b = _t; } while(0)

void rc4_set_key(struct rc4_ctx *ctx, const UINT8 *key, UINT32 len)
{
  register UINT8 j; /* Depends on the eight-bitness of these variables. */
  unsigned i;
  UINT32 k;

  /* Initialize context */
  i = 0;
  do ctx->S[i] = i; while (++i < 256);

  /* Expand key */
  i = j = k = 0;
  do {
    j += ctx->S[i] + key[k];
    SWAP(ctx->S[i], ctx->S[j]);
    k = (k+1) % len; /* Repeat key if needed */
  } while(++i < 256);
  
  ctx->i = ctx->j = 0;
}

void rc4_crypt(struct rc4_ctx *ctx, UINT8 *dest, const UINT8 *src, UINT32 len)
{
  register UINT8 i, j;

  i = ctx->i; j = ctx->j;
  while(len--)
    {
      i++; i &= 0xff;
      j += ctx->S[i]; j &= 0xff;
      SWAP(ctx->S[i], ctx->S[j]);
      *dest++ = *src++ ^ ctx->S[ (ctx->S[i] + ctx->S[j]) & 0xff ];
    }
  ctx->i = i; ctx->j = j;
}
