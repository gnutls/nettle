/* poly1305-internal.c

   Copyright: 2013 Nikos Mavrogiannopoulos
   Copyright: 2013, 2022 Niels Möller

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
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include "poly1305.h"
#include "poly1305-internal.h"

#include "macros.h"

#define M32(a,b) ((uint64_t)(a) * (b))

#define r0 r.r32[0]
#define r1 r.r32[1]
#define r2 r.r32[2]
#define r3 r.r32[3]
#define s0 r.r32[4]
#define s1 r.r32[5]
#define s2 r.r32[6]
#define s3 r.r32[7]

#define h0 h.h32[0]
#define h1 h.h32[1]
#define h2 h.h32[2]
#define h3 h.h32[3]
#define h4 h.h32[4]

void
_nettle_poly1305_set_key(struct poly1305_ctx *ctx, const uint8_t key[16])
{
  uint32_t t0, t1, t2, t3;
  t0 = LE_READ_UINT32 (key);
  t1 = LE_READ_UINT32 (key+4);
  t2 = LE_READ_UINT32 (key+8);
  t3 = LE_READ_UINT32 (key+12);

  ctx->r0 = t0 & 0x0fffffff;
  ctx->r1 = t1 & 0x0ffffffc;
  ctx->r2 = t2 & 0x0ffffffc;
  ctx->r3 = t3 & 0x0ffffffc;

  ctx->s0 = 5*ctx->r0;
  ctx->s1 = 5*(ctx->r1 >> 2);
  ctx->s2 = 5*(ctx->r2 >> 2);
  ctx->s3 = 5*(ctx->r3 >> 2);

  ctx->h0 = 0;
  ctx->h1 = 0;
  ctx->h2 = 0;
  ctx->h3 = 0;
  ctx->h4 = 0;
}

void
_nettle_poly1305_block (struct poly1305_ctx *ctx, const uint8_t *m, unsigned m128)
{
  uint32_t t0, t1, t2, t3, t4;
  uint64_t s, f0, f1, f2, f3;

  /* Add in message block */
  t0 = ctx->h0 + LE_READ_UINT32(m);
  s = (uint64_t) ctx->h1 + (t0 < ctx->h0) + LE_READ_UINT32(m+4);
  t1 = s;
  s = ctx->h2 + (s >> 32) + LE_READ_UINT32(m+8);
  t2 = s;
  s = ctx->h3 + (s >> 32) + LE_READ_UINT32(m+12);
  t3 = s;
  t4 = ctx->h4 + (s >> 32) + m128;

  /* Key constants are bounded by rk < 2^28, sk < 5*2^26, therefore
     all the fk sums fit in 64 bits without overflow, with at least
     one bit margin. */
  f0 = M32(t0, ctx->r0) + M32(t1, ctx->s3) + M32(t2, ctx->s2) + M32(t3, ctx->s1)
    + M32(t4 >> 2, ctx->s0);
  f1 = M32(t0, ctx->r1) + M32(t1, ctx->r0) + M32(t2, ctx->s3) + M32(t3, ctx->s2)
    + M32(t4, ctx->s1);
  f2 = M32(t0, ctx->r2) + M32(t1, ctx->r1) + M32(t2, ctx->r0) + M32(t3, ctx->s3)
    + M32(t4, ctx->s2);
  f3 = M32(t0, ctx->r3) + M32(t1, ctx->r2) + M32(t2, ctx->r1) + M32(t3, ctx->r0)
    + M32(t4, ctx->s3) + ((uint64_t)((t4 & 3)*ctx->r0) << 32);

  ctx->h0 = f0;
  f1 += f0 >> 32;
  ctx->h1 = f1;
  f2 += f1 >> 32;
  ctx->h2 = f2;
  f3 += f2 >> 32;
  ctx->h3 = f3;
  ctx->h4 = f3 >> 32;
}

/* Adds digest to the nonce */
void
_nettle_poly1305_digest (struct poly1305_ctx *ctx, union nettle_block16 *s)
{
  uint32_t t0, t1, t2, t3, t4, c0, c1, c2, c3, mask;
  uint64_t f0, f1, f2;

  t0 = ctx->h0;
  t1 = ctx->h1;
  t2 = ctx->h2;
  t3 = ctx->h3;
  t4 = ctx->h4;

  /* Fold high part of t4 */
  c0 = 5 * (t4 >> 2);
  t4 &= 3;
  t0 += c0; c1 = (t0 < c0);
  t1 += c1; c2 = (t1 < c1);
  t2 += c2; c3 = (t2 < c2);
  t3 += c3;
  t4 += (t3 < c3);

  /* Compute resulting carries when adding 5. */
  c1 = (t0 >= 0xfffffffb);
  c2 = (t1 + c1 < c1);
  c3 = (t2 + c2 < t2);
  t4 += (t3 + c3 < t3);

  /* Set if H >= 2^130 - 5 */
  mask = - (t4 >> 2);

  t0 += mask & 5;
  t1 += mask & c1;
  t2 += mask & c2;
  t3 += mask & c3;

  /* FIXME: Take advantage of s being aligned as an unsigned long. */
  f0 = (uint64_t) t0 + LE_READ_UINT32(s->b);
  f1 = t1 + (f0 >> 32) + LE_READ_UINT32(s->b+4);
  f2 = t2 + (f1 >> 32) + LE_READ_UINT32(s->b+8);
  t3 += (f2 >> 32) + LE_READ_UINT32(s->b+12);

  LE_WRITE_UINT32(s->b, f0);
  LE_WRITE_UINT32(s->b+4, f1);
  LE_WRITE_UINT32(s->b+8, f2);
  LE_WRITE_UINT32(s->b+12, t3);

  ctx->h0 = 0;
  ctx->h1 = 0;
  ctx->h2 = 0;
  ctx->h3 = 0;
  ctx->h4 = 0;
}
