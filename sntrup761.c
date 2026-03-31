/* sntrup761.c

   Copyright (C) 2023 Simon Josefsson

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

/*
 * Derived from public domain source, written by (in alphabetical order):
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "sntrup761.h"

#include "sha2.h"

#define uint32_MINMAX(a,b) \
do { \
  uint64_t d = (uint64_t)b - (uint64_t)a; \
  uint32_t masked_d = (d >> 32) & d; \
  a += masked_d; \
  b -= masked_d; \
} while(0)

/* Based on supercop-20201130/crypto_sort/int32/portable4/sort.c, but
   using uint32_t rather than int32_t. */
static void
crypto_sort_uint32 (uint32_t *x, long long n)
{
  long long top, p, q, r, i, j;

  if (n < 2)
    return;
  top = 1;
  while (top < n - top)
    top += top;

  for (p = top; p >= 1; p >>= 1)
    {
      i = 0;
      while (i + 2 * p <= n)
	{
	  for (j = i; j < i + p; ++j)
	    uint32_MINMAX (x[j], x[j + p]);
	  i += 2 * p;
	}
      for (j = i; j < n - p; ++j)
	uint32_MINMAX (x[j], x[j + p]);

      i = 0;
      j = 0;
      for (q = top; q > p; q >>= 1)
	{
	  if (j != i)
	    for (;;)
	      {
		if (j == n - q)
		  goto done;
		uint32_t a = x[j + p];
		for (r = q; r > p; r >>= 1)
		  uint32_MINMAX (a, x[j + r]);
		x[j + p] = a;
		++j;
		if (j == i + p)
		  {
		    i += 2 * p;
		    break;
		  }
	      }
	  while (i + p <= n - q)
	    {
	      for (j = i; j < i + p; ++j)
		{
		  uint32_t a = x[j + p];
		  for (r = q; r > p; r >>= 1)
		    uint32_MINMAX (a, x[j + r]);
		  x[j + p] = a;
		}
	      i += 2 * p;
	    }
	  /* now i + p > n - q */
	  j = i;
	  while (j < n - q)
	    {
	      uint32_t a = x[j + p];
	      for (r = q; r > p; r >>= 1)
		uint32_MINMAX (a, x[j + r]);
	      x[j + p] = a;
	      ++j;
	    }

	done:;
	}
    }
}

/* from supercop-20201130/crypto_kem/sntrup761/ref/uint32.c */

/*
CPU division instruction typically takes time depending on x.
This software is designed to take time independent of x.
Time still varies depending on m; user must ensure that m is constant.
Time also varies on CPUs where multiplication is variable-time.
There could be more CPU issues.
There could also be compiler issues.
*/

static void
uint32_divmod_uint14 (uint32_t * q, uint16_t * r, uint32_t x, uint16_t m)
{
  uint32_t v = 0x80000000;
  uint32_t qpart;
  uint32_t mask;

  v /= m;

  /* caller guarantees m > 0 */
  /* caller guarantees m < 16384 */
  /* vm <= 2^31 <= vm+m-1 */
  /* xvm <= 2^31 x <= xvm+x(m-1) */

  *q = 0;

  qpart = (x * (uint64_t) v) >> 31;
  /* 2^31 qpart <= xv <= 2^31 qpart + 2^31-1 */
  /* 2^31 qpart m <= xvm <= 2^31 qpart m + (2^31-1)m */
  /* 2^31 qpart m <= 2^31 x <= 2^31 qpart m + (2^31-1)m + x(m-1) */
  /* 0 <= 2^31 newx <= (2^31-1)m + x(m-1) */
  /* 0 <= newx <= (1-1/2^31)m + x(m-1)/2^31 */
  /* 0 <= newx <= (1-1/2^31)(2^14-1) + (2^32-1)((2^14-1)-1)/2^31 */

  x -= qpart * m;
  *q += qpart;
  /* x <= 49146 */

  qpart = (x * (uint64_t) v) >> 31;
  /* 0 <= newx <= (1-1/2^31)m + x(m-1)/2^31 */
  /* 0 <= newx <= m + 49146(2^14-1)/2^31 */
  /* 0 <= newx <= m + 0.4 */
  /* 0 <= newx <= m */

  x -= qpart * m;
  *q += qpart;
  /* x <= m */

  x -= m;
  *q += 1;
  mask = -(x >> 31);
  x += mask & (uint32_t) m;
  *q += mask;
  /* x < m */

  *r = x;
}


static uint16_t
uint32_mod_uint14 (uint32_t x, uint16_t m)
{
  uint32_t q;
  uint16_t r;
  uint32_divmod_uint14 (&q, &r, x, m);
  return r;
}

/* from supercop-20201130/crypto_kem/sntrup761/ref/int32.c */

static void
int32_divmod_uint14 (int32_t * q, uint16_t * r, int32_t x, uint16_t m)
{
  uint32_t uq, uq2;
  uint16_t ur, ur2;
  uint32_t mask;

  uint32_divmod_uint14 (&uq, &ur, 0x80000000 + (uint32_t) x, m);
  uint32_divmod_uint14 (&uq2, &ur2, 0x80000000, m);
  ur -= ur2;
  uq -= uq2;
  mask = -(uint32_t) (ur >> 15);
  ur += mask & m;
  uq += mask;
  *r = ur;
  *q = uq;
}


static uint16_t
int32_mod_uint14 (int32_t x, uint16_t m)
{
  int32_t q;
  uint16_t r;
  int32_divmod_uint14 (&q, &r, x, m);
  return r;
}

/* from supercop-20201130/crypto_kem/sntrup761/ref/paramsmenu.h */
#define SNTRUP761_P 761
#define SNTRUP761_Q 4591
#define Rounded_bytes 1007
#define SNTRUP761_W 286

/* from supercop-20201130/crypto_kem/sntrup761/ref/Decode.h */

/* Decode(R,s,M,len) */
/* assumes 0 < M[i] < 16384 */
/* produces 0 <= R[i] < M[i] */

/* from supercop-20201130/crypto_kem/sntrup761/ref/Decode.c */

static void
Decode (uint16_t * out, const uint8_t *S, const uint16_t * M,
	long long len)
{
  if (len == 1)
    {
      if (M[0] == 1)
	*out = 0;
      else if (M[0] <= 256)
	*out = uint32_mod_uint14 (S[0], M[0]);
      else
	*out = uint32_mod_uint14 (S[0] + (((uint16_t) S[1]) << 8), M[0]);
    }
  if (len > 1)
    {
      uint16_t R2[(len + 1) / 2];
      uint16_t M2[(len + 1) / 2];
      uint16_t bottomr[len / 2];
      uint32_t bottomt[len / 2];
      long long i;
      for (i = 0; i < len - 1; i += 2)
	{
	  uint32_t m = M[i] * (uint32_t) M[i + 1];
	  if (m > 256 * 16383)
	    {
	      bottomt[i / 2] = 256 * 256;
	      bottomr[i / 2] = S[0] + 256 * S[1];
	      S += 2;
	      M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
	    }
	  else if (m >= 16384)
	    {
	      bottomt[i / 2] = 256;
	      bottomr[i / 2] = S[0];
	      S += 1;
	      M2[i / 2] = (m + 255) >> 8;
	    }
	  else
	    {
	      bottomt[i / 2] = 1;
	      bottomr[i / 2] = 0;
	      M2[i / 2] = m;
	    }
	}
      if (i < len)
	M2[i / 2] = M[i];
      Decode (R2, S, M2, (len + 1) / 2);
      for (i = 0; i < len - 1; i += 2)
	{
	  uint32_t r = bottomr[i / 2];
	  uint32_t r1;
	  uint16_t r0;
	  r += bottomt[i / 2] * R2[i / 2];
	  uint32_divmod_uint14 (&r1, &r0, r, M[i]);
	  r1 = uint32_mod_uint14 (r1, M[i + 1]);	/* only needed for invalid inputs */
	  *out++ = r0;
	  *out++ = r1;
	}
      if (i < len)
	*out++ = R2[i / 2];
    }
}

/* from supercop-20201130/crypto_kem/sntrup761/ref/Encode.h */

/* Encode(s,R,M,len) */
/* assumes 0 <= R[i] < M[i] < 16384 */

/* from supercop-20201130/crypto_kem/sntrup761/ref/Encode.c */

/* 0 <= R[i] < M[i] < 16384 */
static void
Encode (uint8_t *out, const uint16_t * R, const uint16_t * M,
	long long len)
{
  if (len == 1)
    {
      uint16_t r = R[0];
      uint16_t m = M[0];
      while (m > 1)
	{
	  *out++ = r;
	  r >>= 8;
	  m = (m + 255) >> 8;
	}
    }
  if (len > 1)
    {
      uint16_t R2[(len + 1) / 2];
      uint16_t M2[(len + 1) / 2];
      long long i;
      for (i = 0; i < len - 1; i += 2)
	{
	  uint32_t m0 = M[i];
	  uint32_t r = R[i] + R[i + 1] * m0;
	  uint32_t m = M[i + 1] * m0;
	  while (m >= 16384)
	    {
	      *out++ = r;
	      r >>= 8;
	      m = (m + 255) >> 8;
	    }
	  R2[i / 2] = r;
	  M2[i / 2] = m;
	}
      if (i < len)
	{
	  R2[i / 2] = R[i];
	  M2[i / 2] = M[i];
	}
      Encode (out, R2, M2, (len + 1) / 2);
    }
}

/* from supercop-20201130/crypto_kem/sntrup761/ref/kem.c */

/* ----- masks */

/* return -1 if x!=0; else return 0 */
static int
int16_t_nonzero_mask (int16_t x)
{
  uint16_t u = x;		/* 0, else 1...65535 */
  uint32_t v = u;		/* 0, else 1...65535 */
  v = -v;			/* 0, else 2^32-65535...2^32-1 */
  v >>= 31;			/* 0, else 1 */
  return -v;			/* 0, else -1 */
}

/* return -1 if x<0; otherwise return 0 */
static int
int16_t_negative_mask (int16_t x)
{
  uint16_t u = x;
  u >>= 15;
  return -(int) u;
  /* alternative with gcc -fwrapv: */
  /* x>>15 compiles to CPU's arithmetic right shift */
}

/* ----- arithmetic mod 3 */

typedef int8_t small;

/* F3 is always represented as -1,0,1 */
/* so ZZ_fromF3 is a no-op */

/* x must not be close to top int16_t */
static small
F3_freeze (int16_t x)
{
  return int32_mod_uint14 (x + 1, 3) - 1;
}

/* ----- arithmetic mod q */

#define SNTRUP761_Q12 ((SNTRUP761_Q-1)/2)
typedef int16_t Fq;
/* always represented as -(q-1)/2...(q-1)/2 */
/* so ZZ_fromFq is a no-op */

/* x must not be close to top int32 */
static Fq
Fq_freeze (int32_t x)
{
  return int32_mod_uint14 (x + SNTRUP761_Q12, SNTRUP761_Q) - SNTRUP761_Q12;
}

static Fq
Fq_recip (Fq a1)
{
  int i = 1;
  Fq ai = a1;

  while (i < SNTRUP761_Q - 2)
    {
      ai = Fq_freeze (a1 * (int32_t) ai);
      i += 1;
    }
  return ai;
}

/* ----- small polynomials */

/* 0 if Weightw_is(r), else -1 */
static int
Weightw_mask (small * r)
{
  int weight = 0;
  int i;

  for (i = 0; i < SNTRUP761_P; ++i)
    weight += r[i] & 1;
  return int16_t_nonzero_mask (weight - SNTRUP761_W);
}

/* R3_fromR(R_fromRq(r)) */
static void
R3_fromRq (small * out, const Fq * r)
{
  int i;
  for (i = 0; i < SNTRUP761_P; ++i)
    out[i] = F3_freeze (r[i]);
}

/* h = f*g in the ring R3 */
static void
R3_mult (small * h, const small * f, const small * g)
{
  small fg[SNTRUP761_P + SNTRUP761_P - 1];
  small result;
  int i, j;

  for (i = 0; i < SNTRUP761_P; ++i)
    {
      result = 0;
      for (j = 0; j <= i; ++j)
	result = F3_freeze (result + f[j] * g[i - j]);
      fg[i] = result;
    }
  for (i = SNTRUP761_P; i < SNTRUP761_P + SNTRUP761_P - 1; ++i)
    {
      result = 0;
      for (j = i - SNTRUP761_P + 1; j < SNTRUP761_P; ++j)
	result = F3_freeze (result + f[j] * g[i - j]);
      fg[i] = result;
    }

  for (i = SNTRUP761_P + SNTRUP761_P - 2; i >= SNTRUP761_P; --i)
    {
      fg[i - SNTRUP761_P] = F3_freeze (fg[i - SNTRUP761_P] + fg[i]);
      fg[i - SNTRUP761_P + 1] = F3_freeze (fg[i - SNTRUP761_P + 1] + fg[i]);
    }

  for (i = 0; i < SNTRUP761_P; ++i)
    h[i] = fg[i];
}

/* returns 0 if recip succeeded; else -1 */
static int
R3_recip (small * out, const small * in)
{
  small f[SNTRUP761_P + 1], g[SNTRUP761_P + 1], v[SNTRUP761_P + 1], r[SNTRUP761_P + 1];
  int i, loop, delta;
  int sign, swap, t;

  for (i = 0; i < SNTRUP761_P + 1; ++i)
    v[i] = 0;
  for (i = 0; i < SNTRUP761_P + 1; ++i)
    r[i] = 0;
  r[0] = 1;
  for (i = 0; i < SNTRUP761_P; ++i)
    f[i] = 0;
  f[0] = 1;
  f[SNTRUP761_P - 1] = f[SNTRUP761_P] = -1;
  for (i = 0; i < SNTRUP761_P; ++i)
    g[SNTRUP761_P - 1 - i] = in[i];
  g[SNTRUP761_P] = 0;

  delta = 1;

  for (loop = 0; loop < 2 * SNTRUP761_P - 1; ++loop)
    {
      for (i = SNTRUP761_P; i > 0; --i)
	v[i] = v[i - 1];
      v[0] = 0;

      sign = -g[0] * f[0];
      swap = int16_t_negative_mask (-delta) & int16_t_nonzero_mask (g[0]);
      delta ^= swap & (delta ^ -delta);
      delta += 1;

      for (i = 0; i < SNTRUP761_P + 1; ++i)
	{
	  t = swap & (f[i] ^ g[i]);
	  f[i] ^= t;
	  g[i] ^= t;
	  t = swap & (v[i] ^ r[i]);
	  v[i] ^= t;
	  r[i] ^= t;
	}

      for (i = 0; i < SNTRUP761_P + 1; ++i)
	g[i] = F3_freeze (g[i] + sign * f[i]);
      for (i = 0; i < SNTRUP761_P + 1; ++i)
	r[i] = F3_freeze (r[i] + sign * v[i]);

      for (i = 0; i < SNTRUP761_P; ++i)
	g[i] = g[i + 1];
      g[SNTRUP761_P] = 0;
    }

  sign = f[0];
  for (i = 0; i < SNTRUP761_P; ++i)
    out[i] = sign * v[SNTRUP761_P - 1 - i];

  return int16_t_nonzero_mask (delta);
}

/* ----- polynomials mod q */

/* h = f*g in the ring Rq */
static void
Rq_mult_small (Fq * h, const Fq * f, const small * g)
{
  Fq fg[SNTRUP761_P + SNTRUP761_P - 1];
  Fq result;
  int i, j;

  for (i = 0; i < SNTRUP761_P; ++i)
    {
      result = 0;
      for (j = 0; j <= i; ++j)
	result = Fq_freeze (result + f[j] * (int32_t) g[i - j]);
      fg[i] = result;
    }
  for (i = SNTRUP761_P; i < SNTRUP761_P + SNTRUP761_P - 1; ++i)
    {
      result = 0;
      for (j = i - SNTRUP761_P + 1; j < SNTRUP761_P; ++j)
	result = Fq_freeze (result + f[j] * (int32_t) g[i - j]);
      fg[i] = result;
    }

  for (i = SNTRUP761_P + SNTRUP761_P - 2; i >= SNTRUP761_P; --i)
    {
      fg[i - SNTRUP761_P] = Fq_freeze (fg[i - SNTRUP761_P] + fg[i]);
      fg[i - SNTRUP761_P + 1] = Fq_freeze (fg[i - SNTRUP761_P + 1] + fg[i]);
    }

  for (i = 0; i < SNTRUP761_P; ++i)
    h[i] = fg[i];
}

/* h = 3f in Rq */
static void
Rq_mult3 (Fq * h, const Fq * f)
{
  int i;

  for (i = 0; i < SNTRUP761_P; ++i)
    h[i] = Fq_freeze (3 * f[i]);
}

/* out = 1/(3*in) in Rq */
/* returns 0 if recip succeeded; else -1 */
static int
Rq_recip3 (Fq * out, const small * in)
{
  Fq f[SNTRUP761_P + 1], g[SNTRUP761_P + 1], v[SNTRUP761_P + 1], r[SNTRUP761_P + 1];
  int i, loop, delta;
  int swap, t;
  int32_t f0, g0;
  Fq scale;

  for (i = 0; i < SNTRUP761_P + 1; ++i)
    v[i] = 0;
  for (i = 0; i < SNTRUP761_P + 1; ++i)
    r[i] = 0;
  r[0] = Fq_recip (3);
  for (i = 0; i < SNTRUP761_P; ++i)
    f[i] = 0;
  f[0] = 1;
  f[SNTRUP761_P - 1] = f[SNTRUP761_P] = -1;
  for (i = 0; i < SNTRUP761_P; ++i)
    g[SNTRUP761_P - 1 - i] = in[i];
  g[SNTRUP761_P] = 0;

  delta = 1;

  for (loop = 0; loop < 2 * SNTRUP761_P - 1; ++loop)
    {
      for (i = SNTRUP761_P; i > 0; --i)
	v[i] = v[i - 1];
      v[0] = 0;

      swap = int16_t_negative_mask (-delta) & int16_t_nonzero_mask (g[0]);
      delta ^= swap & (delta ^ -delta);
      delta += 1;

      for (i = 0; i < SNTRUP761_P + 1; ++i)
	{
	  t = swap & (f[i] ^ g[i]);
	  f[i] ^= t;
	  g[i] ^= t;
	  t = swap & (v[i] ^ r[i]);
	  v[i] ^= t;
	  r[i] ^= t;
	}

      f0 = f[0];
      g0 = g[0];
      for (i = 0; i < SNTRUP761_P + 1; ++i)
	g[i] = Fq_freeze (f0 * g[i] - g0 * f[i]);
      for (i = 0; i < SNTRUP761_P + 1; ++i)
	r[i] = Fq_freeze (f0 * r[i] - g0 * v[i]);

      for (i = 0; i < SNTRUP761_P; ++i)
	g[i] = g[i + 1];
      g[SNTRUP761_P] = 0;
    }

  scale = Fq_recip (f[0]);
  for (i = 0; i < SNTRUP761_P; ++i)
    out[i] = Fq_freeze (scale * (int32_t) v[SNTRUP761_P - 1 - i]);

  return int16_t_nonzero_mask (delta);
}

/* ----- rounded polynomials mod q */

static void
Round (Fq * out, const Fq * a)
{
  int i;
  for (i = 0; i < SNTRUP761_P; ++i)
    out[i] = a[i] - F3_freeze (a[i]);
}

/* ----- sorting to generate short polynomial */

static void
Short_fromlist (small * out, const uint32_t * in)
{
  uint32_t L[SNTRUP761_P];
  int i;

  for (i = 0; i < SNTRUP761_W; ++i)
    L[i] = in[i] & (uint32_t) - 2;
  for (i = SNTRUP761_W; i < SNTRUP761_P; ++i)
    L[i] = (in[i] & (uint32_t) - 3) | 1;
  crypto_sort_uint32 (L, SNTRUP761_P);
  for (i = 0; i < SNTRUP761_P; ++i)
    out[i] = (L[i] & 3) - 1;
}

/* ----- underlying hash function */

#define HASH_SIZE 32

/* e.g., b = 0 means out = Hash0(in) */
static void
hash_init (struct sha512_ctx *ctx, uint8_t b)
{
  sha512_init (ctx);
  sha512_update (ctx, 1, &b);
}
#define hash_update sha512_update

static void
hash_digest (struct sha512_ctx *ctx, uint8_t *digest)
{
  uint8_t h[SHA512_DIGEST_SIZE];
  sha512_digest (ctx, h);
  memcpy (digest, h, HASH_SIZE);
}

static void
Hash_prefix (uint8_t *out, uint8_t b, const uint8_t *in, int inlen)
{
  struct sha512_ctx ctx;
  hash_init (&ctx, b);
  hash_update (&ctx, inlen, in);
  hash_digest (&ctx, out);
}

/* ----- higher-level randomness */

static uint32_t
urandom32 (void *random_ctx, nettle_random_func * random)
{
  uint8_t c[4];
  uint32_t out[4];

  random (random_ctx, 4, c);
  out[0] = (uint32_t) c[0];
  out[1] = ((uint32_t) c[1]) << 8;
  out[2] = ((uint32_t) c[2]) << 16;
  out[3] = ((uint32_t) c[3]) << 24;
  return out[0] + out[1] + out[2] + out[3];
}

static void
Short_random (small * out, void *random_ctx, nettle_random_func * random)
{
  uint32_t L[SNTRUP761_P];
  int i;

  for (i = 0; i < SNTRUP761_P; ++i)
    L[i] = urandom32 (random_ctx, random);
  Short_fromlist (out, L);
}

static void
Small_random (small * out, void *random_ctx, nettle_random_func * random)
{
  int i;

  for (i = 0; i < SNTRUP761_P; ++i)
    out[i] = (((urandom32 (random_ctx, random) & 0x3fffffff) * 3) >> 30) - 1;
}

/* ----- Streamlined NTRU Prime Core */

/* h,(f,ginv) = KeyGen() */
static void
KeyGen (Fq * h, small * f, small * ginv, void *random_ctx,
	nettle_random_func * random)
{
  small g[SNTRUP761_P];
  Fq finv[SNTRUP761_P];

  for (;;)
    {
      Small_random (g, random_ctx, random);
      if (R3_recip (ginv, g) == 0)
	break;
    }
  Short_random (f, random_ctx, random);
  Rq_recip3 (finv, f);		/* always works */
  Rq_mult_small (h, finv, g);
}

/* c = Encrypt(r,h) */
static void
Encrypt (Fq * c, const small * r, const Fq * h)
{
  Fq hr[SNTRUP761_P];

  Rq_mult_small (hr, h, r);
  Round (c, hr);
}

/* r = Decrypt(c,(f,ginv)) */
static void
Decrypt (small * r, const Fq * c, const small * f, const small * ginv)
{
  Fq cf[SNTRUP761_P];
  Fq cf3[SNTRUP761_P];
  small e[SNTRUP761_P];
  small ev[SNTRUP761_P];
  int mask;
  int i;

  Rq_mult_small (cf, c, f);
  Rq_mult3 (cf3, cf);
  R3_fromRq (e, cf3);
  R3_mult (ev, e, ginv);

  mask = Weightw_mask (ev);	/* 0 if weight SNTRUP761_W, else -1 */
  for (i = 0; i < SNTRUP761_W; ++i)
    r[i] = ((ev[i] ^ 1) & ~mask) ^ 1;
  for (i = SNTRUP761_W; i < SNTRUP761_P; ++i)
    r[i] = ev[i] & ~mask;
}

/* ----- encoding small polynomials (including short polynomials) */

#define Small_bytes ((SNTRUP761_P+3)/4)

/* these are the only functions that rely on SNTRUP761_P mod 4 = 1 */

static void
Small_encode (uint8_t *s, const small * f)
{
  small x;
  int i;

  for (i = 0; i < SNTRUP761_P / 4; ++i)
    {
      x = *f++ + 1;
      x += (*f++ + 1) << 2;
      x += (*f++ + 1) << 4;
      x += (*f++ + 1) << 6;
      *s++ = x;
    }
  x = *f++ + 1;
  *s++ = x;
}

static void
Small_decode (small * f, const uint8_t *s)
{
  uint8_t x;
  int i;

  for (i = 0; i < SNTRUP761_P / 4; ++i)
    {
      x = *s++;
      *f++ = ((small) (x & 3)) - 1;
      x >>= 2;
      *f++ = ((small) (x & 3)) - 1;
      x >>= 2;
      *f++ = ((small) (x & 3)) - 1;
      x >>= 2;
      *f++ = ((small) (x & 3)) - 1;
    }
  x = *s++;
  *f++ = ((small) (x & 3)) - 1;
}

/* ----- encoding general polynomials */

static void
Rq_encode (uint8_t *s, const Fq * r)
{
  uint16_t R[SNTRUP761_P], M[SNTRUP761_P];
  int i;

  for (i = 0; i < SNTRUP761_P; ++i)
    R[i] = r[i] + SNTRUP761_Q12;
  for (i = 0; i < SNTRUP761_P; ++i)
    M[i] = SNTRUP761_Q;
  Encode (s, R, M, SNTRUP761_P);
}

static void
Rq_decode (Fq * r, const uint8_t *s)
{
  uint16_t R[SNTRUP761_P], M[SNTRUP761_P];
  int i;

  for (i = 0; i < SNTRUP761_P; ++i)
    M[i] = SNTRUP761_Q;
  Decode (R, s, M, SNTRUP761_P);
  for (i = 0; i < SNTRUP761_P; ++i)
    r[i] = ((Fq) R[i]) - SNTRUP761_Q12;
}

/* ----- encoding rounded polynomials */

static void
Rounded_encode (uint8_t *s, const Fq * r)
{
  uint16_t R[SNTRUP761_P], M[SNTRUP761_P];
  int i;

  for (i = 0; i < SNTRUP761_P; ++i)
    R[i] = ((r[i] + SNTRUP761_Q12) * 10923) >> 15;
  for (i = 0; i < SNTRUP761_P; ++i)
    M[i] = (SNTRUP761_Q + 2) / 3;
  Encode (s, R, M, SNTRUP761_P);
}

static void
Rounded_decode (Fq * r, const uint8_t *s)
{
  uint16_t R[SNTRUP761_P], M[SNTRUP761_P];
  int i;

  for (i = 0; i < SNTRUP761_P; ++i)
    M[i] = (SNTRUP761_Q + 2) / 3;
  Decode (R, s, M, SNTRUP761_P);
  for (i = 0; i < SNTRUP761_P; ++i)
    r[i] = R[i] * 3 - SNTRUP761_Q12;
}

/* ----- Streamlined NTRU Prime Core plus encoding */

typedef small Inputs[SNTRUP761_P];	/* passed by reference */
#define Inputs_random Short_random
#define Inputs_encode Small_encode
#define Inputs_bytes Small_bytes

#define Ciphertexts_bytes Rounded_bytes
#define SecretKeys_bytes (2*Small_bytes)

/* pk,sk = ZKeyGen() */
static void
ZKeyGen (uint8_t *pk, uint8_t *sk, void *random_ctx,
	 nettle_random_func * random)
{
  Fq h[SNTRUP761_P];
  small f[SNTRUP761_P], v[SNTRUP761_P];

  KeyGen (h, f, v, random_ctx, random);
  Rq_encode (pk, h);
  Small_encode (sk, f);
  sk += Small_bytes;
  Small_encode (sk, v);
}

/* C = ZEncrypt(r,pk) */
static void
ZEncrypt (uint8_t *C, const Inputs r, const uint8_t *pk)
{
  Fq h[SNTRUP761_P];
  Fq c[SNTRUP761_P];
  Rq_decode (h, pk);
  Encrypt (c, r, h);
  Rounded_encode (C, c);
}

/* r = ZDecrypt(C,sk) */
static void
ZDecrypt (Inputs r, const uint8_t *C, const uint8_t *sk)
{
  small f[SNTRUP761_P], v[SNTRUP761_P];
  Fq c[SNTRUP761_P];

  Small_decode (f, sk);
  sk += Small_bytes;
  Small_decode (v, sk);
  Rounded_decode (c, C);
  Decrypt (r, c, f, v);
}

/* ----- confirmation hash */

#define Confirm_bytes 32

/* h = HashConfirm(r,pk,cache); cache is Hash4(pk) */
static void
HashConfirm (uint8_t *h, const uint8_t *r,
	     /* const uint8_t *pk, */ const uint8_t *cache)
{
  struct sha512_ctx ctx;
  uint8_t x[HASH_SIZE];

  Hash_prefix (x, 3, r, Inputs_bytes);
  hash_init (&ctx, 2);
  hash_update (&ctx, sizeof (x), x);
  hash_update (&ctx, HASH_SIZE, cache);
  hash_digest (&ctx, h);
}

/* ----- session-key hash */

/* k = HashSession(b,y,z) */
static void
HashSession (uint8_t *k, uint8_t b, const uint8_t *y,
	     const uint8_t *z)
{
  struct sha512_ctx ctx;
  uint8_t x[HASH_SIZE];

  Hash_prefix (x, 3, y, Inputs_bytes);
  hash_init (&ctx, b);
  hash_update (&ctx, sizeof (x), x);
  hash_update (&ctx, Ciphertexts_bytes + Confirm_bytes, z);
  hash_digest (&ctx, k);
}

/* ----- Streamlined NTRU Prime */

/* pk,sk = KEM_KeyGen() */
void
sntrup761_keypair (uint8_t *pk, uint8_t *sk, void *random_ctx,
		   nettle_random_func * random)
{
  int i;

  ZKeyGen (pk, sk, random_ctx, random);
  sk += SecretKeys_bytes;
  for (i = 0; i < SNTRUP761_PUBLICKEY_SIZE; ++i)
    *sk++ = pk[i];
  random (random_ctx, Inputs_bytes, sk);
  sk += Inputs_bytes;
  Hash_prefix (sk, 4, pk, SNTRUP761_PUBLICKEY_SIZE);
}

/* c,r_enc = Hide(r,pk,cache); cache is Hash4(pk) */
static void
Hide (uint8_t *c, uint8_t *r_enc, const Inputs r,
      const uint8_t *pk, const uint8_t *cache)
{
  Inputs_encode (r_enc, r);
  ZEncrypt (c, r, pk);
  c += Ciphertexts_bytes;
  HashConfirm (c, r_enc, cache);
}

/* c,k = Encap(pk) */
void
sntrup761_enc (uint8_t *c, uint8_t *k, const uint8_t *pk,
	       void *random_ctx, nettle_random_func * random)
{
  Inputs r;
  uint8_t r_enc[Inputs_bytes];
  uint8_t cache[HASH_SIZE];

  Hash_prefix (cache, 4, pk, SNTRUP761_PUBLICKEY_SIZE);
  Inputs_random (r, random_ctx, random);
  Hide (c, r_enc, r, pk, cache);
  HashSession (k, 1, r_enc, c);
}

/* 0 if matching ciphertext+confirm, else -1 */
static int
Ciphertexts_diff_mask (const uint8_t *c, const uint8_t *c2)
{
  uint16_t differentbits = 0;
  int len = Ciphertexts_bytes + Confirm_bytes;

  while (len-- > 0)
    differentbits |= (*c++) ^ (*c2++);
  return (1 & ((differentbits - 1) >> 8)) - 1;
}

/* k = Decap(c,sk) */
void
sntrup761_dec (uint8_t *k, const uint8_t *c, const uint8_t *sk)
{
  const uint8_t *pk = sk + SecretKeys_bytes;
  const uint8_t *rho = pk + SNTRUP761_PUBLICKEY_SIZE;
  const uint8_t *cache = rho + Inputs_bytes;
  Inputs r;
  uint8_t r_enc[Inputs_bytes];
  uint8_t cnew[Ciphertexts_bytes + Confirm_bytes];
  int mask;
  int i;

  ZDecrypt (r, c, sk);
  Hide (cnew, r_enc, r, pk, cache);
  mask = Ciphertexts_diff_mask (c, cnew);
  for (i = 0; i < Inputs_bytes; ++i)
    r_enc[i] ^= mask & (r_enc[i] ^ rho[i]);
  HashSession (k, 1 + mask, r_enc, c);
}
