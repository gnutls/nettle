/* sntrup761.c

   Copyright (C) 2023 Simon Josefsson
   Copyright (C) 2026 Niels Möller

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

#include <assert.h>
#include <string.h>

#include "sntrup.h"
#include "sntrup-internal.h"
#include "sntrup761-encoding.h"

#include "bswap-internal.h"
#include "nettle-internal.h"
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
crypto_sort_uint32 (uint32_t *x, size_t n)
{
  size_t top, p, q, r, i, j;

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
	  for (j = i; j < i + p; j++)
	    uint32_MINMAX (x[j], x[j + p]);
	  i += 2 * p;
	}
      for (j = i; j < n - p; j++)
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
		j++;
		if (j == i + p)
		  {
		    i += 2 * p;
		    break;
		  }
	      }
	  while (i + p <= n - q)
	    {
	      for (j = i; j < i + p; j++)
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
	      j++;
	    }

	done:;
	}
    }
}

static uint32_t
uint32_16_divmod (uint16_t *rp, uint32_t u, uint16_t d, uint32_t dinv)
{
  uint32_t q, r, p, mask;
  q = ((uint64_t) dinv * u) >> 32;
  p = q * d;
  r = u - p; /* Interpreted as two's complement, |r| < d */
  mask = - (r >> 31);
  *rp = r + (mask & d);
  assert_maybe (*rp < d);
  return q + mask;
}

static uint16_t
uint32_16_mod (uint32_t u, uint16_t d, uint32_t dinv)
{
  uint32_t q, r, p;
  q = ((uint64_t) dinv * u) >> 32;
  p = q * d;
  r = u - p; /* Interpreted as two's complement, |r| < d */
  r += ((r >> 16) & d);
  assert_maybe ((uint16_t) r < d);
  return r;
}

void
_sntrup_decode (unsigned n, const struct sntrup_encoding_step *step,
		uint16_t *R, const uint8_t *S /* Must point at *end* of input. */)
{
  step += --n;
  assert (step->len == 2);
  {
    /* Decode first pair using M0, M1 */
    uint32_t r;
    unsigned j;

    for (r = j = 0; j < step->M1_count; j++)
      r = (r << 8) | *--S;

    r = uint32_16_divmod (&R[0], r, step->M0, step->M0_inv);
    R[1] = uint32_16_mod (r, step->M1, step->M1_inv);
  }
  while (n-- > 0)
    {
      size_t i;
      step--;
      i = step->len;
      if (i & 1)
	{
	  i--;
	  /* Copy last element */
	  R[i] = R[i / 2];
	}
      else
	{
	  /* Decode a pair using M0, M1 */
	  uint32_t r;
	  unsigned j;
	  i -= 2;
	  for (j = 0, r = R[i/2]; j < step->M1_count; j++)
	    r = (r << 8) | *--S;
	  r = uint32_16_divmod (&R[i], r, step->M0, step->M0_inv);
	  R[i+1] = uint32_16_mod (r, step->M1, step->M1_inv);
	}
      while (i > 0)
	{
	  /* Decode a pair using M0, M0 */
	  uint32_t r;
	  unsigned j;
	  i -= 2;
	  for (j = 0, r = R[i/2]; j < step->M0_count; j++)
	    r = (r << 8) | *--S;
	  r = uint32_16_divmod (&R[i], r, step->M0, step->M0_inv);
	  R[i+1] = uint32_16_mod (r, step->M0, step->M0_inv);
	}
    }
}

/* Clobbers R during encoding. */
void
_sntrup_encode (const struct sntrup_encoding_step *step,
		uint8_t *out, uint16_t *R)
{
  for (;; step++)
    {
      size_t len = step->len;
      size_t i;
      uint32_t r;

      /* Process all but the last one or two elements, based on M0, M0. */
      for (i = 0; i < len - 2; i += 2)
	{
	  unsigned j;
	  r = R[i] + R[i + 1] * step->M0;
	  for (j = 0; j < step->M0_count; j++, r >>= 8)
	    *out++ = r;
	  R[i / 2] = r;
	}

      r = R[i];
      if (i == len - 2)
	{
	  unsigned j;
	  /* Process last two elements, based on M0, M1. */
	  r += R[i + 1] * step->M0;
	  for (j = 0; j < step->M1_count; j++, r >>= 8)
	    *out++ = r;

	  if (i == 0)
	    break;
	}
      R[i / 2] = r;
    }
}

/* ----- arithmetic mod 3 */

/* Reduce input to the canonical range -1,0,1 */
int8_t
_sntrup_mod_3 (int16_t x)
{
  uint16_t ux, a, r;
  /* x is either an canonical representative of Fq, |x| <= (q-1) / 2,
     or result of polynomial multiplication in which case |x| <= 2p
     which is a smaller range. */
  assert_maybe (x <= SNTRUP761_Q12);
  assert_maybe (x >= -SNTRUP761_Q12);

  /* We want ((x + 1) mod q) - 1, but also add a multiple of 3 so we
     can use unsigned arithmetic. And (q-1)/2 happens to be a multiple
     of 3. */
  ux = x + 1 + SNTRUP761_Q12;
  /* Magic constant is ceil (2^16 / 3). */
  a = ((uint32_t) 21846 * ux) >> 16;
  r = ux - 3*a; /* Interpreted as two's complement, |r| < 3 */
  r += (r >> 14);
  assert_maybe (r < 3);
  return (int8_t) r - 1;
}

/* ----- arithmetic mod q */

/* Reduce input to the canonical range -(q-1)/2...(q-1)/2 */
int16_t
_sntrup761_mod_q (int32_t x)
{
  uint32_t ux;
  /* When called from Rq_mult_small, inputs are ideally limited to
     w*(q-1), but to allow overweight inputs and small coeffients
     premultiplied by 3, we must allow inputs up to 3*p*(q-1). When
     called from Fq_recip and Rq_recip3 inputs may be up to 2 q^2,
     which is a larger range. */
  assert_maybe (x < 2*SNTRUP761_Q * SNTRUP761_Q);
  assert_maybe (x > -2*SNTRUP761_Q * SNTRUP761_Q);
  /* We want ((x + (q-1)/2) mod q) - (q-1)/2, but also add a multiple
     of q so we can use unsigned arithmetic. */
  ux = x + SNTRUP761_Q12 + 2*SNTRUP761_Q * SNTRUP761_Q;
  /* Magic constant is ceil (2^32 / q) */
  return (int32_t) uint32_16_mod (ux, SNTRUP761_Q, 935519) - SNTRUP761_Q12;
}


/* ----- polynomials mod q */

/* h = f*g in the ring Rq. Tolerates g coeffients outside of the proper
   range, up to absolute value 3. */
void
_sntrup761_Rq_mult_small (sntrup761_Rq_t h, const sntrup761_Rq_t f, const sntrup761_R3_t g)
{
  int32_t fg[SNTRUP761_P + SNTRUP761_P - 1];
  int i, j;

  for (i = 0; i < SNTRUP761_P; i++)
    {
      int32_t result;
      for (result = 0, j = 0; j <= i; j++)
	result +=  f[j] * (int32_t) g[i - j];
      fg[i] = result;
    }
  for (i = SNTRUP761_P; i < SNTRUP761_P + SNTRUP761_P - 1; i++)
    {
      int32_t result;
      for (result = 0, j = i - SNTRUP761_P + 1; j < SNTRUP761_P; j++)
	result += f[j] * (int32_t) g[i - j];
      fg[i] = result;
    }

  for (i = SNTRUP761_P + SNTRUP761_P - 2; i >= SNTRUP761_P; --i)
    {
      fg[i - SNTRUP761_P] += fg[i];
      fg[i - SNTRUP761_P + 1] += fg[i];
    }

  for (i = 0; i < SNTRUP761_P; i++)
    /* Coeffients to be reduced are bounded by
       2*3*p*(q-1)/2 = 10478970 < q*q. */
    h[i] = _sntrup761_mod_q (fg[i]);
}

/* ----- underlying hash function */

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
  memcpy (digest, h, SNTRUP_HASH_SIZE);
}

void
_sntrup_hash_prefix (uint8_t *out, uint8_t b, size_t size, const uint8_t *in)
{
  struct sha512_ctx ctx;
  hash_init (&ctx, b);
  hash_update (&ctx, size, in);
  hash_digest (&ctx, out);
}

/* ----- session-key hash */

void
_sntrup_hash_session (uint8_t *k, uint8_t b,
		      const uint8_t y[SNTRUP761_R3_SIZE],
		      const uint8_t z[SNTRUP761_CIPHER_SIZE])
{
  struct sha512_ctx ctx;
  uint8_t x[SNTRUP_HASH_SIZE];

  _sntrup_hash_prefix (x, 3, SNTRUP761_R3_SIZE, y);
  hash_init (&ctx, b);
  hash_update (&ctx, sizeof (x), x);
  hash_update (&ctx, SNTRUP761_CIPHER_SIZE, z);
  hash_digest (&ctx, k);
}

void
_sntrup_hash_confirm (uint8_t *h, const uint8_t r[SNTRUP761_R3_SIZE],
		      const uint8_t cache[SNTRUP_HASH_SIZE])
{
  struct sha512_ctx ctx;
  uint8_t x[SNTRUP_HASH_SIZE];

  _sntrup_hash_prefix (x, 3, SNTRUP761_R3_SIZE, r);
  hash_init (&ctx, 2);
  hash_update (&ctx, sizeof (x), x);
  hash_update (&ctx, SNTRUP_HASH_SIZE, cache);
  hash_digest (&ctx, h);
}

/* ----- randomness */
uint32_t
_sntrup_urandom32 (void *random_ctx, nettle_random_func * random)
{
  union {
    uint8_t c[4];
    uint32_t i;
  } u;
  random (random_ctx, 4, u.c);
  return bswap32_if_be (u.i);
}

/* ----- sorting to generate short polynomial */
void
_sntrup761_short_random (sntrup761_R3_t out, void *random_ctx, nettle_random_func * random)
{
  uint32_t L[SNTRUP761_P];
  int i;

  for (i = 0; i < SNTRUP761_W; i++)
    /* Low two bits set randomly to 00 or 10. */
    L[i] = _sntrup_urandom32 (random_ctx, random) & ~(uint32_t) 1;
  for (; i < SNTRUP761_P; i++)
    /* Low two bits set to 01. */
    L[i] = ((_sntrup_urandom32 (random_ctx, random) & ~(uint32_t) 3)) | 1;

  crypto_sort_uint32 (L, SNTRUP761_P);

  for (i = 0; i < SNTRUP761_P; i++)
    {
      assert_maybe (i == 0 || L[i-1] <= L[i]);
      out[i] = (L[i] & 3) - 1;
    }
}

/* ----- encoding small polynomials (including short polynomials) */
void
_sntrup761_small_encode (uint8_t *s, const sntrup761_R3_t f)
{
  const int8_t *p;
  int i;

  /* Relies on SNTRUP761_P mod 4 = 1 */
  for (i = 0, p = f; i < SNTRUP761_P / 4; i++)
    {
      int8_t x;
      x = *p++ + 1;
      x += (*p++ + 1) << 2;
      x += (*p++ + 1) << 4;
      x += (*p++ + 1) << 6;
      *s++ = x;
    }
  *s = *p + 1;
}
