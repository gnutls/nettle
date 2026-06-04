/* sntrup761-keygen.c

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

#include "nettle-internal.h"

static void
R3_random (sntrup761_R3_t out, void *random_ctx, nettle_random_func * random)
{
  int i;

  for (i = 0; i < SNTRUP761_P; ++i)
    out[i] = (((_sntrup_urandom32 (random_ctx, random) & 0x3fffffff) * 3) >> 30) - 1;
}

/* Returns non-canonical representation, 0 <= r < 2q */
static uint16_t
mod_q_appr (uint32_t u)
{
  uint32_t a, r, p;
  /* Magic constant is ceil (2^32 / q) */
  a = ((uint64_t) 935519 * u) >> 32;
  p = a * SNTRUP761_Q;
  r = SNTRUP761_Q + u - p;
  assert_maybe (r < 2*SNTRUP761_Q);
  return r;
}

static int16_t
Fq_recip (int16_t a)
{
  int16_t x;
  uint16_t ua, ux;
  ua = a + SNTRUP761_Q;
  ux = mod_q_appr ((uint32_t) ua * ua); /* a^2 */
  ux = mod_q_appr ((uint32_t) ux * ux); /* a^4 */
  ux = mod_q_appr ((uint32_t) ux * ux); /* a^8 */
  ux = mod_q_appr ((uint32_t) ux * ux); /* a^16 */
  ux = mod_q_appr ((uint32_t) ux * ua); /* a^17 */
  ux = mod_q_appr ((uint32_t) ux * ux); /* a^34 */
  ux = mod_q_appr ((uint32_t) ux * ua); /* a^35 */
  ux = mod_q_appr ((uint32_t) ux * ux); /* a^70 */
  ux = mod_q_appr ((uint32_t) ux * ua); /* a^71 */
  ux = mod_q_appr ((uint32_t) ux * ux); /* a^142 */
  ux = mod_q_appr ((uint32_t) ux * ua); /* a^143 */
  ux = mod_q_appr ((uint32_t) ux * ux); /* a^286 */
  ux = mod_q_appr ((uint32_t) ux * ux); /* a^572 */
  ux = mod_q_appr ((uint32_t) ux * ua); /* a^573 */
  ux = mod_q_appr ((uint32_t) ux * ux); /* a^1146 */
  ux = mod_q_appr ((uint32_t) ux * ua); /* a^1147 */
  ux = mod_q_appr ((uint32_t) ux * ux); /* a^2294 */
  ux = mod_q_appr ((uint32_t) ux * ux); /* a^4588 */
  x = _sntrup761_mod_q ((int32_t) ux * a); /* a^4589 = a^(q-2) */
  assert_maybe (_sntrup761_mod_q ((int32_t) x * a) == 1);
  return x;
}

/* returns 1 if recip succeeded; else 0 */
static int
R3_recip (sntrup761_R3_t out, const sntrup761_R3_t in)
{
  /* Working polynomials have non-canonical coefficients. After 8
     iterations, coefficients may grow up to size fibonacci (11) ==
     89, which still fit in int8_t. */
  int8_t f[SNTRUP761_P + 1], g[SNTRUP761_P + 1], v[SNTRUP761_P + 1], r[SNTRUP761_P + 1];
  int i, loop, delta;
  int sign, swap, t;

  v[0] = 0;
  r[0] = 1;
  for (i = 1; i < SNTRUP761_P + 1; ++i)
    v[i] = r[i] = 0;

  f[0] = 1;
  for (i = 1; i < SNTRUP761_P - 1; ++i)
    f[i] = 0;
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

      /* Always canonicalize the values controlling the iteration
	 update. */
      g[0] = _sntrup_mod_3 (g[0]);
      f[0] = _sntrup_mod_3 (f[0]);

      if (loop && !(loop & 7))
	{
	  /* Re-canonicalize everything. */
	  r[0] = _sntrup_mod_3 (r[0]);
	  for (i = 1; i < SNTRUP761_P + 1; ++i)
	    {
	      g[i] = _sntrup_mod_3 (g[i]);
	      f[i] = _sntrup_mod_3 (f[i]);
	      v[i] = _sntrup_mod_3 (v[i]);
	      r[i] = _sntrup_mod_3 (r[i]);
	    }
	}
      sign = -g[0] * f[0];
      swap = uint16_highbit_mask (-delta) & uint16_nonzero_mask (g[0]);
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

      for (i = 0; i < SNTRUP761_P; ++i)
	g[i] = g[i+1] + sign * f[i+1];
      g[SNTRUP761_P] = 0;

      for (i = 0; i < SNTRUP761_P + 1; ++i)
	r[i] += sign * v[i];
    }

  sign = _sntrup_mod_3 (f[0]);
  for (i = 0; i < SNTRUP761_P; ++i)
    out[i] = _sntrup_mod_3 (sign * v[SNTRUP761_P - 1 - i]);

  return delta == 0;
}

/* out = 1/(3*in) in Rq */
static void
Rq_recip3 (sntrup761_Rq_t out, const sntrup761_R3_t in)
{
  int16_t f[SNTRUP761_P + 1], g[SNTRUP761_P + 1], v[SNTRUP761_P + 1], r[SNTRUP761_P + 1];
  int i, loop, delta;
  int swap, t;
  int32_t f0, g0;
  int16_t scale;

  v[0] = 0;
  r[0] = -1530; /* 3^-1 (mod q) */
  for (i = 1; i < SNTRUP761_P + 1; ++i)
    v[i] = r[i] = 0;

  f[0] = 1;
  for (i = 1; i < SNTRUP761_P - 1; ++i)
    f[i] = 0;
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

      swap = uint16_highbit_mask (-delta) & uint16_nonzero_mask (g[0]);
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
      for (i = 0; i < SNTRUP761_P; ++i)
	g[i] = _sntrup761_mod_q (f0 * g[i+1] - g0 * f[i+1]);
      g[SNTRUP761_P] = 0;

      for (i = 0; i < SNTRUP761_P + 1; ++i)
	r[i] = _sntrup761_mod_q (f0 * r[i] - g0 * v[i]);
    }

  scale = Fq_recip (f[0]);
  for (i = 0; i < SNTRUP761_P; ++i)
    out[i] = _sntrup761_mod_q (scale * (int32_t) v[SNTRUP761_P - 1 - i]);

  /* Since R/q is a field and input is always non-zero. */
  assert_maybe (delta == 0);
}

static void
Rq_encode (uint8_t *s, const sntrup761_Rq_t r)
{
  uint16_t R[SNTRUP761_P];
  int i;

  for (i = 0; i < SNTRUP761_P; ++i)
    R[i] = r[i] + SNTRUP761_Q12;
  _sntrup_encode (_sntrup761_encoding_Rq, s, R);
}

/* Returns public polynomial h, private polynomials f, ginv. */
static void
KeyGen (sntrup761_Rq_t h, sntrup761_R3_t f, sntrup761_R3_t ginv,
	void *random_ctx, nettle_random_func * random)
{
  sntrup761_R3_t g;
  sntrup761_Rq_t finv;

  for (;;)
    {
      R3_random (g, random_ctx, random);
      if (R3_recip (ginv, g))
	break;
    }
  _sntrup761_short_random (f, random_ctx, random);
  Rq_recip3 (finv, f);
  _sntrup761_Rq_mult_small (h, finv, g);
}

void
sntrup761_generate_keypair (uint8_t *pk, uint8_t *sk, void *random_ctx,
			    nettle_random_func * random)
{
  sntrup761_Rq_t h;
  sntrup761_R3_t f, v;

  KeyGen (h, f, v, random_ctx, random);
  Rq_encode (pk, h);
  _sntrup761_small_encode (sk, f);
  _sntrup761_small_encode (sk + SNTRUP761_R3_SIZE, v);

  /* Auxiliary data appended to the secret key: public key, random
     rho, and hash of the public key. */
  memcpy (sk + 2*SNTRUP761_R3_SIZE, pk, SNTRUP761_PUBLIC_KEY_SIZE);
  random (random_ctx, SNTRUP761_R3_SIZE,
	  sk + 2*SNTRUP761_R3_SIZE + SNTRUP761_PUBLIC_KEY_SIZE);
  _sntrup_hash_prefix (sk + 3*SNTRUP761_R3_SIZE + SNTRUP761_PUBLIC_KEY_SIZE,
		       4, SNTRUP761_PUBLIC_KEY_SIZE, pk);
}
