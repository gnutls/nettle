/* sntrup761-decap.c

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

#include "sntrup.h"
#include "sntrup-internal.h"

#include "memops.h"
#include "nettle-internal.h"

/* R3_fromR(R_fromRq(r)) */
static void
R3_fromRq (sntrup761_R3_t out, const sntrup761_Rq_t r)
{
  int i;
  for (i = 0; i < SNTRUP761_P; i++)
    out[i] = _sntrup_mod_3 (r[i]);
}

/* h = f*g in the ring R3. */
static void
R3_mult (sntrup761_R3_t h, const sntrup761_R3_t f, const sntrup761_R3_t g)
{
  int16_t fg[SNTRUP761_P + SNTRUP761_P - 1];
  int i, j;

  for (i = 0; i < SNTRUP761_P; i++)
    {
      int16_t result;
      for (result = 0, j = 0; j <= i; j++)
	result += f[j] * g[i - j];
      fg[i] = result;
    }
  for (i = SNTRUP761_P; i < SNTRUP761_P + SNTRUP761_P - 1; i++)
    {
      int16_t result;
      for (result = 0, j = i - SNTRUP761_P + 1; j < SNTRUP761_P; j++)
	result += f[j] * g[i - j];
      fg[i] = result;
    }

  for (i = SNTRUP761_P + SNTRUP761_P - 2; i >= SNTRUP761_P; --i)
    {
      fg[i - SNTRUP761_P] += + fg[i];
      fg[i - SNTRUP761_P + 1] += fg[i];
    }

  for (i = 0; i < SNTRUP761_P; i++)
    h[i] = _sntrup_mod_3 (fg[i]);
}

/* Decodes a polynomial with coefficients supposedly all being in {-1,
   0, 1}. Invalid inputs, corresponding to the value 2, are
   canonicalized to -1. */
static void
Small_decode (sntrup761_R3_t f, const uint8_t *s)
{
  int8_t *p;
  int i;

  for (i = 0, p = f; i < SNTRUP761_P / 4; i++)
    {
      uint8_t x = *s++;
      /* All bit pairs should be one of 00, 01, 10. If invalid value
	 11 occurs, replace with 00 (reduction mod 3). */
      uint8_t invalid = x & (x >> 1) & 0x55;
      x &= ~(3*invalid);

      *p++ = ((int8_t) (x & 3)) - 1;
      x >>= 2;
      *p++ = ((int8_t) (x & 3)) - 1;
      x >>= 2;
      *p++ = ((int8_t) (x & 3)) - 1;
      x >>= 2;
      *p++ = ((int8_t) (x & 3)) - 1;
    }
  {
    uint8_t x = *s;
    uint8_t valid = (x & (x >> 1) & 1) ^ 1;
    *p = ((int8_t) (x & (3*valid))) - 1;
  }
}

static void
Rounded_decode (sntrup761_Rq_t r, const uint8_t *s)
{
  uint16_t R[SNTRUP761_P];
  int i;

  _sntrup_decode (SNTRUP761_ENCODING_STEPS, _sntrup761_encoding_rounded, R,
		  s + SNTRUP761_ROUNDED_SIZE);
  for (i = 0; i < SNTRUP761_P; i++)
    r[i] = R[i] * 3 - SNTRUP761_Q12;
}

/* Check that weight equals SNTRUP761_W. If not, set r to the
   polynomial 1,..,1,0,...0 of the right weight. */
static void
check_weight (volatile sntrup761_R3_t r)
{
  uint16_t w, mask;
  int i;

  for (i = 0, w = SNTRUP761_W; i < SNTRUP761_P; i++)
    w -= r[i] & 1;

  mask = -IS_ZERO_SMALL (w); /* Mask set to all-ones if valid */

  for (i = 0; i < SNTRUP761_P; i++)
    r[i] &= mask;

  mask = ~mask; /* Mask set to all-ones if not valid */
  for (i = 0; i < SNTRUP761_W; i++)
    r[i] -= mask;
}

/* r = ZDecrypt(C,sk) */
static void
ZDecrypt (const uint8_t *sk, sntrup761_R3_t r, const uint8_t *c_enc)
{
  sntrup761_R3_t f, ginv;
  sntrup761_Rq_t c;
  int i;

  Small_decode (f, sk);
  Small_decode (ginv, sk + SNTRUP761_R3_SIZE);
  Rounded_decode (c, c_enc);

  /* Premultiply by 3; the result is interpreted as a polynomial over
     Rq, not the zero element of R3. */
  for (i = 0; i < SNTRUP761_P; i++)
    f[i] *= 3;

  _sntrup761_Rq_mult_small (c, c, f);
  R3_fromRq (r, c);
  R3_mult (r, r, ginv);

  check_weight (r);
}

/* k = Decap(c,sk) */
void
sntrup761_decap (const uint8_t *sk, uint8_t *k, const uint8_t *c)
{
  const uint8_t *pk = sk + 2*SNTRUP761_R3_SIZE;
  const uint8_t *rho = pk + SNTRUP761_PUBLIC_KEY_SIZE;
  const uint8_t *cache = rho + SNTRUP761_R3_SIZE;
  sntrup761_R3_t r;
  uint8_t r_enc[SNTRUP761_R3_SIZE];
  uint8_t cnew[SNTRUP761_CIPHER_SIZE];
  int mask;
  int i;

  ZDecrypt (sk, r, c);
  _sntrup761_encap_internal (pk, cache, r_enc, cnew, r);
  mask = memeql_sec(c, cnew, sizeof (cnew)) - 1;
  for (i = 0; i < SNTRUP761_R3_SIZE; i++)
    r_enc[i] ^= mask & (r_enc[i] ^ rho[i]);
  _sntrup_hash_session (k, 1 + mask, r_enc, c);
}
