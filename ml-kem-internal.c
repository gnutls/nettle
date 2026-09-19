/* ml-kem-internal.c

   ML-KEM (Kyber) key encapsulation mechanism, FIPS 203

   Copyright (C) 2024 Red Hat, Inc.
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include "ml-kem-internal.h"

#include "memops.h"
#include "nettle-internal.h"
#include "sha3.h"

#define Q 3329
#define Q_BITS 12
#define N 256
#define N_BITS 8
#define INV2 ((Q + 1) / 2)

#define ZETA 17
#define ETA2 2
#define MAX_ETA1 3

/* A polynomial is represented as a uint16_t array of length N, where
 * an element at index i represents the coefficient of x^i.
 *
 * Vectors and matrices of polynomials are represented as a flat,
 * one-dimensional array of uint16_t, where a vector of k polynomials
 * is an array of uint16_t, of length N * k. A matrix of l vectors is
 * an array of uint16_t, of length N * k * l.
 */
#define VECTOR_GET_POLY(vec, i) &(vec)[(i) * N]
#define MATRIX_GET_VECTOR(mat, k, i) &(mat)[(k) * (i) * N]
#define MATRIX_GET_POLY(mat, k, l, i, j) &(mat)[(k) * (i) * N + (l) * (j) * N]

static inline void
H (struct sha3_ctx *ctx,
   size_t len,
   const uint8_t *msg,
   uint8_t *dst)
{
  sha3_init (ctx);
  sha3_256_update (ctx, len, msg);
  sha3_256_digest (ctx, dst);
}

static inline void
G2 (struct sha3_ctx *ctx,
    size_t len1, const uint8_t *msg1,
    size_t len2, const uint8_t *msg2,
    uint8_t *dst)
{
  sha3_init (ctx);
  sha3_512_update (ctx, len1, msg1);
  sha3_512_update (ctx, len2, msg2);
  sha3_512_digest (ctx, dst);
}

static inline void
J2 (struct sha3_ctx *ctx,
    size_t len1, const uint8_t *msg1,
    size_t len2, const uint8_t *msg2,
    uint8_t *dst)
{
  sha3_init (ctx);
  sha3_256_update (ctx, len1, msg1);
  sha3_256_update (ctx, len2, msg2);
  sha3_256_shake (ctx, 32, dst);
}

static inline void
PRF (struct sha3_ctx *ctx,
     const uint8_t *seed,
     uint8_t nonce,
     size_t length,
     uint8_t *dst)
{
  sha3_init (ctx);
  sha3_256_update (ctx, 32, seed);
  sha3_256_update (ctx, 1, &nonce);
  sha3_256_shake (ctx, length, dst);
}

/* Compress(x, d) = Round((2^d/Q)x) mod 2^d
   for 0 <= x < Q and d < 12, the result is in [0, 2^d) */
static inline uint16_t
compress (uint16_t x, unsigned d)
{
  assert_maybe (x < Q);
  return ((UINT64_C(20642679) * ((x << d) + (Q >> 1)) >> 36) & ((1 << d) - 1));
}

/* Decompress(y, d) = Round((Q/2^d)y)
   for 0 <= y < 2^d and d < 12, the result is in [0, Q) */
static inline uint16_t
decompress (uint16_t y, unsigned d)
{
  return ((Q * y + (1 << (d - 1))) >> d);
}

/* Calculate x mod Q using Barrett reduction
   for x in range [0, Q^2) */
static inline uint16_t
reduce (uint32_t u)
{
  uint32_t q, r, p;
  /* Magic constant is ceil(2^32 / Q) */
  q = ((uint64_t) 1290168 * u) >> 32;
  p = q * Q;
  r = u - p; /* Interpreted as two's complement, |r| < d */
  r += ((r >> 16) & Q);
  assert_maybe (r < Q);
  return r;
}

/* Calculate a - b mod Q, where 0 <= a < Q and 0 <= b <= Q */
static inline uint16_t
mod_sub (uint16_t a, uint16_t b)
{
  uint32_t d;
  assert_maybe (a < Q);
  assert_maybe (b <= Q);

  d = (uint32_t) a - b;
  d += (d >> 16) & Q;
  assert_maybe (d < Q);

  return d;
}

/* Calculate a + b mod Q, where a and b are already reduced by Q */
static inline uint16_t
mod_add (uint16_t a, uint16_t b)
{
  assert_maybe (a < Q);
  assert_maybe (b < Q);
  return mod_sub (a, Q - b);
}

static const uint16_t zeta_pow_table[128] =
  {
    0x0001, 0x06c1, 0x0a14, 0x0cd9, 0x0a52, 0x0276, 0x0769, 0x0350,
    0x0426, 0x077f, 0x00c1, 0x031d, 0x0ae2, 0x0cbc, 0x0239, 0x06d2,
    0x0128, 0x098f, 0x053b, 0x05c4, 0x0be6, 0x0038, 0x08c0, 0x0535,
    0x0592, 0x082e, 0x0217, 0x0b42, 0x0959, 0x0b3f, 0x07b6, 0x0335,
    0x0121, 0x014b, 0x0cb5, 0x06dc, 0x04ad, 0x0900, 0x08e5, 0x0807,
    0x028a, 0x07b9, 0x09d1, 0x0278, 0x0b31, 0x0021, 0x0528, 0x077b,
    0x090f, 0x059b, 0x0327, 0x01c4, 0x059e, 0x0b34, 0x05fe, 0x0962,
    0x0a57, 0x0a39, 0x05c9, 0x0288, 0x09aa, 0x0c26, 0x04cb, 0x038e,
    0x0011, 0x0ac9, 0x0247, 0x0a59, 0x0665, 0x02d3, 0x08f0, 0x044c,
    0x0581, 0x0a66, 0x0cd1, 0x00e9, 0x02f4, 0x086c, 0x0bc7, 0x0bea,
    0x06a7, 0x0673, 0x0ae5, 0x06fd, 0x0737, 0x03b8, 0x05b5, 0x0a7f,
    0x03ab, 0x0904, 0x0985, 0x0954, 0x02dd, 0x0921, 0x010c, 0x0281,
    0x0630, 0x08fa, 0x07f5, 0x0c94, 0x0177, 0x09f5, 0x082a, 0x066d,
    0x0427, 0x013f, 0x0ad5, 0x02f5, 0x0833, 0x0231, 0x09a2, 0x0a22,
    0x0af4, 0x0444, 0x0193, 0x0402, 0x0477, 0x0866, 0x0ad7, 0x0376,
    0x06ba, 0x04bc, 0x0752, 0x0405, 0x083e, 0x0b77, 0x0375, 0x086a,
  };

static const uint16_t zeta_pow_table2[128] =
  {
    0x0011, 0x0cf0, 0x0ac9, 0x0238, 0x0247, 0x0aba, 0x0a59, 0x02a8,
    0x0665, 0x069c, 0x02d3, 0x0a2e, 0x08f0, 0x0411, 0x044c, 0x08b5,
    0x0581, 0x0780, 0x0a66, 0x029b, 0x0cd1, 0x0030, 0x00e9, 0x0c18,
    0x02f4, 0x0a0d, 0x086c, 0x0495, 0x0bc7, 0x013a, 0x0bea, 0x0117,
    0x06a7, 0x065a, 0x0673, 0x068e, 0x0ae5, 0x021c, 0x06fd, 0x0604,
    0x0737, 0x05ca, 0x03b8, 0x0949, 0x05b5, 0x074c, 0x0a7f, 0x0282,
    0x03ab, 0x0956, 0x0904, 0x03fd, 0x0985, 0x037c, 0x0954, 0x03ad,
    0x02dd, 0x0a24, 0x0921, 0x03e0, 0x010c, 0x0bf5, 0x0281, 0x0a80,
    0x0630, 0x06d1, 0x08fa, 0x0407, 0x07f5, 0x050c, 0x0c94, 0x006d,
    0x0177, 0x0b8a, 0x09f5, 0x030c, 0x082a, 0x04d7, 0x066d, 0x0694,
    0x0427, 0x08da, 0x013f, 0x0bc2, 0x0ad5, 0x022c, 0x02f5, 0x0a0c,
    0x0833, 0x04ce, 0x0231, 0x0ad0, 0x09a2, 0x035f, 0x0a22, 0x02df,
    0x0af4, 0x020d, 0x0444, 0x08bd, 0x0193, 0x0b6e, 0x0402, 0x08ff,
    0x0477, 0x088a, 0x0866, 0x049b, 0x0ad7, 0x022a, 0x0376, 0x098b,
    0x06ba, 0x0647, 0x04bc, 0x0845, 0x0752, 0x05af, 0x0405, 0x08fc,
    0x083e, 0x04c3, 0x0b77, 0x018a, 0x0375, 0x098c, 0x086a, 0x0497,
  };

/* Move a polynomial PP into NTT domain. */
static void
poly_into_ntt (uint16_t *pp)
{
  size_t layer, zi;

  for (layer = N >> 1, zi = 1; layer >= 2; layer >>= 1)
    {
      size_t offset;

      for (offset = 0; offset < N - layer; offset += 2 * layer)
	{
	  size_t j;
	  uint16_t z;

	  z = zeta_pow_table[zi++];
	  for (j = offset; j < offset + layer; j++)
	    {
	      uint16_t t;

	      t = reduce (z * pp[j + layer]);
	      pp[j + layer] = mod_sub (pp[j], t);
	      pp[j] = mod_add (pp[j], t);
	    }
	}
    }
}

/* Move a polynomial PP back from NTT domain. */
static void
poly_from_ntt (uint16_t *pp)
{
  size_t layer, zi;

  for (layer = 2, zi = (N >> 1) - 1; layer < N; layer <<= 1)
    {
      size_t offset;

      for (offset = 0; offset < N - layer; offset += 2 * layer)
	{
	  size_t j;
	  uint16_t z;

	  z = zeta_pow_table[zi--];
	  for (j = offset; j < offset + layer; j++)
	    {
	      uint16_t t;

	      t = mod_sub (pp[j + layer], pp[j]);
	      pp[j] = reduce (INV2 * (pp[j] + pp[j + layer]));
	      pp[j + layer] = reduce (INV2 * reduce (z * t));
	    }
	}
    }
}

/* Calculate a product of two polynomials AP and BP in NTT domain.
 *
 * Returns the results as a polynomial in RP, which should not overlap
 * with AP nor BP.
 */
static void
poly_mul_ntt (uint16_t *rp, const uint16_t *ap, const uint16_t *bp)
{
  size_t i;

  memset (rp, 0, sizeof(uint16_t) * N);

  for (i = 0; i < N; i += 2)
    {
      uint16_t z, a1, a2, b1, b2;

      a1 = ap[i];
      a2 = ap[i + 1];
      b1 = bp[i];
      b2 = bp[i + 1];

      z = zeta_pow_table2[i >> 1];

      rp[i] = reduce (a1 * b1 + z * reduce (a2 * b2));
      rp[i + 1] = reduce (a2 * b1 + a1 * b2);
    }
}

/* Calculate dot product of two vectors AP and BP with length K in NTT domain.
 *
 * Returns the result as a polynomial in RP.
 */
static void
vector_mul_ntt (uint16_t *rp, const uint16_t *ap, const uint16_t *bp,
		unsigned k)
{
  uint16_t tp[N];
  size_t i;

  memset (rp, 0, sizeof(uint16_t) * N);

  for (i = 0; i < k; i++)
    {
      size_t j;

      poly_mul_ntt (tp, VECTOR_GET_POLY (ap, i), VECTOR_GET_POLY (bp, i));

      for (j = 0; j < N; j++)
	{
	  uint16_t t = tp[j];
	  uint16_t r = rp[j];

	  rp[j] = t + r;
	}
    }

  for (i = 0; i < N; i++)
    rp[i] = reduce (rp[i]);
}

/* Calculate a product of a K x K matrix AP and a vector with K
 * elements BP in NTT domain. ROW_STRIDE and COLUMN_STRIDE specify how
 * AP is accessed. To access in a row-major order, set ROW_STRIDE to K
 * and COLUMN_STRIDE to 1; otherwise set ROW_STRIDE to 1 and
 * COLUMN_STRIDE to K.
 *
 * Returns the result as a vector in RP.
 */
static void
matrix_mul_ntt (uint16_t *rp, const uint16_t *ap, const uint16_t *bp,
		unsigned k,
		unsigned row_stride,
		unsigned column_stride)
{
  size_t i;

  for (i = 0; i < k; i++)
    {
      uint16_t *pp;
      size_t j;

      pp = VECTOR_GET_POLY (rp, i);

      memset (pp, 0, sizeof(uint16_t) * N);

      for (j = 0; j < k; j++)
	{
	  uint16_t tp[N];
	  size_t l;

	  poly_mul_ntt (tp, MATRIX_GET_POLY (ap, row_stride, column_stride,
					     i, j),
			VECTOR_GET_POLY (bp, j));

	  for (l = 0; l < N; l++)
	    {
	      uint16_t t = tp[l];
	      uint16_t r = pp[l];

	      pp[l] = mod_add (t, r);
	    }
	}
    }
}

static void
poly_sample (uint16_t *pp, struct sha3_128_ctx *xof)
{
  uint8_t b[3];
  size_t n = 0;

  memset (pp, 0, sizeof(uint8_t) * N);

  for (;;)
    {
      uint16_t d1, d2;

      sha3_128_shake_output (xof, sizeof(b), b);

      d1 = b[0] + ((b[1] & 15) << 8);
      d2 = (b[1] >> 4) + (b[2] << 4);

      if (d1 < Q)
	{
	  pp[n++] = d1;
	  if (n == N)
	    break;
	}

      if (d2 < Q)
	{
	  pp[n++] = d2;
	  if (n == N)
	    break;
	}
    }
}

/* Returns number of one bits in a number that is at most MAX_ETA1
   bits, i.e., limited to 0 <= x < 8 */
static inline uint16_t
popcount_small(unsigned x)
{
  /*
    000 --> 00
    001 --> 01
    010 --> 01
    011 --> 10
    100 --> 01
    101 --> 10
    110 --> 10
    111 --> 11

    and 1110 1001 1001 0100 = 0xe994.
   */

  const uint16_t magic = 0xe994;
  return (magic >> (2*x)) & 3;
}

static void
vector_sample (uint16_t *vp, const uint8_t *sigma, unsigned eta1,
	       unsigned offset, unsigned k)
{
  size_t i;
  uint16_t mask = (1U << eta1) - 1;

  for (i = 0; i < k; i++)
    {
      struct sha3_ctx ctx;
      uint8_t arr[64 * MAX_ETA1];
      uint16_t *rp;
      size_t j, l;
      unsigned bits, w;

      PRF (&ctx, sigma, offset + i, 64 * eta1, arr);

      rp = VECTOR_GET_POLY (vp, i);

      /* Each iteration gets a block of 2*eta1 bits from the array. */
      for (j = l = bits = w = 0; j < N; j++, bits -= 2*eta1, w >>= 2*eta1)
	{
	  unsigned xbits, ybits;
	  if (bits < 2 * eta1)
	    {
	      w |= (arr[l++] << bits);
	      bits += 8;
	    }

	  xbits = w & mask;
	  ybits = (w >> eta1) & mask;

	  rp[j] = mod_sub(popcount_small (xbits), popcount_small (ybits));
	}
      assert (bits == 0);
      assert (l == 64 * eta1);
    }
}

static void
matrix_sample (uint16_t *mp, const uint8_t *rho, unsigned k)
{
  uint8_t i;

  for (i = 0; i < k; i++)
    {
      uint16_t *v;
      uint8_t j;

      v = MATRIX_GET_VECTOR (mp, k, i);

      for (j = 0; j < k; j++)
	{
	  struct sha3_128_ctx xof;
	  uint16_t *p;

	  sha3_128_init (&xof);
	  sha3_128_update (&xof, 32, rho);
	  sha3_128_update (&xof, 1, &j);
	  sha3_128_update (&xof, 1, &i);

	  p = VECTOR_GET_POLY (v, j);
	  poly_sample (p, &xof);
	}
    }
}

/* When d < Q_BITS == 12, only the low d bits of each entry are
   written. */
static void
poly_encode (uint8_t *rp, const uint16_t *ap, unsigned d)
{
  size_t i, j;
  unsigned bits, w;
  uint16_t mask = (1U << d) - 1;

  for (i = j = bits = w = 0; i < N; i++)
    {
      /* Needs worst case 7 + 11 = 18 bits in w. */
      w |= (unsigned) (ap[i] & mask) << bits;

      for (bits += d; bits >= 8; bits -= 8, w >>= 8)
	rp[j++] = w;
    }
  assert (bits == 0);
}

static void
poly_decode (uint16_t *rp, const uint8_t *ap, unsigned d)
{
  size_t i, j;
  unsigned bits, w;
  uint16_t mask = (1U << d) - 1;

  for (i = j = bits = w = 0; i < N; )
    {
      /* Needs worst case 10 + 8 = 18 bits in w. */
      for (; bits < d; bits +=8)
	w |= (ap[j++] << bits);

      for (; i < N && bits >= d; bits -= d, w >>= d)
	{
	  /* Reduce mod q; needed only when d == 12 */
	  uint32_t r = (w & mask) - Q;
	  rp[i++] = r + ((r >> 16) & Q);
	}
    }
  assert (bits == 0);
}

static void
vector_encode (uint8_t *rp, const uint16_t *ap, unsigned k, unsigned w)
{
  size_t i;

  for (i = 0; i < k; i++)
    poly_encode (&rp[((w * N) >> 3) * i], VECTOR_GET_POLY (ap, i), w);
}

static void
vector_decode (uint16_t *rp, const uint8_t *ap, unsigned k, unsigned w)
{
  size_t i;

  for (i = 0; i < k; i++)
    poly_decode (VECTOR_GET_POLY (rp, i), &ap[((w * N) >> 3) * i], w);
}

size_t
_ml_kem_inner_generate_keypair_itch (const struct ml_kem_params *params)
{
  return N * (params->k * params->k + params->k + params->k + params->k);
}

void
_ml_kem_inner_generate_keypair (const struct ml_kem_params *params,
				uint8_t *pub,
				uint8_t *key,
				const uint8_t *seed,
				uint16_t *scratch)
{
  struct sha3_ctx gctx;
  uint8_t buffer[64];
  uint8_t *rho = buffer, *sigma = &buffer[32];
  unsigned i;
  uint16_t *a, *s, *e, *t;
  uint8_t k = params->k;

  a = scratch;
  s = a + N * params->k * params->k;
  e = s + N * params->k;
  t = e + N * params->k;

  G2 (&gctx, 32, seed, 1, &k, buffer);

  matrix_sample (a, rho, params->k);
  vector_sample (s, sigma, params->eta1, 0, params->k);
  vector_sample (e, sigma, params->eta1, params->k, params->k);

  for (i = 0; i < params->k; i++)
    {
      poly_into_ntt (VECTOR_GET_POLY (s, i));
      poly_into_ntt (VECTOR_GET_POLY (e, i));
    }

  /* row-major */
  matrix_mul_ntt (t, a, s, params->k, params->k, 1);

  for (i = 0; i < params->k; i++)
    {
      uint16_t *tp, *ep;
      size_t j;

      tp = VECTOR_GET_POLY (t, i);
      ep = VECTOR_GET_POLY (e, i);

      for (j = 0; j < N; j++)
	tp[j] = mod_add (tp[j], ep[j]);
    }

  vector_encode (pub, t, params->k, Q_BITS);

  memcpy (pub + (params->k * Q_BITS * N) / 8, rho, 32);

  vector_encode (key, s, params->k, Q_BITS);
}

size_t
_ml_kem_inner_encrypt_itch (const struct ml_kem_params *params)
{
  return N * (params->k * params->k + params->k + 1 +
	      params->k + params->k + params->k);
}

void
_ml_kem_inner_encrypt (const struct ml_kem_params *params,
		       const uint8_t *pub,
		       const uint8_t *msg,
		       const uint8_t *seed,
		       uint8_t *ciphertext,
		       uint16_t *scratch)
{
  const uint8_t *rho = &pub[(params->k * Q_BITS * N) / 8];
  uint16_t *a, *r, *e1, *e2, *t, *u;
  uint16_t m[N], v[N];
  size_t i;

  a = scratch;
  e1 = a + N * params->k * params->k;
  e2 = e1 + N * params->k;
  r = e2 + N;
  t = r + N * params->k;
  u = t + N * params->k;

  vector_decode (t, pub, params->k, Q_BITS);

  matrix_sample (a, rho, params->k);

  vector_sample (r, seed, params->eta1, 0, params->k);
  vector_sample (e1, seed, ETA2, params->k, params->k);
  vector_sample (e2, seed, ETA2, 2 * params->k, 1);

  for (i = 0; i < params->k; i++)
    poly_into_ntt (VECTOR_GET_POLY (r, i));

  /* column-major */
  matrix_mul_ntt (u, a, r, params->k, 1, params->k);

  for (i = 0; i < params->k; i++)
    poly_from_ntt (VECTOR_GET_POLY (u, i));

  for (i = 0; i < params->k; i++)
    {
      uint16_t *up, *ep;
      size_t j;

      up = VECTOR_GET_POLY (u, i);
      ep = VECTOR_GET_POLY (e1, i);

      for (j = 0; j < N; j++)
	up[j] = mod_add (up[j], ep[j]);
    }

  /* Expand each message bit into the values decompress (0,1) = 0 or
     decompress (1, 1) = (Q+1)/2 */
  for (i = 0; i < 32; i++)
    {
      unsigned j;
      uint8_t b;

      for (b = msg[i], j = 0; j < 8; j++, b >>= 1)
	m[8*i+j] = - (b & 1) & INV2;
    }

  vector_mul_ntt (v, t, r, params->k);
  poly_from_ntt (v);

  for (i = 0; i < N; i++)
    v[i] = mod_add (mod_add (v[i], e2[i]), m[i]);

  for (i = 0; i < params->k; i++)
    {
      size_t j;
      uint16_t *up;

      up = VECTOR_GET_POLY (u, i);
      for (j = 0; j < N; j++)
	up[j] = compress (up[j], params->du);
    }

  vector_encode (ciphertext, u, params->k, params->du);

  for (i = 0; i < N; i++)
    v[i] = compress (v[i], params->dv);

  poly_encode (&ciphertext[(params->du * params->k * N) / 8], v,
	       params->dv);
}

size_t
_ml_kem_inner_decrypt_itch (const struct ml_kem_params *params)
{
  return N * (params->k + params->k);
}

void
_ml_kem_inner_decrypt (const struct ml_kem_params *params,
		       const uint8_t *key,
		       const uint8_t *ciphertext,
		       uint8_t *plaintext,
		       uint16_t *scratch)
{
  uint16_t r[N], *s, *u, v[N];
  size_t i;

  s = scratch;
  u = s + N * params->k;

  vector_decode (u, ciphertext, params->k, params->du);

  for (i = 0; i < params->k; i++)
    {
      size_t j;
      uint16_t *up;

      up = VECTOR_GET_POLY (u, i);
      for (j = 0; j < N; j++)
	up[j] = decompress (up[j], params->du);
    }

  poly_decode (v, &ciphertext[(params->du * params->k * N) / 8],
	       params->dv);

  for (i = 0; i < N; i++)
    v[i] = decompress (v[i], params->dv);

  vector_decode (s, key, params->k, Q_BITS);

  for (i = 0; i < params->k; i++)
    poly_into_ntt (VECTOR_GET_POLY (u, i));

  vector_mul_ntt (r, s, u, params->k);
  poly_from_ntt (r);

  for (i = 0; i < N; i++)
    v[i] = mod_sub (v[i], r[i]);

  for (i = 0; i < N; i++)
    v[i] = compress (v[i], 1);

  poly_encode (plaintext, v, 1);
}

size_t
_ml_kem_generate_keypair_itch (const struct ml_kem_params *params)
{
  return _ml_kem_inner_generate_keypair_itch (params);
}

void
_ml_kem_generate_keypair (const struct ml_kem_params *params,
			  uint8_t *pub,
			  uint8_t *key,
			  const uint8_t *seed,
			  uint16_t *scratch)
{
  struct sha3_ctx hctx;
  uint8_t *p;

  _ml_kem_inner_generate_keypair (params, pub, key, seed, scratch);

  /* dk = dk|ek|H(ek)|z */
  p = &key[params->inner_private_key_size];
  memcpy (p, pub, params->inner_public_key_size);
  p += params->inner_public_key_size;

  H (&hctx, params->inner_public_key_size, pub, p);
  p += 32;

  memcpy (p, &seed[32], 32);
}

size_t
_ml_kem_encap_itch (const struct ml_kem_params *params)
{
  return _ml_kem_inner_encrypt_itch (params);
}

void
_ml_kem_encap (const struct ml_kem_params *params,
	       const uint8_t *pub,
	      uint8_t *secret, uint8_t *ciphertext,
	      void *random_ctx, nettle_random_func *random,
	      uint16_t *scratch)
{
  uint8_t m[32], buffer[64], *r = &buffer[32];
  struct sha3_ctx hctx;
  struct sha3_ctx gctx;

  random (random_ctx, sizeof(m), m);

  H (&hctx, params->public_key_size, pub, buffer);
  G2 (&gctx, sizeof(m), m, 32, buffer, buffer);

  _ml_kem_inner_encrypt (params, pub, m, r, ciphertext, scratch);

  memcpy (secret, buffer, 32);
}

size_t
_ml_kem_decap_itch (const struct ml_kem_params *params)
{
  /* The scratch space consists of two parts: the first part is used
     for encrypt/decrypt and the second part
     is used for a new ciphertext (for implicit rejection).

     This makes use of the fact that:
     - _ml_kem_inner_encrypt_itch is larger than
     _ml_kem_inner_decrypt_itch
     - params->ciphertext_size is multiple of 32-byte blocks and
     therefore no alignment violation
  */
  return _ml_kem_inner_encrypt_itch (params) + params->ciphertext_size;
}

void
_ml_kem_decap (const struct ml_kem_params *params,
	       const uint8_t *key,
	       uint8_t *secret,
	       const uint8_t *ciphertext,
	       uint16_t *scratch)
{
  uint8_t m[32], buffer[64], k2[32];
  const uint8_t *pub = key + params->inner_private_key_size;
  const uint8_t *h = pub + params->inner_public_key_size;
  const uint8_t *z = h + 32;
  struct sha3_ctx hctx;
  struct sha3_ctx gctx;
  volatile int ok = 1;
  uint8_t *ciphertext2 = (uint8_t *)(scratch + _ml_kem_inner_encrypt_itch (params));

  _ml_kem_inner_decrypt (params, key, ciphertext, m, scratch);

  G2 (&gctx, sizeof(m), m, 32, h, buffer);

  _ml_kem_inner_encrypt (params, pub, m, &buffer[32], ciphertext2, scratch);

  /* K1 = KBar2 */
  memcpy (secret, buffer, 32);

  /* K2 = J(z || cipherText) */
  J2 (&hctx, 32, z, params->ciphertext_size, ciphertext, k2);

  ok &= memeql_sec (ciphertext, ciphertext2, params->ciphertext_size);

  cnd_memcpy (!ok, secret, k2, 32);
}
