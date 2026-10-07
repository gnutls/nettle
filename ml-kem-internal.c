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
#define MAX_ETA 3

/* A polynomial is represented as a uint16_t array of length N, where
 * an element at index i represents the coefficient of x^i.
 *
 * Vectors and matrices of polynomials are represented as a flat,
 * one-dimensional array of uint16_t, where a vector of k polynomials
 * is an array of uint16_t, of length N * k. A matrix of l vectors is
 * an array of uint16_t, of length N * k * l.
 */

static inline void
H (struct sha3_ctx *ctx,
   size_t len,
   const uint8_t *msg,
   uint8_t *dst)
{
  sha3_256_update (ctx, len, msg);
  sha3_256_digest (ctx, dst);
}

static inline void
G2 (struct sha3_ctx *ctx,
    size_t len1, const uint8_t *msg1,
    size_t len2, const uint8_t *msg2,
    uint8_t *dst)
{
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
  sha3_256_update (ctx, 32, seed);
  sha3_256_update (ctx, 1, &nonce);
  sha3_256_shake (ctx, length, dst);
}

/* Calculate x mod Q using Barrett reduction
   for x in range [0, Q^2) */
static inline uint16_t
reduce (uint32_t u)
{
  /* Magic constant is ceil(2^32 / Q) */
  return uint32_16_mod (u, Q, 1290168);
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

/* Calculate a product of two polynomials AP and BP in NTT domain, add to RP. */
static void
poly_addmul_ntt (uint16_t *rp, const uint16_t *ap, const uint16_t *bp)
{
  size_t i;

  for (i = 0; i < N; i += 2)
    {
      uint16_t z, a1, a2, b1, b2;

      a1 = ap[i];
      a2 = ap[i + 1];
      b1 = bp[i];
      b2 = bp[i + 1];

      z = zeta_pow_table2[i >> 1];

      rp[i] = reduce (rp[i] + a1 * b1 + z * reduce (a2 * b2));
      rp[i + 1] = reduce (rp[i + 1] + a2 * b1 + a1 * b2);
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
  size_t i;

  poly_mul_ntt (rp, ap, bp);

  for (i = 1; i < k; i++)
    poly_addmul_ntt (rp, ap + i*N, bp + i*N);
}

/* This is used to sample the matrix A. In the notation of the spec,
   this function produces A_ji, i.e., the first index i is the
   *column*, which is a bit weird. */
static void
sample_ntt (uint16_t *rp, struct sha3_ctx *xof, const uint8_t *rho, unsigned i, unsigned j)
{
  uint8_t indices[2] = { i, j };
  size_t n;

  sha3_128_update (xof, 32, rho);
  sha3_128_update (xof, 2, indices);

  for (n = 0;;)
    {
      uint8_t b[3]; /* Multiple of 8 would be more efficient with shake. */
      uint16_t d1, d2;

      sha3_128_shake_output (xof, sizeof(b), b);

      d1 = b[0] + ((b[1] & 15) << 8);
      d2 = (b[1] >> 4) + (b[2] << 4);

      if (d1 < Q)
	{
	  rp[n++] = d1;
	  if (n == N)
	    break;
	}

      if (d2 < Q)
	{
	  rp[n++] = d2;
	  if (n == N)
	    break;
	}
    }
  /* Explicit reinit needed after sha3_128_shake_output. */
  sha3_init (xof);
}

/* Calculate a product of the K x K matrix generated from rho,
 * *transposed*, and a vector with K elements BP in NTT domain. Needs
 * scratch space N for a single matrix element. */
static void
matrix_mul_ntt (uint16_t *rp, struct sha3_ctx *hctx, const uint8_t *rho, const uint16_t *bp,
		unsigned k, uint16_t *scratch)
{
  size_t i;

  for (i = 0; i < k; i++, rp += N)
    {
      size_t j;

      sample_ntt (scratch, hctx, rho, i, 0);
      poly_mul_ntt (rp, scratch, bp);

      for (j = 1; j < k; j++)
	{
	  sample_ntt (scratch, hctx, rho, i, j);
	  poly_addmul_ntt (rp, scratch, bp + j*N);
	}
    }
}

/* Calculate a product of the K x K matrix generated from rho and a
 * vector with K elements BP in NTT domain. Needs scratch space N for
 * a single matrix element.
 *
 * Adds the result to the vector in RP.
 */
static void
matrix_addmul_ntt (uint16_t *rp, struct sha3_ctx *hctx, const uint8_t *rho, const uint16_t *bp,
		   unsigned k, uint16_t *scratch)
{
  size_t i;

  for (i = 0; i < k; i++, rp += N)
    {
      size_t j;

      for (j = 0; j < k; j++)
	{
	  sample_ntt (scratch, hctx, rho, j, i);
	  poly_addmul_ntt (rp, scratch, bp + j*N);
	}
    }
}

/* Returns number of one bits in a number that is at most MAX_ETA
   bits, i.e., limited to 0 <= x < 8 */
static inline uint16_t
popcount_small (unsigned x)
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

/* Needs a scratch buffer of 64*eta bytes, or at most 64*MAX_ETA ==
   192. */
static void
vector_sample (uint16_t *rp, struct sha3_ctx *ctx, const uint8_t *sigma, unsigned eta,
	       unsigned offset, unsigned k, uint8_t *buffer)
{
  size_t i;
  uint16_t mask = (1U << eta) - 1;

  for (i = 0; i < k; i++, rp += N)
    {
      size_t j, l;
      unsigned bits, w;

      PRF (ctx, sigma, offset + i, 64 * eta, buffer);

      /* Each iteration gets a block of 2*eta bits from the buffer. */
      for (j = l = bits = w = 0; j < N; j++, bits -= 2*eta, w >>= 2*eta)
	{
	  unsigned xbits, ybits;
	  if (bits < 2 * eta)
	    {
	      w |= (buffer[l++] << bits);
	      bits += 8;
	    }

	  xbits = w & mask;
	  ybits = (w >> eta) & mask;

	  rp[j] = mod_sub (popcount_small (xbits), popcount_small (ybits));
	}
      assert (bits == 0);
      assert (l == 64 * eta);
    }
}

/* Encodes 12-bit coefficients, one "scalar" (256 coeffients) is
   stored as 384 bytes. */
static void
full_encode (uint8_t *rp, const uint16_t *ap, unsigned k)
{
  size_t i, j;
  for (i = j = 0; i < N*k; i += 2, j += 3)
    {
      uint16_t a0 = ap[i];
      uint16_t a1 = ap[i+1];
      assert_maybe (a0 < Q);
      assert_maybe (a1 < Q);

      rp[j] = a0;
      rp[j+1] = (a0 >> 8) | a1 << 4;
      rp[j+2] = a1 >> 4;
    }
  assert (j == 384 * k);
}

/* Decodes 12-bit coefficients, and reduces mod Q. One "scalar" (256
   coeffients) corresponds to 384 bytes input. */
static void
full_decode (uint16_t *rp, const uint8_t *ap, unsigned k)
{
  size_t i, j;
  for (i = j = 0; i < N*k; i += 2, j += 3)
    {
      uint8_t a1 = ap[j+1];
      uint32_t r;

      r = (ap[j] | ((a1 & 0x0f) << 8)) - Q;
      rp[i] = r + ((r >> 16) & Q);
      r = ((ap[j+2] << 4) | (a1 >> 4)) - Q;
      rp[i+1] = r + ((r >> 16) & Q);
    }
  assert (j == 384 * k);
}

/* Compresses coeffients to d bits, and encodes them as a byte array
   of size 32 * k * d bytes. */
static void
compress_encode (uint8_t *rp, const uint16_t *ap, unsigned k, unsigned d)
{
  size_t i, j;
  unsigned bits, w;
  uint16_t mask = (1U << d) - 1;

  for (i = j = bits = w = 0; i < N * k ; i++)
    {
      uint16_t x = ap[i];
      uint16_t c;

      assert_maybe (x < Q);
      /* Compress(x, d) = Round((2^d x / Q)) mod 2^d
	 for 0 <= x < Q and d < 12 */
      c = ((UINT64_C(20642679) * ((x << d) + (Q >> 1))) >> 36) & mask;
      /* Needs worst case 7 + 11 = 18 bits in w. */
      w |= (unsigned) c << bits;

      for (bits += d; bits >= 8; bits -= 8, w >>= 8)
	rp[j++] = w;
    }
  assert (bits == 0);
}

static void
decompress_decode (uint16_t *rp, const uint8_t *ap, unsigned k, unsigned d)
{
  size_t i, j;
  unsigned bits, w;
  uint16_t mask = (1U << d) - 1;
  uint16_t half = 1U << (d-1);

  for (i = j = bits = w = 0; i < N * k; )
    {
      /* Needs worst case 10 + 8 = 18 bits in w. */
      for (; bits < d; bits +=8)
	w |= (ap[j++] << bits);

      for (; bits >= d; bits -= d, w >>= d)
	{
	  /* Decompress(y, d) = Round((Q/2^d)y)
	     for 0 <= y < 2^d and d < 12, the result is in [0, Q) */
	  rp[i++] = (Q * (w & mask) + half) >> d;
	}
    }
  assert (bits == 0);
}

static size_t
inner_generate_keypair_itch (const struct ml_kem_params *params)
{
  return N * (2 * params->k + 1);
}

static void
inner_generate_keypair (const struct ml_kem_params *params,
			uint8_t *pub,
			uint8_t *key,
			struct sha3_ctx *hctx,
			const uint8_t *seed,
			uint16_t *scratch)
{
  uint8_t *buffer, *rho, *sigma;
  unsigned i;
  uint16_t *s, *e, *scratch_out;
  uint8_t k = params->k;

  /* Scratch use:
     +-------+-------+---+
     |   s   |   e   |   |
     +-------+-------+---+
        k N     k N    N scratch_out
   */
  s = scratch;
  e = scratch + N * params->k;
  scratch_out = scratch + 2*N * params->k;
  /* buffer is used for the 64 byte G2 hash, and as scratch for
     vector_sample. This fits comfortable in the 512 bytes of scratch
     for matrix_addmul_ntt, we just must copy out the rho value before
     reusing this space. */
  buffer = (uint8_t *) scratch_out;
  sigma = buffer + 32;

  G2 (hctx, 32, seed, 1, &k, buffer);

  vector_sample (s, hctx, sigma, params->eta1, 0, params->k, buffer + 64);
  vector_sample (e, hctx, sigma, params->eta1, params->k, params->k, buffer + 64);

  for (i = 0; i < params->k; i++)
    {
      poly_into_ntt (s + i*N);
      poly_into_ntt (e + i*N);
    }

  rho = pub + (params->k * Q_BITS * N) / 8;
  memcpy (rho, buffer, 32);

  /* row-major */
  matrix_addmul_ntt (e, hctx, rho, s, params->k, scratch_out);
  full_encode (pub, e, params->k);

  full_encode (key, s, params->k);
}

static size_t
inner_encrypt_itch (const struct ml_kem_params *params)
{
  return N * (2 * params->k + 2);
}

static void
inner_encrypt (const struct ml_kem_params *params,
	       const uint8_t *pub,
	       const uint8_t *msg,
	       struct sha3_ctx *hctx,
	       const uint8_t *seed,
	       uint8_t *ciphertext,
	       uint16_t *scratch)
{
  const uint8_t *rho = &pub[(params->k * Q_BITS * N) / 8];
  uint16_t *r, *t, *u, *v, *e1, *e2, *scratch_out;
  size_t i;

  /* Scratch use:
     +-------+-------+---+---+
     |  r,e  |  t,u  | v |   |
     +-------+-------+---+---+
        k N     k N    N   N scratch_out
   */
  r = scratch;
  t = scratch + N * params->k;
  v = scratch + N * 2*params->k;
  u = t; /* Reuse storage */
  e1 = r; /* Reuse storage */
  e2 = r; /* Reuse storage */
  scratch_out = scratch + N * (2*params->k + 1);

  vector_sample (r, hctx, seed, params->eta1, 0, params->k, (uint8_t *) scratch_out);

  for (i = 0; i < params->k; i++)
    poly_into_ntt (r + i*N);

  full_decode (t, pub, params->k);

  vector_mul_ntt (v, t, r, params->k);
  poly_from_ntt (v);

  /* column-major */
  matrix_mul_ntt (u, hctx, rho, r, params->k, scratch_out);

  for (i = 0; i < params->k; i++)
    poly_from_ntt (u + i*N);

  vector_sample (e1, hctx, seed, ETA2, params->k, params->k, (uint8_t *) scratch_out);

  for (i = 0; i < params->k * N; i++)
    u[i] = mod_add (u[i], e1[i]);

  compress_encode (ciphertext, u, params->k, params->du);

  vector_sample (e2, hctx, seed, ETA2, 2 * params->k, 1, (uint8_t *) scratch_out);

  /* Expand each message bit into the values decompress (0,1) = 0 or
     decompress (1, 1) = (Q+1)/2 */
  for (i = 0; i < 32; i++)
    {
      unsigned j;
      uint8_t b;

      for (b = msg[i], j = 0; j < 8; j++, b >>= 1)
	e2[8*i+j] = mod_add (e2[8*i+j], - (b & 1) & INV2);
    }

  for (i = 0; i < N; i++)
    v[i] = mod_add (v[i], e2[i]);

  compress_encode (&ciphertext[(params->du * params->k * N) / 8], v,
		   1, params->dv);
}

/* Scratch need is N * (params->k + params->k) */
static void
inner_decrypt (const struct ml_kem_params *params,
	       const uint8_t *key,
	       const uint8_t *ciphertext,
	       uint8_t *plaintext,
	       uint16_t *scratch)
{
  uint16_t r[N], *s, *u, v[N];
  size_t i;

  s = scratch;
  u = s + N * params->k;

  decompress_decode (u, ciphertext, params->k, params->du);
  decompress_decode (v, &ciphertext[(params->du * params->k * N) / 8],
		     1, params->dv);
  full_decode (s, key, params->k);

  for (i = 0; i < params->k; i++)
    poly_into_ntt (u + i*N);

  vector_mul_ntt (r, s, u, params->k);
  poly_from_ntt (r);

  for (i = 0; i < N; i++)
    v[i] = mod_sub (v[i], r[i]);

  compress_encode (plaintext, v, 1, 1);
}

size_t
_ml_kem_generate_keypair_itch (const struct ml_kem_params *params)
{
  return inner_generate_keypair_itch (params);
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

  sha3_init (&hctx);
  inner_generate_keypair (params, pub, key, &hctx, seed, scratch);

  /* dk = dk|ek|H(ek)|z */
  p = &key[params->inner_private_key_size];
  memcpy (p, pub, params->public_key_size);
  p += params->public_key_size;

  H (&hctx, params->public_key_size, pub, p);
  p += 32;

  memcpy (p, &seed[32], 32);
}

size_t
_ml_kem_encap_itch (const struct ml_kem_params *params)
{
  return inner_encrypt_itch (params);
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

  random (random_ctx, sizeof (m), m);

  sha3_init (&hctx);
  H (&hctx, params->public_key_size, pub, buffer);
  G2 (&hctx, sizeof (m), m, 32, buffer, buffer);

  inner_encrypt (params, pub, m, &hctx, r, ciphertext, scratch);

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
  return inner_encrypt_itch (params) + params->ciphertext_size;
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
  const uint8_t *h = pub + params->public_key_size;
  const uint8_t *z = h + 32;
  struct sha3_ctx hctx;
  volatile int ok = 1;
  uint8_t *ciphertext2 = (uint8_t *)(scratch + inner_encrypt_itch (params));

  inner_decrypt (params, key, ciphertext, m, scratch);

  sha3_init (&hctx);
  G2 (&hctx, sizeof (m), m, 32, h, buffer);

  inner_encrypt (params, pub, m, &hctx, &buffer[32], ciphertext2, scratch);

  /* K1 = KBar2 */
  memcpy (secret, buffer, 32);

  /* K2 = J(z || cipherText) */
  J2 (&hctx, 32, z, params->ciphertext_size, ciphertext, k2);

  ok &= memeql_sec (ciphertext, ciphertext2, params->ciphertext_size);

  cnd_memcpy (!ok, secret, k2, 32);
}
