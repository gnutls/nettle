/* salsa20.c
 *
 * The Salsa20 stream cipher.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2012 Simon Josefsson
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

/* Based on:
   salsa20-ref.c version 20051118
   D. J. Bernstein
   Public domain.
*/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>

#include "salsa20.h"

#include "macros.h"

#define SWAP32(v)				\
  ((ROTL32(8,  v) & 0x00FF00FFUL) |		\
   (ROTL32(24, v) & 0xFF00FF00UL))

#ifdef WORDS_BIGENDIAN
#define U32TO32_LITTLE(v) SWAP32(v)
#else
#define U32TO32_LITTLE(v) (v)
#endif

#define U8TO32_LITTLE(p) U32TO32_LITTLE(((uint32_t*)(p))[0])
#define U32TO8_LITTLE(p, v) (((uint32_t*)(p))[0] = U32TO32_LITTLE(v))

static void salsa20_wordtobyte(uint8_t output[SALSA20_BLOCK_SIZE],const uint32_t input[_SALSA20_INPUT_LENGTH])
{
  uint32_t x[_SALSA20_INPUT_LENGTH];
  int i;

  for (i = 0;i < _SALSA20_INPUT_LENGTH;++i) x[i] = input[i];
  for (i = 20;i > 0;i -= 2) {
    x[ 4] ^= ROTL32( 7, x[ 0] + x[12]);
    x[ 8] ^= ROTL32( 9, x[ 4] + x[ 0]);
    x[12] ^= ROTL32(13, x[ 8] + x[ 4]);
    x[ 0] ^= ROTL32(18, x[12] + x[ 8]);
    x[ 9] ^= ROTL32( 7, x[ 5] + x[ 1]);
    x[13] ^= ROTL32( 9, x[ 9] + x[ 5]);
    x[ 1] ^= ROTL32(13, x[13] + x[ 9]);
    x[ 5] ^= ROTL32(18, x[ 1] + x[13]);
    x[14] ^= ROTL32( 7, x[10] + x[ 6]);
    x[ 2] ^= ROTL32( 9, x[14] + x[10]);
    x[ 6] ^= ROTL32(13, x[ 2] + x[14]);
    x[10] ^= ROTL32(18, x[ 6] + x[ 2]);
    x[ 3] ^= ROTL32( 7, x[15] + x[11]);
    x[ 7] ^= ROTL32( 9, x[ 3] + x[15]);
    x[11] ^= ROTL32(13, x[ 7] + x[ 3]);
    x[15] ^= ROTL32(18, x[11] + x[ 7]);
    x[ 1] ^= ROTL32( 7, x[ 0] + x[ 3]);
    x[ 2] ^= ROTL32( 9, x[ 1] + x[ 0]);
    x[ 3] ^= ROTL32(13, x[ 2] + x[ 1]);
    x[ 0] ^= ROTL32(18, x[ 3] + x[ 2]);
    x[ 6] ^= ROTL32( 7, x[ 5] + x[ 4]);
    x[ 7] ^= ROTL32( 9, x[ 6] + x[ 5]);
    x[ 4] ^= ROTL32(13, x[ 7] + x[ 6]);
    x[ 5] ^= ROTL32(18, x[ 4] + x[ 7]);
    x[11] ^= ROTL32( 7, x[10] + x[ 9]);
    x[ 8] ^= ROTL32( 9, x[11] + x[10]);
    x[ 9] ^= ROTL32(13, x[ 8] + x[11]);
    x[10] ^= ROTL32(18, x[ 9] + x[ 8]);
    x[12] ^= ROTL32( 7, x[15] + x[14]);
    x[13] ^= ROTL32( 9, x[12] + x[15]);
    x[14] ^= ROTL32(13, x[13] + x[12]);
    x[15] ^= ROTL32(18, x[14] + x[13]);
  }
  for (i = 0;i < _SALSA20_INPUT_LENGTH;++i) x[i] = x[i] + input[i];
  for (i = 0;i < _SALSA20_INPUT_LENGTH;++i) U32TO8_LITTLE(output + 4 * i,x[i]);
}

static const char sigma[_SALSA20_INPUT_LENGTH] = "expand 32-byte k";
static const char tau[_SALSA20_INPUT_LENGTH] = "expand 16-byte k";

void
salsa20_set_key(struct salsa20_ctx *ctx,
		unsigned length, const uint8_t *key)
{
  const char *constants;

  assert (length == SALSA20_MIN_KEY_SIZE || length == SALSA20_MAX_KEY_SIZE);

  ctx->input[1] = U8TO32_LITTLE(key + 0);
  ctx->input[2] = U8TO32_LITTLE(key + 4);
  ctx->input[3] = U8TO32_LITTLE(key + 8);
  ctx->input[4] = U8TO32_LITTLE(key + 12);
  if (length == SALSA20_MAX_KEY_SIZE) { /* recommended */
    key += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  ctx->input[11] = U8TO32_LITTLE(key + 0);
  ctx->input[12] = U8TO32_LITTLE(key + 4);
  ctx->input[13] = U8TO32_LITTLE(key + 8);
  ctx->input[14] = U8TO32_LITTLE(key + 12);
  ctx->input[0] = U8TO32_LITTLE(constants + 0);
  ctx->input[5] = U8TO32_LITTLE(constants + 4);
  ctx->input[10] = U8TO32_LITTLE(constants + 8);
  ctx->input[15] = U8TO32_LITTLE(constants + 12);
}

void
salsa20_set_iv(struct salsa20_ctx *ctx, unsigned length, const uint8_t *iv)
{
  assert (length == SALSA20_IV_SIZE);

  ctx->input[6] = U8TO32_LITTLE(iv + 0);
  ctx->input[7] = U8TO32_LITTLE(iv + 4);
  ctx->input[8] = 0;
  ctx->input[9] = 0;
}

void
salsa20_crypt(struct salsa20_ctx *ctx,
	      unsigned length,
	      uint8_t *c,
	      const uint8_t *m)
{
  uint8_t output[SALSA20_BLOCK_SIZE];
  unsigned i;

  if (!length) return;
  for (;;) {
    salsa20_wordtobyte(output,ctx->input);
    ctx->input[8]++;
    if (!ctx->input[8]) {
      ctx->input[9]++;
      /* stopping at 2^70 length per nonce is user's responsibility */
    }
    if (length <= SALSA20_BLOCK_SIZE) {
      for (i = 0;i < length;++i) c[i] = m[i] ^ output[i];
      return;
    }
    for (i = 0;i < SALSA20_BLOCK_SIZE;++i) c[i] = m[i] ^ output[i];
    length -= SALSA20_BLOCK_SIZE;
    c += SALSA20_BLOCK_SIZE;
    m += SALSA20_BLOCK_SIZE;
  }
}
