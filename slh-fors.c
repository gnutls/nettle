/* slh-fors.c

   Forest of Random Subsets, part of SLH-DSA (FIPS 205)

   Copyright (C) 2025 Niels Möller

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

#include <assert.h>

#include "bswap-internal.h"
#include "sha3.h"
#include "slh-dsa-internal.h"

void
_fors_gen (const struct slh_merkle_ctx_secret *ctx,
	   unsigned idx, uint8_t *sk, uint8_t *leaf)
{
  struct slh_address_hash ah =
    {
      bswap32_if_le (SLH_FORS_PRF),
      bswap32_if_le (ctx->pub.keypair),
      0,
      bswap32_if_le(idx),
    };
  assert (idx < (FORS_K << FORS_A));

  _slh_shake (ctx->pub.seed, &ctx->pub.at, &ah, ctx->secret_seed, sk);

  ah.type = bswap32_if_le (SLH_FORS_TREE);
  _slh_shake (ctx->pub.seed, &ctx->pub.at, &ah, sk, leaf);
}

static void
fors_leaf (const struct slh_merkle_ctx_secret *ctx, unsigned idx, uint8_t *out)
{
  _fors_gen (ctx, idx, out, out);
}

static void
fors_node (const struct slh_merkle_ctx_public *ctx, unsigned height, unsigned index,
	   const uint8_t *left, const uint8_t *right, uint8_t *out)
{
  struct sha3_256_ctx sha3;
  struct slh_address_hash ah =
    {
      bswap32_if_le (SLH_FORS_TREE),
      bswap32_if_le (ctx->keypair),
      bswap32_if_le (height),
      bswap32_if_le (index),
    };
  _slh_shake_init (&sha3, ctx->seed, &ctx->at, &ah);
  sha3_256_update (&sha3, _SLH_DSA_128_SIZE, left);
  sha3_256_update (&sha3, _SLH_DSA_128_SIZE, right);
  sha3_256_shake (&sha3, _SLH_DSA_128_SIZE, out);
}

static void
fors_sign_one (const struct slh_merkle_ctx_secret *ctx,
	       unsigned idx, uint8_t *signature, struct sha3_256_ctx *pub)
{
  uint8_t hash[_SLH_DSA_128_SIZE];
  assert (idx < (FORS_K << FORS_A));

  _fors_gen (ctx, idx, signature, hash);

  _merkle_sign (ctx, fors_leaf, fors_node, FORS_A, idx,
		signature + _SLH_DSA_128_SIZE);
  _merkle_verify (&ctx->pub, fors_node, FORS_A, idx, signature + _SLH_DSA_128_SIZE, hash);

  sha3_256_update (pub, _SLH_DSA_128_SIZE, hash);
}

void
_fors_sign (const struct slh_merkle_ctx_secret *ctx,
	    const uint8_t *msg, uint8_t *signature, uint8_t *pub)
{
  struct slh_address_hash ah =
    {
      bswap32_if_le(SLH_FORS_ROOTS),
      bswap32_if_le(ctx->pub.keypair),
      0, 0,
    };
  struct sha3_256_ctx sha3;
  unsigned i;

  assert (FORS_A == 12); /* Specialized code */

  _slh_shake_init (&sha3, ctx->pub.seed, &ctx->pub.at, &ah);

  for (i = 0; i < FORS_K; i += 2, msg += 3, signature += 2*(FORS_A + 1) * _SLH_DSA_128_SIZE)
    {
      unsigned m0 = ((unsigned) msg[0] << 4) + (msg[1] >> 4);
      unsigned m1 = ((msg[1] & 0xf) << 8) + msg[2];
      fors_sign_one (ctx, (i << FORS_A) +  m0, signature, &sha3);
      fors_sign_one (ctx,((i+1) << FORS_A) + m1,
		     signature + (FORS_A + 1) * _SLH_DSA_128_SIZE, &sha3);
    }

  sha3_256_shake (&sha3, _SLH_DSA_128_SIZE, pub);
}

static void
fors_verify_one (const struct slh_merkle_ctx_public *ctx,
		 unsigned idx, const uint8_t *signature, struct sha3_256_ctx *pub)
{
  uint8_t root[_SLH_DSA_128_SIZE];
  struct slh_address_hash ah =
    {
      bswap32_if_le (SLH_FORS_TREE),
      bswap32_if_le (ctx->keypair),
      0,
      bswap32_if_le(idx),
    };
  assert (idx < (FORS_K << FORS_A));

  _slh_shake (ctx->seed, &ctx->at, &ah, signature, root);
  _merkle_verify (ctx, fors_node, FORS_A, idx, signature + _SLH_DSA_128_SIZE, root);

  sha3_256_update (pub, _SLH_DSA_128_SIZE, root);
}

void
_fors_verify (const struct slh_merkle_ctx_public *ctx,
	      const uint8_t *msg, const uint8_t *signature, uint8_t *pub)
{
  struct sha3_256_ctx sha3;
  unsigned i;
  struct slh_address_hash ah =
    {
      bswap32_if_le (SLH_FORS_ROOTS),
      bswap32_if_le (ctx->keypair),
      0, 0,
    };

  assert (FORS_A == 12); /* Specialized code */

  _slh_shake_init (&sha3, ctx->seed, &ctx->at, &ah);

  for (i = 0; i < FORS_K; i += 2, msg += 3, signature += 2*(FORS_A + 1) * _SLH_DSA_128_SIZE)
    {
      unsigned m0 = ((unsigned) msg[0] << 4) + (msg[1] >> 4);
      unsigned m1 = ((msg[1] & 0xf) << 8) + msg[2];
      fors_verify_one (ctx, (i << FORS_A) +  m0, signature, &sha3);
      fors_verify_one (ctx, ((i+1) << FORS_A) + m1,
		       signature + (FORS_A + 1) * _SLH_DSA_128_SIZE, &sha3);
    }
  sha3_256_shake (&sha3, _SLH_DSA_128_SIZE, pub);
}
