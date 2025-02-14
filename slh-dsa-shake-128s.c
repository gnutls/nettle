/* slh-dsa-shake-128s.c

   SLH-DSA (FIPS 205) signatures.

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
#include <string.h>

#include "bswap-internal.h"
#include "memops.h"
#include "sha3.h"
#include "slh-dsa.h"
#include "slh-dsa-internal.h"

void
slh_dsa_shake_128s_root (const uint8_t *public_seed, const uint8_t *private_seed,
			 uint8_t *root)
{
  _xmss_gen (public_seed, private_seed, root);
}

void
slh_dsa_shake_128s_generate_keypair (uint8_t *pub, uint8_t *priv,
				     void *random_ctx, nettle_random_func *random)
{
  random (random_ctx, SLH_DSA_SHAKE_128S_SEED_SIZE, pub);
  random (random_ctx, 2*SLH_DSA_SHAKE_128S_SEED_SIZE, priv);
  slh_dsa_shake_128s_root (pub, priv, pub + SLH_DSA_SHAKE_128S_SEED_SIZE);
}

static const uint8_t slh_pure_prefix[2] = {0, 0};

static void
slh_digest (struct sha3_256_ctx *ctx,
	    const uint8_t *randomizer, const uint8_t *pub,
	    size_t length, const uint8_t *msg,
	    uint8_t *digest, uint64_t *tree_idx, unsigned *leaf_idx)
{
  uint64_t x;
  unsigned i;

  sha3_256_update (ctx, _SLH_DSA_128_SIZE, randomizer);
  sha3_256_update (ctx, 2*_SLH_DSA_128_SIZE, pub);
  sha3_256_update (ctx, sizeof(slh_pure_prefix), slh_pure_prefix);
  sha3_256_update (ctx, length, msg);
  sha3_256_shake (ctx, SLH_DSA_M, digest);

  /* Split digest as
     +----+------+-----+
     | md | tree | leaf|
     +----+------+-----+
       21       7     2

   The first 21 octets are the digest signed with fors, the next 7
   octets represent 54 bits selecting the tree, the last 2 octets
   represent 9 bits selecting the key in that tree.

   Left over high bits are discarded.
  */
  x = digest[21] & 0x3f; /* Discard 2 high-most bits of 56 */
  for (i = 22; i < 28; i++)
    x = (x << 8) + digest[i];
  *tree_idx = x;
  /* Discard 7 high-most bits of 16 */
  *leaf_idx = ((digest[28] & 1) << 8) + digest[29];
}

/* Only the "pure" and deterministic variant. */
void
slh_dsa_shake_128s_sign (const uint8_t *pub, const uint8_t *priv,
			 size_t length, const uint8_t *msg,
			 uint8_t *signature)
{
  struct sha3_256_ctx ctx;
  uint8_t digest[SLH_DSA_M];
  uint8_t root[_SLH_DSA_128_SIZE];

  uint64_t tree_idx;
  unsigned leaf_idx;
  int i;

  struct slh_merkle_ctx_secret merkle_ctx =
    {
      {
	pub, { 0, }, 0,
      },
      priv,
    };
  /* First the "randomizer" */
  sha3_256_init (&ctx);
  sha3_256_update (&ctx, _SLH_DSA_128_SIZE, priv + _SLH_DSA_128_SIZE);
  sha3_256_update (&ctx, _SLH_DSA_128_SIZE, pub);
  sha3_256_update (&ctx, sizeof(slh_pure_prefix), slh_pure_prefix);
  sha3_256_update (&ctx, length, msg);
  sha3_256_shake (&ctx, _SLH_DSA_128_SIZE, signature);

  slh_digest (&ctx, signature, pub, length, msg, digest, &tree_idx, &leaf_idx);

  signature += _SLH_DSA_128_SIZE;

  merkle_ctx.pub.at.tree_idx = bswap64_if_le (tree_idx);
  merkle_ctx.pub.keypair = leaf_idx;

  _fors_sign (&merkle_ctx, digest, signature, root);
  signature += FORS_SIGNATURE_SIZE;

  _xmss_sign (&merkle_ctx, leaf_idx, root, signature, root);

  for (i = 1; i < SLH_DSA_D; i++)
    {
      signature += XMSS_SIGNATURE_SIZE;

      leaf_idx = tree_idx & ((1<< XMSS_H) - 1);
      tree_idx >>= XMSS_H;

      merkle_ctx.pub.at.layer = bswap32_if_le(i);
      merkle_ctx.pub.at.tree_idx = bswap64_if_le (tree_idx);

      _xmss_sign (&merkle_ctx, leaf_idx, root, signature, root);
    }
  assert (memeql_sec (root, pub + _SLH_DSA_128_SIZE, sizeof(root)));
}

int
slh_dsa_shake_128s_verify (const uint8_t *pub,
			   size_t length, const uint8_t *msg,
			   const uint8_t *signature)
{
  struct sha3_256_ctx ctx;
  uint8_t digest[SLH_DSA_M];
  uint8_t root[_SLH_DSA_128_SIZE];

  uint64_t tree_idx;
  unsigned leaf_idx;
  int i;

  struct slh_merkle_ctx_public merkle_ctx =
    {
      pub, { 0, }, 0
    };

  sha3_256_init (&ctx);
  slh_digest (&ctx, signature, pub, length, msg, digest, &tree_idx, &leaf_idx);

  signature += _SLH_DSA_128_SIZE;

  merkle_ctx.at.tree_idx = bswap64_if_le (tree_idx);
  merkle_ctx.keypair = leaf_idx;

  _fors_verify (&merkle_ctx, digest, signature, root);
  signature += FORS_SIGNATURE_SIZE;

  _xmss_verify (&merkle_ctx, leaf_idx, root, signature, root);

  for (i = 1; i < SLH_DSA_D; i++)
    {
      signature += XMSS_SIGNATURE_SIZE;

      leaf_idx = tree_idx & ((1<< XMSS_H) - 1);
      tree_idx >>= XMSS_H;

      merkle_ctx.at.layer = bswap32_if_le(i);
      merkle_ctx.at.tree_idx = bswap64_if_le (tree_idx);

      _xmss_verify (&merkle_ctx, leaf_idx, root, signature, root);
    }
  return memcmp (root, pub + _SLH_DSA_128_SIZE, sizeof(root)) == 0;
}
