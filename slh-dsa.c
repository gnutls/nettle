/* slh-dsa-shake.c

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


static const uint8_t slh_pure_prefix[2] = {0, 0};

void
_slh_dsa_randomizer (const uint8_t *public_seed, const uint8_t *secret_prf,
		     size_t msg_length, const uint8_t *msg,
		     uint8_t *randomizer)
{
  struct sha3_256_ctx ctx;

  sha3_256_init (&ctx);
  sha3_256_update (&ctx, _SLH_DSA_128_SIZE, secret_prf);
  sha3_256_update (&ctx, _SLH_DSA_128_SIZE, public_seed);
  sha3_256_update (&ctx, sizeof(slh_pure_prefix), slh_pure_prefix);
  sha3_256_update (&ctx, msg_length, msg);
  sha3_256_shake (&ctx, _SLH_DSA_128_SIZE, randomizer);
}

void
_slh_dsa_digest (const uint8_t *randomizer, const uint8_t *pub,
		 size_t length, const uint8_t *msg,
		 size_t digest_size, uint8_t *digest)
{
  struct sha3_256_ctx ctx;

  sha3_256_init (&ctx);
  sha3_256_update (&ctx, _SLH_DSA_128_SIZE, randomizer);
  sha3_256_update (&ctx, 2*_SLH_DSA_128_SIZE, pub);
  sha3_256_update (&ctx, sizeof(slh_pure_prefix), slh_pure_prefix);
  sha3_256_update (&ctx, length, msg);
  sha3_256_shake (&ctx, digest_size, digest);
}

void
_slh_dsa_sign (const struct slh_dsa_params *params,
	       const uint8_t *pub, const uint8_t *priv,
	       const uint8_t *digest,
	       uint64_t tree_idx, unsigned leaf_idx,
	       uint8_t *signature)
{
  uint8_t root[_SLH_DSA_128_SIZE];
  int i;

  struct slh_merkle_ctx_secret merkle_ctx =
    {
      {
	pub, { 0, 0, bswap64_if_le (tree_idx) }, leaf_idx,
      },
      priv,
    };

  _fors_sign (&merkle_ctx, &params->fors, digest, signature, root);
  signature += params->fors.signature_size;

  _xmss_sign (&merkle_ctx, params->xmss.h, leaf_idx, root, signature, root);

  for (i = 1; i < params->xmss.d; i++)
    {
      signature += params->xmss.signature_size;

      leaf_idx = tree_idx & ((1 << params->xmss.h) - 1);
      tree_idx >>= params->xmss.h;

      merkle_ctx.pub.at.layer = bswap32_if_le(i);
      merkle_ctx.pub.at.tree_idx = bswap64_if_le (tree_idx);

      _xmss_sign (&merkle_ctx, params->xmss.h, leaf_idx, root, signature, root);
    }
  assert (memeql_sec (root, pub + _SLH_DSA_128_SIZE, sizeof(root)));
}

int
_slh_dsa_verify (const struct slh_dsa_params *params, const uint8_t *pub,
		 const uint8_t *digest, uint64_t tree_idx, unsigned leaf_idx,
		 const uint8_t *signature)
{
  uint8_t root[_SLH_DSA_128_SIZE];
  int i;

  struct slh_merkle_ctx_public merkle_ctx =
    {
      pub, { 0, }, 0
    };

  merkle_ctx.at.tree_idx = bswap64_if_le (tree_idx);
  merkle_ctx.keypair = leaf_idx;

  _fors_verify (&merkle_ctx, &params->fors, digest, signature, root);
  signature += params->fors.signature_size;

  _xmss_verify (&merkle_ctx, params->xmss.h, leaf_idx, root, signature, root);

  for (i = 1; i < params->xmss.d; i++)
    {
      signature += params->xmss.signature_size;

      leaf_idx = tree_idx & ((1 << params->xmss.h) - 1);
      tree_idx >>= params->xmss.h;

      merkle_ctx.at.layer = bswap32_if_le(i);
      merkle_ctx.at.tree_idx = bswap64_if_le (tree_idx);

      _xmss_verify (&merkle_ctx, params->xmss.h, leaf_idx, root, signature, root);
    }
  return memcmp (root, pub + _SLH_DSA_128_SIZE, sizeof(root)) == 0;
}
