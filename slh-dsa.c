/* slh-dsa.c

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

#include "memops.h"
#include "slh-dsa.h"
#include "slh-dsa-internal.h"

void
_slh_dsa_sign (const struct slh_dsa_params *params,
	       const struct slh_hash *hash,
	       const uint8_t *pub, const uint8_t *priv,
	       const uint8_t *digest,
	       uint64_t tree_idx, unsigned leaf_idx,
	       uint8_t *signature)
{
  uint8_t root[_SLH_DSA_128_SIZE];
  int i;

  struct slh_merkle_ctx_secret merkle_ctx =
    {
      { hash, {}, leaf_idx },
      priv,
    };
  hash->init_tree (&merkle_ctx.pub.tree_ctx, pub, 0, tree_idx);

  _fors_sign (&merkle_ctx, &params->fors, digest, signature, root);
  signature += params->fors.signature_size;

  _xmss_sign (&merkle_ctx, params->xmss.h, leaf_idx, root, signature, root);

  for (i = 1; i < params->xmss.d; i++)
    {
      signature += params->xmss.signature_size;

      leaf_idx = tree_idx & ((1 << params->xmss.h) - 1);
      tree_idx >>= params->xmss.h;

      hash->init_tree (&merkle_ctx.pub.tree_ctx, pub, i, tree_idx);

      _xmss_sign (&merkle_ctx, params->xmss.h, leaf_idx, root, signature, root);
    }
  assert (memeql_sec (root, pub + _SLH_DSA_128_SIZE, sizeof (root)));
}

int
_slh_dsa_verify (const struct slh_dsa_params *params,
		 const struct slh_hash *hash,
		 const uint8_t *pub,
		 const uint8_t *digest, uint64_t tree_idx, unsigned leaf_idx,
		 const uint8_t *signature)
{
  uint8_t root[_SLH_DSA_128_SIZE];
  int i;

  struct slh_merkle_ctx_public merkle_ctx =
    { hash, {}, leaf_idx };

  hash->init_tree (&merkle_ctx.tree_ctx, pub, 0, tree_idx);

  _fors_verify (&merkle_ctx, &params->fors, digest, signature, root);
  signature += params->fors.signature_size;

  _xmss_verify (&merkle_ctx, params->xmss.h, leaf_idx, root, signature, root);

  for (i = 1; i < params->xmss.d; i++)
    {
      signature += params->xmss.signature_size;

      leaf_idx = tree_idx & ((1 << params->xmss.h) - 1);
      tree_idx >>= params->xmss.h;

      hash->init_tree (&merkle_ctx.tree_ctx, pub, i, tree_idx);

      _xmss_verify (&merkle_ctx, params->xmss.h, leaf_idx, root, signature, root);
    }
  return memcmp (root, pub + _SLH_DSA_128_SIZE, sizeof (root)) == 0;
}
