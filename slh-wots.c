/* slh-wots.c

   WOTS+ one-time signatures, part of SLH-DSA (FIPS 205)

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

#include "slh-dsa-internal.h"

#include "sha3.h"
#include "bswap-internal.h"

/* If s == 0, returns src and leaves dst unchanged. Otherwise, returns
   dst. For the ah argument, leaves ah->keypair and ah->height_chain
   unchanged, but overwrites the other fields. */
static const uint8_t *
wots_chain (const struct sha3_ctx *ctx,
	    struct slh_address_hash *ah,
	    unsigned i, unsigned s,
	    const uint8_t *src, uint8_t *dst)
{
  unsigned j;

  if (s == 0)
    return src;

  ah->type = bswap32_if_le (SLH_WOTS_HASH);
  ah->index_hash = bswap32_if_le (i);

  _slh_shake (ctx, ah, src, dst);

  for (j = 1; j < s; j++)
    {
      ah->index_hash = bswap32_if_le (i + j);
      _slh_shake (ctx, ah, dst, dst);
    }

  return dst;
}

static void
wots_pk_init (const struct sha3_ctx *tree_ctx,
	      unsigned keypair, struct slh_address_hash *ah, struct sha3_ctx *ctx)
{
  ah->type = bswap32_if_le (SLH_WOTS_PK);
  ah->keypair = bswap32_if_le (keypair);
  ah->height_chain = 0;
  ah->index_hash = 0;
  *ctx = *tree_ctx;
  sha3_256_update (ctx, sizeof (*ah), (const uint8_t *) ah);
}

void
_wots_gen (const struct sha3_ctx *tree_ctx, const uint8_t *secret_seed,
	   uint32_t keypair, uint8_t *pub)
{
  struct slh_address_hash ah;
  struct sha3_ctx ctx;
  unsigned i;

  wots_pk_init (tree_ctx, keypair, &ah, &ctx);

  for (i = 0; i < _WOTS_SIGNATURE_LENGTH; i++)
    {
      uint8_t out[_SLH_DSA_128_SIZE];

      /* Generate secret value. */
      ah.type = bswap32_if_le (SLH_WOTS_PRF);
      ah.height_chain = bswap32_if_le (i);
      ah.index_hash = 0;
      _slh_shake (tree_ctx, &ah, secret_seed, out);

      /* Hash chain. */
      wots_chain (tree_ctx, &ah, 0, 15, out, out);

      sha3_256_update (&ctx, _SLH_DSA_128_SIZE, out);
    }
  sha3_256_shake (&ctx, _SLH_DSA_128_SIZE, pub);
}

/* Produces signature hash corresponding to the ith message nybble. Modifies addr. */
static void
wots_sign_one (const struct sha3_ctx *tree_ctx, const uint8_t *secret_seed,
	       uint32_t keypair,
	       unsigned i, uint8_t msg, uint8_t *sig, struct sha3_ctx *ctx)
{
  struct slh_address_hash ah;
  uint8_t pub[_SLH_DSA_128_SIZE];
  sig += i*_SLH_DSA_128_SIZE;

  /* Generate secret value. */
  ah.type = bswap32_if_le (SLH_WOTS_PRF);
  ah.keypair = bswap32_if_le (keypair);
  ah.height_chain = bswap32_if_le (i);
  ah.index_hash = 0;
  _slh_shake (tree_ctx, &ah, secret_seed, sig);

  /* Hash chain. */
  wots_chain (tree_ctx, &ah, 0, msg, sig, sig);

  sha3_256_update (ctx, _SLH_DSA_128_SIZE,
		   wots_chain (tree_ctx, &ah, msg, 15 - msg, sig, pub));
}

void
_wots_sign (const struct sha3_ctx *tree_ctx, const uint8_t *secret_seed,
	    unsigned keypair, const uint8_t *msg, uint8_t *signature, uint8_t *pub)
{
  struct slh_address_hash ah;
  struct sha3_ctx ctx;
  unsigned i;
  uint32_t csum;

  wots_pk_init (tree_ctx, keypair, &ah, &ctx);

  for (i = 0, csum = 15*32; i < _SLH_DSA_128_SIZE; i++)
    {
      uint8_t m0, m1;
      m0 = msg[i] >> 4;
      csum -= m0;
      wots_sign_one (tree_ctx, secret_seed, keypair, 2*i, m0, signature, &ctx);

      m1 = msg[i] & 0xf;
      csum -= m1;
      wots_sign_one (tree_ctx, secret_seed, keypair, 2*i + 1, m1, signature, &ctx);
    }

  wots_sign_one (tree_ctx, secret_seed, keypair, 32, csum >> 8, signature, &ctx);
  wots_sign_one (tree_ctx, secret_seed, keypair, 33, (csum >> 4) & 0xf, signature, &ctx);
  wots_sign_one (tree_ctx, secret_seed, keypair, 34, csum & 0xf, signature, &ctx);

  sha3_256_shake (&ctx, _SLH_DSA_128_SIZE, pub);
}

static void
wots_verify_one (const struct sha3_ctx *tree_ctx, struct sha3_ctx *ctx,
		 uint32_t keypair, unsigned i, uint8_t msg, const uint8_t *signature)
{
  struct slh_address_hash ah;
  uint8_t out[_SLH_DSA_128_SIZE];
  signature += i*_SLH_DSA_128_SIZE;

  ah.keypair = bswap32_if_le (keypair);
  ah.height_chain = bswap32_if_le (i);

  sha3_256_update (ctx, _SLH_DSA_128_SIZE,
		   wots_chain (tree_ctx, &ah, msg, 15 - msg, signature, out));
}

void
_wots_verify (const struct sha3_ctx *tree_ctx,
	      unsigned keypair, const uint8_t *msg, const uint8_t *signature, uint8_t *pub)
{
  struct slh_address_hash ah;
  struct sha3_ctx ctx;
  unsigned i;
  uint32_t csum;

  wots_pk_init (tree_ctx, keypair, &ah, &ctx);

  for (i = 0, csum = 15*32; i < _SLH_DSA_128_SIZE; i++)
    {
      uint8_t m0, m1;
      m0 = msg[i] >> 4;
      csum -= m0;
      wots_verify_one (tree_ctx, &ctx, keypair, 2*i, m0, signature);

      m1 = msg[i] & 0xf;
      csum -= m1;
      wots_verify_one (tree_ctx, &ctx, keypair, 2*i + 1, m1, signature);
    }

  wots_verify_one (tree_ctx, &ctx, keypair, 32, csum >> 8, signature);
  wots_verify_one (tree_ctx, &ctx, keypair, 33, (csum >> 4) & 0xf, signature);
  wots_verify_one (tree_ctx, &ctx, keypair, 34, csum & 0xf, signature);

  sha3_256_shake (&ctx, _SLH_DSA_128_SIZE, pub);
}
