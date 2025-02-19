/* slh-dsa-shake-128f.c

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

#define SLH_DSA_M 34

#define SLH_DSA_D 22
#define XMSS_H 3

/* Use k Merkle trees, each of size 2^a. Signs messages of size
   k * a = 198 bits or 25 octets (with 2 left-over bits). */
#define FORS_A 6
#define FORS_K 33
#define FORS_MSG_SIZE 25

const struct slh_dsa_params
_slh_dsa_shake_128f_params =
  {
    { SLH_DSA_D, XMSS_H, XMSS_SIGNATURE_SIZE(XMSS_H) },
    { FORS_A, FORS_K, FORS_MSG_SIZE, FORS_SIGNATURE_SIZE(FORS_A, FORS_K) },
  };

void
slh_dsa_shake_128f_root (const uint8_t *public_seed, const uint8_t *private_seed,
			 uint8_t *root)
{
  uint8_t scratch[(XMSS_H + 1)*_SLH_DSA_128_SIZE];
  _xmss_gen (public_seed, private_seed, &_slh_dsa_shake_128f_params.xmss, scratch, root);
}

void
slh_dsa_shake_128f_generate_keypair (uint8_t *pub, uint8_t *priv,
				     void *random_ctx, nettle_random_func *random)
{
  random (random_ctx, SLH_DSA_SHAKE_128_SEED_SIZE, pub);
  random (random_ctx, 2*SLH_DSA_SHAKE_128_SEED_SIZE, priv);
  slh_dsa_shake_128f_root (pub, priv, pub + SLH_DSA_SHAKE_128_SEED_SIZE);
}

static void
parse_digest (const uint8_t *digest, uint64_t *tree_idx, unsigned *leaf_idx)
{
  uint64_t x;
  unsigned i;

  /* Split digest as
     +----+------+-----+
     | md | tree | leaf|
     +----+------+-----+
       25       8     1

   The first 25 octets are the digest signed with fors (and not
   processed by this function), the next 8 octets represent 63 bits
   selecting the tree, the last octet represent 3 bits selecting
   the key in that tree.

   Left over high bits are discarded.
  */
  x = digest[0] & 0x7f; /* Discard high-most bit of 64 */
  for (i = 1; i < 8; i++)
    x = (x << 8) + digest[i];
  *tree_idx = x;
  /* Discard 5 high-most bits */
  *leaf_idx = digest[8] & 7;
}

/* Only the "pure" and deterministic variant. */
void
slh_dsa_shake_128f_sign (const uint8_t *pub, const uint8_t *priv,
			 size_t length, const uint8_t *msg,
			 uint8_t *signature)
{
  uint8_t digest[SLH_DSA_M];
  uint64_t tree_idx;
  unsigned leaf_idx;

  _slh_dsa_randomizer (pub, priv + _SLH_DSA_128_SIZE, length, msg, signature);
  _slh_dsa_digest (signature, pub, length, msg, SLH_DSA_M, digest);
  parse_digest (digest + FORS_MSG_SIZE, &tree_idx, &leaf_idx);

  _slh_dsa_sign (&_slh_dsa_shake_128f_params, pub, priv, digest, tree_idx, leaf_idx,
		 signature + _SLH_DSA_128_SIZE);
}

int
slh_dsa_shake_128f_verify (const uint8_t *pub,
			   size_t length, const uint8_t *msg,
			   const uint8_t *signature)
{
  uint8_t digest[SLH_DSA_M];
  uint64_t tree_idx;
  unsigned leaf_idx;

  _slh_dsa_digest (signature, pub, length, msg, SLH_DSA_M,digest);
  parse_digest (digest + FORS_MSG_SIZE, &tree_idx, &leaf_idx);
  return _slh_dsa_verify (&_slh_dsa_shake_128f_params, pub, digest, tree_idx, leaf_idx,
			  signature + _SLH_DSA_128_SIZE);
}
