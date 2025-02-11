/* slh-dsa-internal.h

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

#ifndef NETTLE_SLH_DSA_INTERNAL_H_INCLUDED
#define NETTLE_SLH_DSA_INTERNAL_H_INCLUDED

#include <stdint.h>

/* Name mangling */
#define _wots_gen _nettle_wots_gen
#define _wots_sign _nettle_wots_sign
#define _wots_verify _nettle_wots_verify

/* Size of a single hash, including the seed and prf parameters */
#define _SLH_DSA_128_SIZE 16

/* Fields always big-endian */
struct slh_address_tree
{
  uint32_t layer;
  uint32_t pad; /* Always zero */
  uint64_t tree_idx;
};

/* Fields always big-endian */
struct slh_address_hash
{
  uint32_t type;
  uint32_t keypair;
  /* height for XMSS_TREE and FORS_TREE, chain address for WOTS_HASH. */
  uint32_t height_chain;
  /* index for XMSS_TREE and FORS_TREE, hash address for WOTS_HASH. */
  uint32_t index_hash;
};

enum slh_addr_type
  {
    SLH_WOTS_HASH = 0,
    SLH_WOTS_PK = 1,
    SLH_XMSS_TREE = 2,
    SLH_FORS_TREE = 3,
    SLH_FORS_ROOTS = 4,
    SLH_WOTS_PRF = 5,
    SLH_FORS_PRF = 6,
  };

#define _WOTS_SIGNATURE_LENGTH 35
/* 560 bytes */
#define WOTS_SIGNATURE_SIZE (_WOTS_SIGNATURE_LENGTH*_SLH_DSA_128_SIZE)

void
_wots_gen (const uint8_t *public_seed, const uint8_t *secret_seed, const struct slh_address_tree *at,
	   uint32_t keypair, uint8_t *pub);

void
_wots_sign (const uint8_t *public_seed, const uint8_t *secret_seed, const struct slh_address_tree *at,
	    unsigned keypair, const uint8_t *msg, uint8_t *signature, uint8_t *pub);

/* Computes candidate public key from signature. */
void
_wots_verify (const uint8_t *public_seed, const struct slh_address_tree *at,
	      unsigned keypair, const uint8_t *msg, const uint8_t *signature, uint8_t *pub);

#endif /* NETTLE_SLH_DSA_INTERNAL_H_INCLUDED */
