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
#define _slh_shake_init _nettle_slh_shake_init
#define _slh_shake _nettle_slh_shake
#define _wots_gen _nettle_wots_gen
#define _wots_sign _nettle_wots_sign
#define _wots_verify _nettle_wots_verify
#define _merkle_root _nettle_merkle_root
#define _merkle_sign _nettle_merkle_sign
#define _merkle_verify _nettle_merkle_verify
#define _fors_gen _nettle_fors_gen
#define _fors_sign _nettle_fors_sign
#define _fors_verify _nettle_fors_verify
#define _xmss_gen _nettle_xmss_gen
#define _xmss_sign _nettle_xmss_sign
#define _xmss_verify _nettle_xmss_verify

/* Size of a single hash, including the seed and prf parameters */
#define _SLH_DSA_128_SIZE 16

#define SLH_DSA_D 7
#define SLH_DSA_M 30

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

struct slh_merkle_ctx_public
{
  const uint8_t *seed;
  struct slh_address_tree at;
  unsigned keypair; /* Used only by fors_leaf and fors_node. */
};

struct slh_merkle_ctx_secret
{
  struct slh_merkle_ctx_public pub;
  const uint8_t *secret_seed;
};

struct sha3_256_ctx;
void
_slh_shake_init (struct sha3_256_ctx *ctx, const uint8_t *public_seed,
		 const struct slh_address_tree *at, const struct slh_address_hash *ah);
void
_slh_shake (const uint8_t *public_seed,
	    const struct slh_address_tree *at, const struct slh_address_hash *ah,
	    const uint8_t *secret, uint8_t *out);

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

/* Merkle tree functions. Could be generalized for other merkle tree
   applications, by using const void* for the ctx argument. */
typedef void merkle_leaf_hash_func (const struct slh_merkle_ctx_secret *ctx, unsigned index, uint8_t *out);
typedef void merkle_node_hash_func (const struct slh_merkle_ctx_public *ctx, unsigned height, unsigned index,
				    const uint8_t *left, const uint8_t *right, uint8_t *out);

void
_merkle_root (const struct slh_merkle_ctx_secret *ctx,
	      merkle_leaf_hash_func *leaf_hash, merkle_node_hash_func *node_hash,
	      unsigned height, unsigned start, uint8_t *root,
	      /* Must have space for (height + 1) node hashes */
	      uint8_t *stack);

void
_merkle_sign (const struct slh_merkle_ctx_secret *ctx,
	      merkle_leaf_hash_func *leaf_hash, merkle_node_hash_func *node_hash,
	      unsigned height, unsigned idx, uint8_t *signature);

/* The hash argument is both input (leaf hash to be verified) and output (resulting root hash). */
void
_merkle_verify (const struct slh_merkle_ctx_public *ctx, merkle_node_hash_func *node_hash,
		unsigned height, unsigned idx, const uint8_t *signature, uint8_t *hash);

/* Use k Merkle trees, each of size 2^a. Signs messages of size
   k * a = 168 bits or 21 octets. */
#define FORS_A 12
#define FORS_K 14

#define FORS_MSG_SIZE 21
/* 2912 bytes */
#define FORS_SIGNATURE_SIZE (FORS_K * (FORS_A + 1) * _SLH_DSA_128_SIZE)

/* Generates a single secret value, and corresponding leaf hash. */
void
_fors_gen (const struct slh_merkle_ctx_secret *ctx, unsigned index, uint8_t *sk, uint8_t *leaf);

/* Computes a fors signature as well as the public key. */
void
_fors_sign (const struct slh_merkle_ctx_secret *fors_ctx,
	    const uint8_t *msg, uint8_t *signature, uint8_t *pub);

/* Computes candidate public key from signature. */
void
_fors_verify (const struct slh_merkle_ctx_public *ctx,
	      const uint8_t *msg, const uint8_t *signature, uint8_t *pub);

#define XMSS_H 9
/* Just the auth path, excluding the wots signature, 144 bytes. */
#define XMSS_AUTH_SIZE (XMSS_H * _SLH_DSA_128_SIZE)
#define XMSS_SIGNATURE_SIZE (WOTS_SIGNATURE_SIZE + XMSS_AUTH_SIZE)

void
_xmss_gen (const uint8_t *public_seed, const uint8_t *secret_seed,
	   uint8_t *root);

/* Signs using wots, then signs wots public key using xmss. Also
   returns the xmss public key (i.e., root hash).*/
void
_xmss_sign (const struct slh_merkle_ctx_secret *ctx,
	    unsigned idx, const uint8_t *msg, uint8_t *signature, uint8_t *pub);

void
_xmss_verify (const struct slh_merkle_ctx_public *ctx,
	      unsigned idx, const uint8_t *msg, const uint8_t *signature, uint8_t *pub);

#endif /* NETTLE_SLH_DSA_INTERNAL_H_INCLUDED */
