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

#include "nettle-types.h"

/* Name mangling */
#define _slh_shake_init _nettle_slh_shake_init
#define _slh_shake _nettle_slh_shake
#define _slh_shake_digest _nettle_slh_shake_digest
#define _slh_shake_randomizer _nettle_slh_shake_randomizer
#define _slh_shake_msg_digest _nettle_slh_shake_msg_digest
#define _slh_sha256_init _nettle_slh_sha256_init
#define _slh_sha256 _nettle_slh_sha256
#define _slh_sha256_randomizer _nettle_slh_sha256_randomizer
#define _slh_sha256_digest _nettle_slh_sha256_digest
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
#define _slh_dsa_sign _nettle_slh_dsa_sign
#define _slh_dsa_verify _nettle_slh_dsa_verify

#define _slh_dsa_shake_128s_params _nettle_slh_dsa_shake_128s_params
#define _slh_dsa_shake_128f_params _nettle_slh_dsa_shake_128f_params

/* Size of a single hash, including the seed and prf parameters */
#define _SLH_DSA_128_SIZE 16

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

typedef void slh_hash_init_func (void *tree_ctx, const uint8_t *public_seed,
				 uint32_t layer, uint64_t tree_idx);
typedef void slh_hash_secret_func (const void *tree_ctx,
				   const struct slh_address_hash *ah,
				   const uint8_t *secret, uint8_t *out);
typedef void slh_hash_node_func (const void *tree_ctx,
				 const struct slh_address_hash *ah,
				 const uint8_t *left, const uint8_t *right,
				 uint8_t *out);
typedef void slh_hash_start_func (const void *tree_ctx, void *ctx, const struct slh_address_hash *ah);

struct slh_hash
{
  slh_hash_init_func *init;
  slh_hash_secret_func *secret;
  slh_hash_node_func *node;
  slh_hash_start_func *start;
  nettle_hash_update_func *update;
  nettle_hash_digest_func *digest;
};

extern const struct slh_hash _slh_hash_shake;
struct slh_hash_ctxs
{
  const struct slh_hash *hash;
  /* Initialized based on public seed and slh_address_tree. */
  const void *tree;
  /* Working ctx for wots and fors. */
  void *scratch;
};

struct slh_merkle_ctx_public
{
  struct slh_hash_ctxs ctx;
  unsigned keypair; /* Used only by fors_leaf and fors_node. */
};

struct slh_merkle_ctx_secret
{
  struct slh_merkle_ctx_public pub;
  const uint8_t *secret_seed;
};

struct slh_xmss_params
{
  unsigned short d; /* Levels of xmss trees. */
  unsigned short h; /* Height of each tree. */
  unsigned short signature_size;
};

struct slh_fors_params
{
  unsigned short a; /* Height of tree. */
  unsigned short k; /* Number of trees. */
  unsigned short signature_size;
};

struct slh_dsa_params
{
  struct slh_xmss_params xmss;
  struct slh_fors_params fors;
};

extern const struct slh_dsa_params _slh_dsa_128s_params;

struct sha3_ctx;
void
_slh_shake_init (struct sha3_ctx *ctx, const uint8_t *public_seed,
		 uint32_t layer, uint64_t tree_idx);

void
_slh_shake (const struct sha3_ctx *tree_ctx,
	    const struct slh_address_hash *ah,
	    const uint8_t *secret, uint8_t *out);

void
_slh_shake_digest (struct sha3_ctx *ctx, uint8_t *out);

void
_slh_shake_randomizer (const uint8_t *public_seed, const uint8_t *secret_prf,
		       size_t msg_length, const uint8_t *msg,
		       uint8_t *randomizer);
void
_slh_shake_msg_digest (const uint8_t *randomizer, const uint8_t *pub,
		       size_t length, const uint8_t *msg,
		       size_t digest_size, uint8_t *digest);

struct sha256_ctx;
void
_slh_sha256_init (struct sha256_ctx *ctx, const uint8_t *public_seed,
		 uint32_t layer, uint64_t tree_idx);

void
_slh_sha256 (const struct sha256_ctx *tree_ctx,
	     const struct slh_address_hash *ah,
	     const uint8_t *secret, uint8_t *out);

void
_slh_sha256_randomizer (const uint8_t *public_seed, const uint8_t *secret_prf,
			size_t msg_length, const uint8_t *msg,
			uint8_t *randomizer);
void
_slh_sha256_msg_digest (const uint8_t *randomizer, const uint8_t *pub,
			size_t length, const uint8_t *msg,
			size_t digest_size, uint8_t *digest);

#define _WOTS_SIGNATURE_LENGTH 35
/* 560 bytes */
#define WOTS_SIGNATURE_SIZE (_WOTS_SIGNATURE_LENGTH*_SLH_DSA_128_SIZE)

void
_wots_gen (const struct slh_hash_ctxs *ctx, const uint8_t *secret_seed,
	   uint32_t keypair, uint8_t *pub);

void
_wots_sign (const struct slh_hash_ctxs *ctx, const uint8_t *secret_seed,
	    unsigned keypair, const uint8_t *msg, uint8_t *signature, uint8_t *pub);

/* Computes candidate public key from signature. */
void
_wots_verify (struct slh_hash_ctxs *ctx,
	      unsigned keypair, const uint8_t *msg, const uint8_t *signature, uint8_t *pub);

/* Merkle tree functions. Leaf function uses a non-const context, to allow the ctx to point at
   working storage. Could be generalized for other merkle tree
   applications, by using void * for the ctx argument. */
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

#define FORS_SIGNATURE_SIZE(a, k) ((k) * ((a) + 1) * _SLH_DSA_128_SIZE)

/* Generates a single secret value, and corresponding leaf hash. */
void
_fors_gen (const struct slh_merkle_ctx_secret *ctx, unsigned index, uint8_t *sk, uint8_t *leaf);

/* Computes a fors signature as well as the public key. */
void
_fors_sign (const struct slh_merkle_ctx_secret *ctx,
	    const struct slh_fors_params *fors,
	    const uint8_t *msg, uint8_t *signature, uint8_t *pub);

/* Computes candidate public key from signature. */
void
_fors_verify (const struct slh_merkle_ctx_public *ctx,
	      const struct slh_fors_params *fors,
	      const uint8_t *msg, const uint8_t *signature, uint8_t *pub);

/* Just the auth path, excluding the wots signature, 144 bytes. */
#define XMSS_AUTH_SIZE(h) ((h) * _SLH_DSA_128_SIZE)
#define XMSS_SIGNATURE_SIZE(h) (WOTS_SIGNATURE_SIZE + XMSS_AUTH_SIZE (h))

/* Provided scratch must be of size (xmss->h + 1) * _SLH_DSA_128_SIZE. */
void
_xmss_gen (const struct slh_hash *hash,
	   void *ha, void *hb,
	   const uint8_t *public_seed, const uint8_t *secret_seed,
	   const struct slh_xmss_params *xmss,
	   uint8_t *scratch, uint8_t *root);

/* Signs using wots, then signs wots public key using xmss. Also
   returns the xmss public key (i.e., root hash).*/
void
_xmss_sign (const struct slh_merkle_ctx_secret *ctx, unsigned h,
	    unsigned idx, const uint8_t *msg, uint8_t *signature, uint8_t *pub);

void
_xmss_verify (const struct slh_merkle_ctx_public *ctx, unsigned h,
	      unsigned idx, const uint8_t *msg, const uint8_t *signature, uint8_t *pub);

void
_slh_dsa_sign (const struct slh_dsa_params *params,
	       const struct slh_hash *hash,
	       void *ha, void *hb,
	       const uint8_t *pub, const uint8_t *priv,
	       const uint8_t *digest,
	       uint64_t tree_idx, unsigned leaf_idx,
	       uint8_t *signature);
int
_slh_dsa_verify (const struct slh_dsa_params *params,
		 const struct slh_hash *hash,
		 void *ha, void *hb,
		 const uint8_t *pub,
		 const uint8_t *digest, uint64_t tree_idx, unsigned leaf_idx,
		 const uint8_t *signature);


#endif /* NETTLE_SLH_DSA_INTERNAL_H_INCLUDED */
