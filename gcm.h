/* gcm.h
 *
 * Galois counter mode, specified by NIST,
 * http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
 *
 */

/* NOTE: Tentative interface, subject to change. No effort will be
   made to avoid incompatible changes. */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2011 Niels Möller
 * Copyright (C) 2011 Katholieke Universiteit Leuven
 * 
 * Contributed by Nikos Mavrogiannopoulos
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

#ifndef NETTLE_GCM_H_INCLUDED
#define NETTLE_GCM_H_INCLUDED

#include "nettle-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define gcm_set_key nettle_gcm_set_key
#define gcm_set_iv nettle_gcm_set_iv
#define gcm_auth nettle_gcm_auth
#define gcm_encrypt nettle_gcm_encrypt
#define gcm_decrypt nettle_gcm_decrypt
#define gcm_digest nettle_gcm_digest

#define GCM_BLOCK_SIZE 16
#define GCM_IV_SIZE (GCM_BLOCK_SIZE - 4)

#define GCM_TABLE_BITS 0

struct gcm_ctx {
  /* Key-dependent state. */
  /* Hashing subkey */
  uint8_t h[GCM_BLOCK_SIZE];
#if GCM_TABLE_BITS
  uint8_t h_table[1 << GCM_TABLE_BITS][GCM_BLOCK_SIZE];
#endif
  /* Per-message state, depending on the iv */
  /* Original counter block */
  uint8_t iv[GCM_BLOCK_SIZE];
  /* Updated for each block. */
  uint8_t ctr[GCM_BLOCK_SIZE];
  /* Hashing state */
  uint8_t x[GCM_BLOCK_SIZE];
  uint64_t auth_size;
  uint64_t data_size;
};

/* FIXME: Should use const for the cipher context. Then needs const for
   nettle_crypt_func, which also rules out using that abstraction for
   arcfour. */
void
gcm_set_key(struct gcm_ctx *ctx,
	    void *cipher, nettle_crypt_func *f);

void
gcm_set_iv(struct gcm_ctx *ctx, unsigned length, const uint8_t *iv);

void
gcm_auth(struct gcm_ctx *ctx, unsigned length, const uint8_t *data);

void
gcm_encrypt(struct gcm_ctx *ctx, void *cipher, nettle_crypt_func *f,
	    unsigned length, uint8_t *dst, const uint8_t *src);

void
gcm_decrypt(struct gcm_ctx *ctx, void *cipher, nettle_crypt_func *f,
	    unsigned length, uint8_t *dst, const uint8_t *src);

void
gcm_digest(struct gcm_ctx *ctx, void *cipher, nettle_crypt_func *f,
	   unsigned length, uint8_t *digest);

#if 0
/* FIXME: Is this macrology useful? */
#define GCM_KEY(type) \
{ type cipher; struct gcm_ctx gcm; }

#define GCM_SET_KEY(ctx, set_key, encrypt, length, data)	\
  do {								\
    (set_key)(&(ctx)->cipher, (length), (data));		\
    gcm_set_key(&(ctx)->gcm, &(ctx)->cipher, (encrypt));	\
  } while (0)

#define GCM_AUTH(ctx, encrypt, length, data)	    \
  gcm_auth((ctx)->gcm, &(ctx)->cipher, (encrypt),   \
	   (length), (data))

#define GCM_ENCRYPT(ctx, encrypt, length, dst, src)       \
  gcm_encrypt((ctx)->gcm, &(ctx)->cipher, (encrypt),	  \
	      (length), (dst), (src))

#define GCM_DECRYPT(ctx, key, encrypt, length, dst, src)       \
  gcm_decrypt((ctx)->gcm, &(ctx)->cipher, (encrypt),	       \
	      (length), (dst), (src))

#define GCM_DIGEST(ctx, key, encrypt, length, digest)		\
  gcm_digest((ctx)->gcm, &(ctx)->cipher, (encrypt),		\
	     (length), (digest))

struct gcm_aes_ctx GCM_CTX(struct aes_ctx);

void
gcm_aes_set_key(struct gcm_aes_ctx *ctx,
		unsigned length, const uint8_t *key);

void
gcm_aes_set_iv(struct gcm_aes_ctx *ctx,
	       unsigned length, const uint8_t *iv);

void
gcm_aes_auth(struct gcm_aes_ctx *ctx,
	     unsigned length, const uint8_t *data);

void
gcm_aes_encrypt(struct gcm_aes_ctx *ctx,
		unsigned length, uint8_t *dst, const uint8_t *src);

void
gcm_aes_decrypt(struct gcm_aes_ctx *ctx,
		unsigned length, uint8_t *dst, const uint8_t *src);

void
gcm_aes_digest(struct gcm_aes_ctx *ctx,
	       unsigned length, uint8_t *digest);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_GCM_H_INCLUDED */
