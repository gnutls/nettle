/* ocb.h

   OCB AEAD mode, RFC 7253

   Copyright (C) 2021 Niels Möller

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

#ifndef NETTLE_OCB_H_INCLUDED
#define NETTLE_OCB_H_INCLUDED

#include "nettle-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define ocb_set_key nettle_ocb_set_key
#define ocb_set_nonce nettle_ocb_set_nonce
#define ocb_update nettle_ocb_update
#define ocb_encrypt nettle_ocb_encrypt
#define ocb_decrypt nettle_ocb_decrypt
#define ocb_digest nettle_ocb_digest

#define OCB_BLOCK_SIZE 16
#define OCB_DIGEST_SIZE 16

/* Open questions:
   1. Precompute more of the L_i values?

   2. Since processing of the auth data is independent of the nonce, can
      we have some interface for reusing the same auth data with several messages?

   3. Nonce processing seems intended to allow for incrementing the
      nonce cheaply, via the "stretch" bits. Should we implement this,
      maybe as auto-incrementing the nonce (like umac)?
*/

struct ocb_key {
  /* L_*, L_$ and L_0 */
  union nettle_block16 L[3];
};

struct ocb_ctx {
  /* Initial offset, Offset_0 in the spec. */
  union nettle_block16 initial;
  /* Offset, updated per block. */
  union nettle_block16 offset;
  /* Authentication for the associated data */
  union nettle_block16 sum;
  /* Authentication for the message */
  union nettle_block16 checksum;
  /* Count of processed blocks. */
  size_t data_count;
  size_t message_count;
};

void
ocb_set_key (struct ocb_key *key, const void *cipher, nettle_cipher_func *f);

void
ocb_set_nonce (struct ocb_ctx *ctx,
	       const void *cipher, nettle_cipher_func *f,
	       size_t tag_length, size_t nonce_length, const uint8_t *nonce);

void
ocb_update (struct ocb_ctx *ctx, const struct ocb_key *key,
	    const void *cipher, nettle_cipher_func *f,
	    size_t length, const uint8_t *data);

void
ocb_encrypt (struct ocb_ctx *ctx, const struct ocb_key *key,
	     const void *cipher, nettle_cipher_func *f,
	     size_t length, uint8_t *dst, const uint8_t *src);

void
ocb_decrypt (struct ocb_ctx *ctx, const struct ocb_key *key,
	     const void *encrypt_ctx, nettle_cipher_func *encrypt,
	     const void *decrypt_ctx, nettle_cipher_func *decrypt,
	     size_t length, uint8_t *dst, const uint8_t *src);

void
ocb_digest (const struct ocb_ctx *ctx, const struct ocb_key *key,
	    const void *cipher, nettle_cipher_func *f,
	    size_t length, uint8_t *digest);


void
ocb_encrypt_message (const struct ocb_key *ocb_key,
		     const void *cipher, nettle_cipher_func *f,
		     size_t nlength, const uint8_t *nonce,
		     size_t alength, const uint8_t *adata,
		     size_t clength, uint8_t *dst, const uint8_t *src);

void
ocb_decrypt_message (const struct ocb_key *ocb_key,
		     const void *encrypt_ctx, nettle_cipher_func *encrypt,
		     const void *decrypt_ctx, nettle_cipher_func *decrypt,
		     size_t nlength, const uint8_t *nonce,
		     size_t alength, const uint8_t *adata,
		     size_t clength, uint8_t *dst, const uint8_t *src);

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_OCB_H_INCLUDED */
