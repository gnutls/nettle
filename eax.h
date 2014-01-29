/* eax.h
 *
 * EAX mode, see http://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2013 Niels Möller
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
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#ifndef NETTLE_EAX_H_INCLUDED
#define NETTLE_EAX_H_INCLUDED

#include "aes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define eax_set_key nettle_eax_set_key
#define eax_set_nonce nettle_eax_set_nonce
#define eax_update nettle_eax_update
#define eax_encrypt nettle_eax_encrypt
#define eax_decrypt nettle_eax_decrypt
#define eax_digest nettle_eax_digest

#define eax_aes_set_key nettle_eax_aes_set_key
#define eax_aes_set_nonce nettle_eax_aes_set_nonce
#define eax_aes_update nettle_eax_aes_update
#define eax_aes_encrypt nettle_eax_aes_encrypt
#define eax_aes_decrypt nettle_eax_aes_decrypt
#define eax_aes_digest nettle_eax_aes_digest

/* Restricted to block ciphers with 128 bit block size. FIXME: Reflect
   this in naming? */

#define EAX_BLOCK_SIZE 16

/* FIXME: Ensure nice alignment. See gcm.h, union gcm_block. */

/* Values independent of message and nonce */
struct eax_key
{
  union nettle_block16 pad_block;
  union nettle_block16 pad_partial;
};

struct eax_ctx
{
  union nettle_block16 omac_nonce;
  union nettle_block16 omac_data;
  union nettle_block16 omac_message;
  union nettle_block16 ctr;
};

void
eax_set_key (struct eax_key *key, void *cipher, nettle_crypt_func *f);

void
eax_set_nonce (struct eax_ctx *eax, const struct eax_key *key,
	       void *cipher, nettle_crypt_func *f,
	       size_t nonce_length, const uint8_t *nonce);

void
eax_update (struct eax_ctx *eax, const struct eax_key *key,
	    void *cipher, nettle_crypt_func *f,
	    size_t data_length, const uint8_t *data);

void
eax_encrypt (struct eax_ctx *eax, const struct eax_key *key,
	     void *cipher, nettle_crypt_func *f,
	     size_t length, uint8_t *dst, const uint8_t *src);

void
eax_decrypt (struct eax_ctx *eax, const struct eax_key *key,
	     void *cipher, nettle_crypt_func *f,
	     size_t length, uint8_t *dst, const uint8_t *src);

void
eax_digest (struct eax_ctx *eax, const struct eax_key *key,
	    void *cipher, nettle_crypt_func *f,
	    size_t length, uint8_t *digest);

/* Put the cipher last, to get cipher-independent offsets for the EAX
 * state. */
#define EAX_CTX(type) \
  { struct eax_key key; struct eax_ctx eax; type cipher; }

#define EAX_SET_KEY(ctx, set_key, encrypt, data)			\
  do {									\
    (set_key)(&(ctx)->cipher, (data));					\
    if (0) (encrypt) (&(ctx)->cipher, 0, (void *) 0, (void *) 0);	\
    eax_set_key (&(ctx)->key, &(ctx)->cipher, (nettle_crypt_func *) encrypt); \
  } while (0)

#define EAX_SET_NONCE(ctx, encrypt, length, nonce) \
  (0 ? (encrypt) (&(ctx)->cipher, 0, (void *) 0, (void *) 0)	\
   : eax_set_nonce (&(ctx)->eax, &(ctx)->key,			\
		    &(ctx)->cipher, (nettle_crypt_func *) (encrypt),	\
		    (length), (nonce)))

#define EAX_UPDATE(ctx, encrypt, length, data)				\
  (0 ? (encrypt) (&(ctx)->cipher, 0, (void *) 0, (void *) 0)		\
   : eax_update (&(ctx)->eax, &(ctx)->key,				\
		 &(ctx)->cipher, (nettle_crypt_func *) (encrypt),	\
		 (length), (data)))

#define EAX_ENCRYPT(ctx, encrypt, length, dst, src)			\
  (0 ? (encrypt) (&(ctx)->cipher, 0, (void *) 0, (void *) 0)		\
   : eax_encrypt (&(ctx)->eax, &(ctx)->key,				\
		 &(ctx)->cipher, (nettle_crypt_func *) (encrypt),	\
		  (length), (dst), (src)))

#define EAX_DECRYPT(ctx, encrypt, length, dst, src)			\
  (0 ? (encrypt) (&(ctx)->cipher, 0, (void *) 0, (void *) 0)		\
   : eax_decrypt (&(ctx)->eax, &(ctx)->key,				\
		 &(ctx)->cipher, (nettle_crypt_func *) (encrypt),	\
		  (length), (dst), (src)))

#define EAX_DIGEST(ctx, encrypt, length, digest)			\
  (0 ? (encrypt) (&(ctx)->cipher, 0, (void *) 0, (void *) 0)		\
   : eax_digest (&(ctx)->eax, &(ctx)->key,				\
		 &(ctx)->cipher, (nettle_crypt_func *) (encrypt),	\
		 (length), (digest)))

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_EAX_H_INCLUDED */
