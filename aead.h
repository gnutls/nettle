/* aead.h
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2014 Niels Möller
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

#ifndef NETTLE_AEAD_H_INCLUDED
#define NETTLE_AEAD_H_INCLUDED

#include "nettle-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define aead_encrypt_msg_size nettle_aead_encrypt_msg_size
#define aead_encrypt_msg nettle_aead_encrypt_msg
#define aead_decrypt_msg_size nettle_aead_decrypt_msg_size
#define aead_decrypt_msg nettle_aead_decrypt_msg
#define aead_encrypt_ctx_size nettle_aead_encrypt_ctx_size
#define aead_encrypt_init nettle_aead_encrypt_init
#define aead_encrypt nettle_aead_encrypt
#define aead_encrypt_final_size nettle_aead_encrypt_final_size
#define aead_encrypt_final nettle_aead_encrypt_final
#define aead_decrypt_ctx_size nettle_aead_decrypt_ctx_size
#define aead_decrypt_init nettle_aead_decrypt_init
#define aead_decrypt nettle_aead_decrypt
#define aead_decrypt_final_size nettle_aead_decrypt_final_size
#define aead_decrypt_final nettle_aead_decrypt_final

struct nettle_aead;
struct nettle_buffer;

/* Interface for processing a complete message at a time. Application
   must allocate the context and call the set_key function before
   using this interface. */
size_t
aead_encrypt_msg_size (const struct nettle_aead *aead, size_t size);
void
aead_encrypt_msg (const struct nettle_aead *aead,
		  void *ctx, const uint8_t *nonce,
		  size_t ad_size, const uint8_t *ad,
		  size_t plaintext_size,
		  uint8_t *gibberish, const uint8_t *plaintext);

size_t
aead_decrypt_msg_size (const struct nettle_aead *aead, size_t size);
int
aead_decrypt_msg (const struct nettle_aead *aead,
		  void *ctx, const uint8_t *nonce,
		  size_t ad_size, const uint8_t *ad,
		  size_t gibberish_size,
		  uint8_t *plaintext, const uint8_t *gibberish);

/* Streaming interface, including buffering. Uses a context struct
   corresponding to the aead algorithm, with additional buffers added
   at the end. Hence, the context can be passed to algorithm-specific
   functions. Applications should call set_key and set_nonce before
   using these functions. */

#define aead_update(aead, ctx, size, data) \
  ((aead)->update((ctx), (size), (data)))

size_t
aead_encrypt_ctx_size (const struct nettle_aead *aead);

void
aead_encrypt_init (const struct nettle_aead *aead,
		   void *ctx, const uint8_t *nonce);

/* Attempts to grow the destination buffer as needed. Returns the
   amount of plaintext that could be processed. */
size_t
aead_encrypt (const struct nettle_aead *aead,
	      void *ctx, struct nettle_buffer *buffer,
	      size_t size, const uint8_t *plaintext);

/* Maximum output size for aead_encrypt_final. */
size_t
aead_encrypt_final_size (const struct nettle_aead *aead);

/* Returns 1 on success, 0 if buffer was too small and growing it
   failed. On failure, some output may still be generated, and the
   function can be called again with more output space. */
int
aead_encrypt_final (const struct nettle_aead *aead,
		    void *ctx, struct nettle_buffer *buffer);

size_t
aead_decrypt_ctx_size (const struct nettle_aead *aead);

void
aead_decrypt_init (const struct nettle_aead *aead,
		   void *ctx, const uint8_t *nonce);

/* Attempts to grow the destination buffer as needed. Returns the
   amount of plaintext that could be processed. */
size_t
aead_decrypt (const struct nettle_aead *aead,
	      void *ctx, struct nettle_buffer *dst,
	      size_t size, const uint8_t *gibberish);

/* Maximum output size for aead_decrypt_final. */
size_t
aead_decrypt_final_size (const struct nettle_aead *aead);

/* Returns 1 on success, 0 if buffer is too small or authentication
   failed. FIXME: Distinguish between failure cases? */
int
aead_decrypt_final (const struct nettle_aead *aead,
		    void *ctx, struct nettle_buffer *dst);


#ifdef __cplusplus
}
#endif

#endif /* NETTLE_AEAD_H_INCLUDED */
