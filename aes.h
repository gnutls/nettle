/* aes.h
 *
 * The aes/rijndael block cipher.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001, 2013 Niels Möller
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
 
#ifndef NETTLE_AES_H_INCLUDED
#define NETTLE_AES_H_INCLUDED

#include "nettle-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define aes_set_encrypt_key nettle_aes_set_encrypt_key
#define aes_set_decrypt_key nettle_aes_set_decrypt_key
#define aes_invert_key nettle_aes_invert_key
#define aes_encrypt nettle_aes_encrypt
#define aes_decrypt nettle_aes_decrypt
#define aes128_set_encrypt_key nettle_aes128set_encrypt_key
#define aes128_set_decrypt_key nettle_aes128set_decrypt_key
#define aes128_invert_key nettle_aes128invert_key
#define aes128_encrypt nettle_aes128encrypt
#define aes128_decrypt nettle_aes128decrypt
#define aes192_set_encrypt_key nettle_aes192set_encrypt_key
#define aes192_set_decrypt_key nettle_aes192set_decrypt_key
#define aes192_invert_key nettle_aes192invert_key
#define aes192_encrypt nettle_aes192encrypt
#define aes192_decrypt nettle_aes192decrypt

#define AES_BLOCK_SIZE 16

#define AES128_KEY_SIZE 16
#define AES192_KEY_SIZE 24
#define AES256_KEY_SIZE 32
#define _AES128_ROUNDS 10
#define _AES192_ROUNDS 12
#define _AES256_ROUNDS 14

/* Variable key size between 128 and 256 bits. But the only valid
 * values are 16 (128 bits), 24 (192 bits) and 32 (256 bits). */
#define AES_MIN_KEY_SIZE AES128_KEY_SIZE
#define AES_MAX_KEY_SIZE AES256_KEY_SIZE

/* Older nettle-2.7 interface */

#define AES_KEY_SIZE 32

struct aes_ctx
{
  unsigned rounds;  /* number of rounds to use for our key size */
  uint32_t keys[4*(_AES256_ROUNDS + 1)];  /* maximum size of key schedule */
};

void
aes_set_encrypt_key(struct aes_ctx *ctx,
		    size_t length, const uint8_t *key);

void
aes_set_decrypt_key(struct aes_ctx *ctx,
		   size_t length, const uint8_t *key);

void
aes_invert_key(struct aes_ctx *dst,
	       const struct aes_ctx *src);

void
aes_encrypt(const struct aes_ctx *ctx,
	    size_t length, uint8_t *dst,
	    const uint8_t *src);
void
aes_decrypt(const struct aes_ctx *ctx,
	    size_t length, uint8_t *dst,
	    const uint8_t *src);

struct aes128_ctx
{
  uint32_t keys[4 * (_AES128_ROUNDS + 1)];
};

void
aes128_set_encrypt_key(struct aes128_ctx *ctx, const uint8_t *key);
void
aes128_set_decrypt_key(struct aes128_ctx *ctx, const uint8_t *key);
void
aes128_invert_key(struct aes128_ctx *dst,
		  const struct aes128_ctx *src);
void
aes128_encrypt(const struct aes128_ctx *ctx,
	       size_t length, uint8_t *dst,
	       const uint8_t *src);
void
aes128_decrypt(const struct aes128_ctx *ctx,
	       size_t length, uint8_t *dst,
	       const uint8_t *src);

struct aes192_ctx
{
  uint32_t keys[4 * (_AES192_ROUNDS + 1)];
};

void
aes192_set_encrypt_key(struct aes192_ctx *ctx, const uint8_t *key);
void
aes192_set_decrypt_key(struct aes192_ctx *ctx, const uint8_t *key);
void
aes192_invert_key(struct aes192_ctx *dst,
		  const struct aes192_ctx *src);
void
aes192_encrypt(const struct aes192_ctx *ctx,
	       size_t length, uint8_t *dst,
	       const uint8_t *src);
void
aes192_decrypt(const struct aes192_ctx *ctx,
	       size_t length, uint8_t *dst,
	       const uint8_t *src);

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_AES_H_INCLUDED */
