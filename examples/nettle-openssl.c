/* nettle-openssl.c
 *
 * Glue that's used only by the benchmark, and subject to change.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2002 Niels Möller
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

#if HAVE_CONFIG_H
# include "config.h"
#endif /* HAVE_CONFIG_H */

/* Openssl glue, for comparative benchmarking only */

#if HAVE_LIBCRYPTO

#include "nettle-internal.h"

#include <openssl/blowfish.h>
#include <openssl/des.h>
#include <openssl/cast.h>

#include <assert.h>


/* Blowfish */
static void
openssl_bf_set_key(void *ctx, unsigned length, const uint8_t *key)
{
  BF_set_key(ctx, length, key);
}


static void
openssl_bf_encrypt(void *ctx, unsigned length,
		   uint8_t *dst, const uint8_t *src)
{
  assert (!(length % BF_BLOCK));
  while (length)
    {
      BF_ecb_encrypt(src, dst, ctx, BF_ENCRYPT);
      length -= BF_BLOCK;
      dst += BF_BLOCK;
      src += BF_BLOCK;
    }
}

static void
openssl_bf_decrypt(void *ctx, unsigned length,
		   uint8_t *dst, const uint8_t *src)
{
  assert (!(length % BF_BLOCK));
  while (length)
    {
      BF_ecb_encrypt(src, dst, ctx, BF_DECRYPT);
      length -= BF_BLOCK;
      dst += BF_BLOCK;
      src += BF_BLOCK;
    }
}

const struct nettle_cipher
nettle_openssl_blowfish128 = {
  "openssl bf128", sizeof(BF_KEY),
  /* Claim no block size, so that the benchmark doesn't try CBC mode
   * (as openssl cipher + nettle cbc is somewhat pointless to
   * benchmark). */
  0, 16,
  openssl_bf_set_key, openssl_bf_set_key,
  openssl_bf_encrypt, openssl_bf_decrypt
};


/* DES */
static void
openssl_des_set_key(void *ctx, unsigned length, const uint8_t *key)
{
  assert(length == 8);
  des_key_sched((char *) key, ctx);
}

#define DES_BLOCK_SIZE 8

static void
openssl_des_encrypt(void *ctx, unsigned length,
		    uint8_t *dst, const uint8_t *src)
{
  assert (!(length % DES_BLOCK_SIZE));
  while (length)
    {
      des_ecb_encrypt((char *) src, (char *) dst, ctx, DES_ENCRYPT);
      length -= DES_BLOCK_SIZE;
      dst += DES_BLOCK_SIZE;
      src += DES_BLOCK_SIZE;
    }
}

static void
openssl_des_decrypt(void *ctx, unsigned length,
		    uint8_t *dst, const uint8_t *src)
{
  assert (!(length % DES_BLOCK_SIZE));
  while (length)
    {
      des_ecb_encrypt((char *) src, (char *) dst, ctx, DES_DECRYPT);
      length -= DES_BLOCK_SIZE;
      dst += DES_BLOCK_SIZE;
      src += DES_BLOCK_SIZE;
    }
}

const struct nettle_cipher
nettle_openssl_des = {
  "openssl des", sizeof(des_key_schedule),
  /* Claim no block size, so that the benchmark doesn't try CBC mode
   * (as openssl cipher + nettle cbc is somewhat pointless to
   * benchmark). */
  0, 8,
  openssl_des_set_key, openssl_des_set_key,
  openssl_des_encrypt, openssl_des_decrypt
};


/* Cast128 */
static void
openssl_cast_set_key(void *ctx, unsigned length, const uint8_t *key)
{
  CAST_set_key(ctx, length, key);
}

static void
openssl_cast_encrypt(void *ctx, unsigned length,
		     uint8_t *dst, const uint8_t *src)
{
  assert (!(length % CAST_BLOCK));
  while (length)
    {
      CAST_ecb_encrypt(src, dst, ctx, CAST_ENCRYPT);
      length -= CAST_BLOCK;
      dst += CAST_BLOCK;
      src += CAST_BLOCK;
    }
}

static void
openssl_cast_decrypt(void *ctx, unsigned length,
		     uint8_t *dst, const uint8_t *src)
{
  assert (!(length % CAST_BLOCK));
  while (length)
    {
      CAST_ecb_encrypt(src, dst, ctx, CAST_DECRYPT);
      length -= CAST_BLOCK;
      dst += CAST_BLOCK;
      src += CAST_BLOCK;
    }
}

const struct nettle_cipher
nettle_openssl_cast128 = {
  "openssl cast128", sizeof(CAST_KEY),
  /* Claim no block size, so that the benchmark doesn't try CBC mode
   * (as openssl cipher + nettle cbc is somewhat pointless to
   * benchmark). */
  0, CAST_KEY_LENGTH,
  openssl_cast_set_key, openssl_cast_set_key,
  openssl_cast_encrypt, openssl_cast_decrypt
};

#endif /* HAVE_LIBCRYPTO */
