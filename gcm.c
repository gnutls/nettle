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
 * A few functions copied from Tom S. Dennis' libtomcrypt, which is in
 * the public domain.
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
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "gcm.h"

#include "memxor.h"
#include "nettle-internal.h"
#include "macros.h"

/* The gcm_rightshift and gcm_gf_mul was copied from
 * libtomcrypt, which is under public domain. 
 * Written by Tom S. Dennis.
 */

/* FIXME: Change representation so we can to word-sized shifts? */
static void
gcm_rightshift (uint8_t * a)
{
  int x;
  for (x = 15; x > 0; x--)
    {
      a[x] = (a[x] >> 1) | ((a[x - 1] << 7) & 0x80);
    }
  a[0] >>= 1;
}

/**
  GCM GF multiplier (internal use only) bitserial
  @param a   First value (and destination)
  @param b   Second value
 */
static void
gcm_gf_mul (uint8_t * a, const uint8_t * b)
{
  static const uint8_t mask[] =
    { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
  static const uint8_t poly[] = { 0x00, 0xE1 };

  uint8_t Z[16], V[16];
  unsigned x, z;

  memset (Z, 0, 16);
  memcpy (V, a, 16);
  for (x = 0; x < 128; x++)
    {
      if (b[x >> 3] & mask[x & 7])
        {
          memxor (Z, V, 16);
        }
      z = V[15] & 0x01;
      gcm_rightshift (V);
      V[0] ^= poly[z];
    }
  memcpy (a, Z, 16);
}

/* Increment the rightmost 32 bits. */
#define INC32(block) INCREMENT(4, (block) + GCM_BLOCK_SIZE - 4)

/* Initialization of GCM.
 * @ctx: The context of GCM
 * @cipher: The context of the underlying block cipher
 * @f: The underlying cipher encryption function
 */
void
gcm_set_key(struct gcm_ctx *ctx,
	    void *cipher, nettle_crypt_func f)
{
  memset (ctx->h, 0, sizeof (ctx->h));
  f (cipher, GCM_BLOCK_SIZE, ctx->h, ctx->h);  /* H */
#if GCM_TABLE_BITS
  /* FIXME: Expand hash subkey */
  abort();
#endif
}

/*
 * @length: The size of the iv (fixed for now to GCM_NONCE_SIZE)
 * @iv: The iv
 */
void
gcm_set_iv(struct gcm_ctx *ctx, unsigned length, const uint8_t* iv)
{
  /* FIXME: remove the iv size limitation */
  assert (length == GCM_IV_SIZE);

  memcpy (ctx->iv, iv, GCM_BLOCK_SIZE - 4);
  ctx->iv[GCM_BLOCK_SIZE - 4] = 0;
  ctx->iv[GCM_BLOCK_SIZE - 3] = 0;
  ctx->iv[GCM_BLOCK_SIZE - 2] = 0;
  ctx->iv[GCM_BLOCK_SIZE - 1] = 1;

  memcpy (ctx->ctr, ctx->iv, GCM_BLOCK_SIZE);
  INC32 (ctx->ctr);

  /* Reset the rest of the message-dependent state. */
  memset(ctx->x, 0, sizeof(ctx->x));
  ctx->auth_size = ctx->data_size = 0;
}

static void
gcm_hash(struct gcm_ctx *ctx, unsigned length, const uint8_t *data)
{
  for (; length >= GCM_BLOCK_SIZE;
       length -= GCM_BLOCK_SIZE, data += GCM_BLOCK_SIZE)
    {
      memxor (ctx->x, data, GCM_BLOCK_SIZE);
      gcm_gf_mul (ctx->x, ctx->h);
    }
  if (length > 0)
    {
      memxor (ctx->x, data, length);
      gcm_gf_mul (ctx->x, ctx->h);
    }
}

void
gcm_auth(struct gcm_ctx *ctx,
	 unsigned length, const uint8_t *data)
{
  assert(ctx->auth_size % GCM_BLOCK_SIZE == 0);
  assert(ctx->data_size % GCM_BLOCK_SIZE == 0);

  gcm_hash(ctx, length, data);

  ctx->auth_size += length;
}

static void
gcm_crypt(struct gcm_ctx *ctx, void *cipher, nettle_crypt_func *f,
	  unsigned length,
	   uint8_t *dst, const uint8_t *src)
{
  uint8_t buffer[GCM_BLOCK_SIZE];

  if (src != dst)
    {
      for (; length >= GCM_BLOCK_SIZE;
           (length -= GCM_BLOCK_SIZE,
	    src += GCM_BLOCK_SIZE, dst += GCM_BLOCK_SIZE))
        {
          f (cipher, GCM_BLOCK_SIZE, dst, ctx->ctr);
          memxor (dst, src, GCM_BLOCK_SIZE);
          INC32 (ctx->ctr);
        }
    }
  else
    {
      for (; length >= GCM_BLOCK_SIZE;
           (length -= GCM_BLOCK_SIZE,
	    src += GCM_BLOCK_SIZE, dst += GCM_BLOCK_SIZE))
        {
          f (cipher, GCM_BLOCK_SIZE, buffer, ctx->ctr);
          memxor3 (dst, src, buffer, GCM_BLOCK_SIZE);
          INC32 (ctx->ctr);
        }
    }
  if (length > 0)
    {
      /* A final partial block */
      f (cipher, GCM_BLOCK_SIZE, buffer, ctx->ctr);
      memxor3 (dst, src, buffer, length);
      INC32 (ctx->ctr);
    }
}

void
gcm_encrypt (struct gcm_ctx *ctx, void *cipher, nettle_crypt_func *f,
	     unsigned length,
             uint8_t *dst, const uint8_t *src)
{
  assert(ctx->data_size % GCM_BLOCK_SIZE == 0);

  gcm_crypt(ctx, cipher, f, length, dst, src);
  gcm_hash(ctx, length, dst);

  ctx->data_size += length;
}

void
gcm_decrypt(struct gcm_ctx *ctx, void *cipher, nettle_crypt_func *f,
	    unsigned length, uint8_t *dst, const uint8_t *src)
{
  assert(ctx->data_size % GCM_BLOCK_SIZE == 0);

  gcm_hash(ctx, length, src);
  gcm_crypt(ctx, cipher, f, length, dst, src);

  ctx->data_size += length;
}

void
gcm_digest(struct gcm_ctx *ctx, void *cipher, nettle_crypt_func *f,
	   unsigned length, uint8_t *digest)
{
  uint8_t buffer[GCM_BLOCK_SIZE];

  assert (length <= GCM_BLOCK_SIZE);

  ctx->data_size *= 8;
  ctx->auth_size *= 8;

  WRITE_UINT64 (buffer, ctx->auth_size);
  WRITE_UINT64 (buffer + 8, ctx->data_size);

  gcm_hash(ctx, GCM_BLOCK_SIZE, buffer);

  f (cipher, GCM_BLOCK_SIZE, buffer, ctx->iv);
  memxor3 (digest, ctx->x, buffer, length);

  return;
}
