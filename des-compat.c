/* des-compat.h
 *
 * The des block cipher, libdes/openssl-style interface.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001 Niels Möller
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

#include "des-compat.h"

#undef des_set_key

#include "cbc.h"
#include "memxor.h"

#include <string.h>
#include <assert.h>

struct des_compat_des3 { struct des_ctx *keys[3]; }; 

typedef void (*cbc_crypt_func)(void *, uint32_t, uint8_t *, const uint8_t *);

static void
des_compat_des3_encrypt(struct des_compat_des3 *ctx,
			uint32_t length, uint8_t *dst, const uint8_t *src)
{
  des_encrypt(ctx->keys[0], length, dst, src);
  des_decrypt(ctx->keys[1], length, dst, dst);
  des_encrypt(ctx->keys[2], length, dst, dst);
}

static void
des_compat_des3_decrypt(struct des_compat_des3 *ctx,
			uint32_t length, uint8_t *dst, const uint8_t *src)
{
  des_decrypt(ctx->keys[0], length, dst, src);
  des_encrypt(ctx->keys[1], length, dst, dst);
  des_decrypt(ctx->keys[2], length, dst, dst);
}

void
des_ecb3_encrypt(const uint8_t *src, uint8_t *dst,
		 struct des_ctx *k1, struct des_ctx *k2,
		 struct des_ctx *k3, int enc)
{
  struct des_compat_des3 keys = { { k1, k2, k3 } };

  ((enc == DES_ENCRYPT) ? des_compat_des3_encrypt : des_compat_des3_decrypt)
    (&keys, DES_BLOCK_SIZE, dst, src);
}

void
des_cbc_cksum(const uint8_t *src, uint8_t *dst,
	      long length, struct des_ctx *ctx,
	      uint8_t *iv)
{
  /* FIXME: I'm not entirely sure how this function is supposed to
   * work, in particular what it should return, and if iv can be
   * modified. */
  uint8_t block[DES_BLOCK_SIZE];
  memcpy(block, iv, DES_BLOCK_SIZE);

  assert(!(length % DES_BLOCK_SIZE));
  
  for ( ; length; length -= DES_BLOCK_SIZE, src += DES_BLOCK_SIZE)
    {
      memxor(iv, src, DES_BLOCK_SIZE);
      des_encrypt(ctx, DES_BLOCK_SIZE, block, block);
    }
  memcpy(dst, block, DES_BLOCK_SIZE);
}


void
des_cbc_encrypt(const uint8_t *src, uint8_t *dst, long length,
		struct des_ctx *ctx, uint8_t *iv,
		int enc)
{
  cbc_encrypt(ctx,
	      (cbc_crypt_func) ((enc == DES_ENCRYPT) ? des_encrypt : des_decrypt),
              DES_BLOCK_SIZE, iv,
              length, dst, src);
}

void
des_3cbc_encrypt(const uint8_t *src, uint8_t *dst, long length,
		 struct des_ctx * k1,struct des_ctx *k2,
		 /* What mode is this, two iv:s? */
		 uint8_t *iv1, uint8_t *iv2,
		 int enc);

void
des_ecb_encrypt(const uint8_t *src, uint8_t *dst, long length,
		struct des_ctx *ctx,
		int enc)
{
  ((enc == DES_ENCRYPT) ? des_encrypt : des_decrypt)(ctx, length, dst, src);
}

void
des_ede3_cbc_encrypt(const uint8_t *src, uint8_t *dst, long length,
		     struct des_ctx * k1, struct des_ctx *k2, struct des_ctx *k3,
		     uint8_t *iv,
		     int enc)
{
  struct des_compat_des3 keys = { { k1, k2, k3 } };

  if (enc == DES_ENCRYPT)
    cbc_encrypt(&keys, (cbc_crypt_func) des_compat_des3_encrypt,
		DES_BLOCK_SIZE, iv,
		length, dst, src);
  else
    cbc_decrypt(&keys, (cbc_crypt_func) des_compat_des3_decrypt,
		DES_BLOCK_SIZE, iv,
		length, dst, src);
}

int
des_set_odd_parity(uint8_t *key)
{
  des_fix_parity(DES_KEY_SIZE, key, key);

  /* FIXME: What to return? */
  return 0;
}

/* Returns 0 for ok, -1 for bad parity, and -2 for weak keys. */
int
des_key_sched(const uint8_t *key, struct des_ctx *ctx)
{
  if (des_set_key(ctx, key))
    return 0;
  else switch(ctx->status)
    {
    case DES_BAD_PARITY:
      return -1;
    case DES_WEAK_KEY:
      return -2;
    default:
      abort();
    }
}

int
des_is_weak_key(const uint8_t *key)
{
  struct des_ctx ctx;

  return !des_set_key(&ctx, key);
}
