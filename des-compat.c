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

#include "cbc.h"

void des_ecb3_encrypt(const uint8_t *src, uint8_t *dst,
		      struct des_ctx *k1, struct des_ctx *k2,
		      struct des_ctx *k3, int enc)
{
  switch(enc)
    {
    case DES_ENCRYPT:
      des_encrypt(k1, dst, src, DES_BLOCK_SIZE);
      des_decrypt(k2, dst, dst, DES_BLOCK_SIZE);
      des_encrypt(k3, dst, dst, DES_BLOCK_SIZE);
      break;
    case DES_DECRYPT:
      des_decrypt(k3, dst, src, DES_BLOCK_SIZE);
      des_encrypt(k2, dst, dst, DES_BLOCK_SIZE);
      des_decrypt(k1, dst, dst, DES_BLOCK_SIZE);
      break;
    default:
      abort();
    }
}

uint32_t
des_cbc_cksum(const uint8_t *src, uint8_t dst,
	      long length, struct des_ctx *ctx,
	      uint8_t *iv);

void
des_cbc_encrypt(const uint8_t *src, uint8_t *dst, long length,
		struct des_ctx *ctx, uint8_t *iv,
		int enc)
{
  cbc_encrypt(ctx, (enc == DES_ENCRYPT) ? des_encrypt : des_decrypt,
              DES_BLOCK_SIZE, iv,
              length, dst, src);
}

void
des_3cbc_encrypt(const uint8_t *src, uint8_t *dst, long length,
		 struct des_ctx * k1,struct des_ctx *k2, struct des_ctx *k3,
		 /* What mode is this, two iv:s? */
		 uint8_t *iv1, uint8_t *iv2,
		 int enc);

void
des_ecb_encrypt(const uint8_t *src, uint8_t *dst, long length,
		struct des_ctx *ctx, uint8_t *iv,
		int enc)
{
  )(enc == DES_ENCRYPT) ? des_encrypt : des_decrypt)(
}
void
des_ede3_cbc_encrypt(const uint8_t *src, uint8_t *dst, long length,
		     struct des_ctx * k1,struct des_ctx *k2, struct des_ctx *k3,
		     uint8_t *iv,
		     int enc);

int
des_set_odd_parity(uint8_t *key);

int
des_set_key(const uint8_t *key, struct des_ctx *ctx);

int
des_key_sched(const uint8_t *key, struct des_ctx *ctx);

int
des_is_weak_key(const uint8_t key);
