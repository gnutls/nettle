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

#ifndef NETTLE_DES_COMPAT_H_INCLUDED
#define NETTLE_DES_COMPAT_H_INCLUDED

/* According to Assar, des_set_key, des_set_key_odd_parity,
 * des_is_weak_key, plus the encryption functions (des_*_encrypt and
 * des_cbc_cksum) would be a pretty useful subset. */

#include "des.h"

/* FIXME: Names collides with nettle, so we'll need some ugly symbol
 * munging */

void des_ecb3_encrypt(const uint8_t *src, uint8_t *dst,
		      struct des_ctx *k1, struct des_ctx *k2,
		      struct des_ctx *k3, int enc);

uint32_t
des_cbc_cksum(const uint8_t *src, uint8_t dst,
	      long length, struct des_ctx *ctx,
	      uint8_t *iv);

void
des_cbc_encrypt(const uint8_t *src, uint8_t *dst, long length,
		struct des_ctx *ctx, uint8_t *iv,
		int enc);

void
des_3cbc_encrypt(const uint8_t *src, uint8_t *dst, long length,
		 struct des_ctx * k1,struct des_ctx *k2, struct des_ctx *k3,
		 /* What mode is this, two iv:s? */
		 uint8_t *iv1, uint8_t *iv2,
		 int enc);

void
des_ecb_encrypt(const uint8_t *src, uint8_t *dst, long length,
		struct des_ctx *ctx, uint8_t *iv,
		int enc);
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

#endif /* NETTLE_DES_COMPAT_H_INCLUDED */
