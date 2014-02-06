/* cast128.h
 *
 * The CAST-128 block cipher.
 */

/*	CAST-128 in C
 *	Written by Steve Reid <sreid@sea-to-sky.net>
 *	100% Public Domain - no warranty
 *	Released 1997.10.11
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001, 2014 Niels Möller
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
 
#ifndef NETTLE_CAST128_H_INCLUDED
#define NETTLE_CAST128_H_INCLUDED

#include "nettle-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define cast5_set_key nettle_cast5_set_key
#define cast128_set_key nettle_cast128_set_key
#define cast128_encrypt nettle_cast128_encrypt
#define cast128_decrypt nettle_cast128_decrypt

#define CAST128_BLOCK_SIZE 8

/* Variable key size between 40 and 128. */
#define CAST5_MIN_KEY_SIZE 5
#define CAST5_MAX_KEY_SIZE 16

#define CAST128_KEY_SIZE 16

struct cast128_ctx
{
  unsigned rounds;  /* Number of rounds to use, 12 or 16 */
  /* Expanded key, rotations (5 bits only) and 32-bit masks. */
  unsigned char Kr[16];
  uint32_t Km[16];
};

/* Using variable key size. */
void
cast5_set_key(struct cast128_ctx *ctx,
	      size_t length, const uint8_t *key);

void
cast128_set_key(struct cast128_ctx *ctx, const uint8_t *key);

void
cast128_encrypt(const struct cast128_ctx *ctx,
		size_t length, uint8_t *dst,
		const uint8_t *src);
void
cast128_decrypt(const struct cast128_ctx *ctx,
		size_t length, uint8_t *dst,
		const uint8_t *src);

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_CAST128_H_INCLUDED */
