/* des.h
 *
 * The des block cipher.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 1992, 2001, Dana L. How, Niels Möller
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

/*
 *	des - fast & portable DES encryption & decryption.
 *	Copyright (C) 1992  Dana L. How
 *	Please see the file `../lib/descore.README' for the complete copyright
 *	notice.
 *
 * Slightly edited by Niels Möller, 1997
 */

#ifndef NETTLE_DES_H
#define NETTLE_DES_H

#include <inttypes.h>

#define DES_KEY_SIZE 8
#define DES_BLOCK_SIZE 8

/* Expanded key length */
#define _DES_KEY_LENGTH 32

enum des_error { DES_OK, DES_BAD_PARITY, DES_WEAK_KEY };

struct des_ctx
{
  uint32_t key[_DES_KEY_LENGTH];
  enum des_error status;
};

/* On success, returns 1 and sets ctx->status to DES_OK (zero). On
 * error, returns 0 and sets ctx->status accordingly. */
int
des_set_key(struct des_ctx *ctx, const uint8_t *key);

void
des_encrypt(struct des_ctx *ctx,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src);
void
des_decrypt(struct des_ctx *ctx,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src);

#endif /* NETTLE_DES_H */
