/* cbc.h
 *
 * Cipher block chaining mode.
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

#ifndef NETTLE_CBC_H_INCLUDED
#define NETTLE_CBC_H_INCLUDED

#include <inttypes.h>

/* Uses a void * for cipher contexts. */

void
cbc_encrypt(void *ctx, void (*f)(void *ctx,
				 unsigned length, uint8_t *dst,
				 const uint8_t *src),
	    unsigned block_size, uint8_t *iv,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src);

void
cbc_decrypt(void *ctx, void (*f)(void *ctx,
				 unsigned length, uint8_t *dst,
				 const uint8_t *src),
	    unsigned block_size, uint8_t *iv,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src);

/* Type safer variants */
#define CBC_ENCRYPT(ctx, f, b, iv, l, dst, src) \
(0 ? ((f)((ctx),0,NULL,NULL)) \
   : cbc_encrypt((void *)(ctx), \
                 ((*)(void *, unsigned, uint8_t *, const uint8_t *)) (f), \
                 (b), (iv), (l), (dst), (src)))

#endif /* NETTLE_CBC_H_INCLUDED */
