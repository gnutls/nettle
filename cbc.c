/* cbc.c
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

#include "cbc.h"

#include "memxor.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

void
cbc_encrypt(void *ctx, void (*f)(void *ctx,
				 unsigned length, uint8_t *dst,
				 const uint8_t *src),
	    unsigned block_size, uint8_t *iv,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
  assert(!(length % block_size));

  for ( ; length; length -= block_size, src += block_size, dst += block_size)
    {
      memxor(iv, src, block_size);
      f(ctx, block_size, dst, src);
      memcpy(iv, dst, block_size);
    }
}

void
cbc_decrypt(void *ctx, void (*f)(void *ctx,
				 unsigned length, uint8_t *dst,
				 const uint8_t *src),
	    unsigned block_size, uint8_t *iv,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
  assert(!(length % block_size));

  if (!length)
    return;

  if (src == dst)
    {
      /* Keep a copy of the ciphertext. */
      /* FIXME: If length is large enough, allocate a smaller buffer
       * and process one buffer size at a time */
      uint8_t *tmp = alloca(length);
      memcpy(tmp, src, length);
      src = tmp;
    }

  /* Decrypt in ECB mode */
  f(ctx, length, dst, src);

  /* XOR the cryptotext, shifted one block */
  memxor(dst, iv, block_size);
  memxor(dst + block_size, src, length - block_size);
  memcpy(iv, src + length - block_size, block_size);
}

#if 0
#include "twofish.h"
#include "aes.h"

static void foo(void)
{
  struct CBC_CTX(struct twofish_ctx, TWOFISH_BLOCK_SIZE) ctx;
  uint8_t src[TWOFISH_BLOCK_SIZE];
  uint8_t dst[TWOFISH_BLOCK_SIZE];
  
  CBC_ENCRYPT(&ctx, twofish_encrypt, TWOFISH_BLOCK_SIZE, dst, src);

  /* Should result in a warning */
  CBC_ENCRYPT(&ctx, aes_encrypt, TWOFISH_BLOCK_SIZE, dst, src);
  
}

static void foo2(void)
{
  struct twofish_ctx ctx;
  uint8_t iv[TWOFISH_BLOCK_SIZE];
  uint8_t src[TWOFISH_BLOCK_SIZE];
  uint8_t dst[TWOFISH_BLOCK_SIZE];
  
  CBC_ENCRYPT2(&ctx, twofish_encrypt, TWOFISH_BLOCK_SIZE, iv, TWOFISH_BLOCK_SIZE, dst, src);
  /* Should result in a warning */
  CBC_ENCRYPT2(&ctx, aes_encrypt, TWOFISH_BLOCK_SIZE, iv, TWOFISH_BLOCK_SIZE, dst, src);
}

#endif
