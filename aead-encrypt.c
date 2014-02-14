/* aead-encrypt.c
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2014 Niels Möller
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include "aead.h"

#include "nettle-meta.h"
#include "buffer.h"

/* Needs a buffer of block_size - 1 bytes. Let this be followed by an
   uint8_t buffer index; using a small type avoids alignment
   issues. */
#define GET_BUF(aead, ctx) \
  ((uint8_t *)((char *) (ctx) + (aead)->context_size))

size_t
aead_encrypt_ctx_size (const struct nettle_aead *aead)
{
  return aead->context_size + aead->block_size;
}

void
aead_encrypt_init (const struct nettle_aead *aead,
		   void *ctx, const uint8_t *nonce)
{
  /* The case of unbuffered underlying method not supported. Niether
     is block sizes larger than 256 bytes. */
  assert (aead->block_size > 0);
  assert (aead->block_size <= 256);

  /* Allow NULL nonce, for the case that the caller already has done
     that. E.g., if the application uses a nonce size different from
     aead->nonce_size. */
  if (nonce)
    aead->set_nonce (ctx, nonce);

  /* Initialize buffer index. */
  GET_BUF (aead, ctx)[aead->block_size-1] = 0;
}

size_t
aead_encrypt (const struct nettle_aead *aead,
	      void *ctx, struct nettle_buffer *buffer,
	      size_t size, const uint8_t *plaintext)
{
  uint8_t *buf;
  uint8_t *dst;
  uint8_t left_over;
  size_t done;
  
  buf = GET_BUF (aead, ctx);
  left_over = buf[aead->block_size-1];
  assert (left_over < aead->block_size);

  if (left_over > 0)
    {
      /* Try to fill buffer */
      if (size >= aead->block_size - left_over)
	{
	  dst = nettle_buffer_space (buffer, aead->block_size);
	  if (!dst)
	    /* Would could copy some more data into our buffer, but we
	       really can't make any progress until the caller
	       provides a larger output buffer. */
	    return 0;

	  done = aead->block_size - left_over;
	  memcpy (buf + left_over, plaintext, done);
	  aead->encrypt (ctx, aead->block_size, dst, buf);
	  size -= done;
	  plaintext += done;
	}
      else
	{
	  memcpy (buf + left_over, plaintext, size);
	  left_over += size;
	  assert (left_over < aead->block_size);
	  buf[aead->block_size-1] = left_over;
	  return size;
	}
    }
  else
    done = 0;

  left_over = size % aead->block_size;

  dst = nettle_buffer_space (buffer, size - left_over);
  if (dst)
    {
      /* Buffer rest of input. */
      size -= left_over;
      memcpy (buf, plaintext + size, left_over);
      done += left_over;
    }
  else
    {
      /* Process as many blocks as possible, without growing the buffer. */
      size_t avail = (buffer->alloc - buffer->size);
      avail -= (avail % aead->block_size);
      assert (avail < size);
      size = avail;
      left_over = 0;
      dst = nettle_buffer_space (buffer, size);
      assert (dst != NULL);
    }
  aead->encrypt (ctx, size, dst, plaintext);
  done += size;

  buf[aead->block_size-1] = left_over;

  return done;
}

size_t
aead_encrypt_final_size (const struct nettle_aead *aead)
{
  return aead->digest_size + aead->block_size - 1;
}

int
aead_encrypt_final (const struct nettle_aead *aead,
		    void *ctx, struct nettle_buffer *buffer)
{
  uint8_t *buf = GET_BUF (aead, ctx);
  uint8_t *dst;
  uint8_t left_over = buf[aead->block_size - 1];
  assert (left_over < aead->block_size);
  if (left_over)
    {
      dst = nettle_buffer_space (buffer, left_over);
      if (!dst)
	return 0;
      aead->encrypt (ctx, left_over, dst, buf);
      buf[aead->block_size - 1] = 0;
    }
  dst = nettle_buffer_space (buffer, aead->digest_size);
  if (!dst)
    return 0;
  aead->digest (ctx, aead->digest_size, dst);
  return 1;
}
