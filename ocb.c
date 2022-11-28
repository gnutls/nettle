/* ocb.c

   OCB AEAD mode, RFC 7253

   Copyright (C) 2021 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include "ocb.h"
#include "block-internal.h"

/* FIXME: Duplicated in nist-keywrap.c */
#if WORDS_BIGENDIAN
#define bswap_if_le(x) (x)
#elif HAVE_BUILTIN_BSWAP64
#define bswap_if_le(x) (__builtin_bswap64 (x))
#else
static uint64_t
bswap_if_le (uint64_t x)
{
  x = ((x >> 32) & UINT64_C (0xffffffff))
    | ((x & UINT64_C (0xffffffff)) << 32);
  x = ((x >> 16) & UINT64_C (0xffff0000ffff))
    | ((x & UINT64_C (0xffff0000ffff)) << 16);
  x = ((x >> 8) & UINT64_C (0xff00ff00ff00ff))
    | ((x & UINT64_C (0xff00ff00ff00ff)) << 8);
  return x;
}
#endif

/* Returns 64 bits from the concatenation (u0, u1), starting from bit offset. */
static inline uint64_t
extract(uint64_t u0, uint64_t u1, unsigned offset)
{
  if (offset == 0)
    return u0;
  u0 = bswap_if_le(u0);
  u1 = bswap_if_le(u1);
  return bswap_if_le((u0 << offset) | (u1 >> (64 - offset)));
}

void
ocb_set_key (struct ocb_key *key, const void *cipher, nettle_cipher_func *f)
{
  static const union nettle_block16 zero_block;
  f (cipher, OCB_BLOCK_SIZE, key->L[0].b, zero_block.b);
  block16_mulx_be (&key->L[1], &key->L[0]);
  block16_mulx_be (&key->L[2], &key->L[1]);
}

/* Add x^k L[2], where k is the number of trailing zero bits in i. */
static void
update_offset(const struct ocb_key *key,
	      union nettle_block16 *offset, size_t i)
{
  if (i & 1)
    block16_xor (offset, &key->L[2]);
  else
    {
      assert (i > 0);
      union nettle_block16 diff;
      block16_mulx_be (&diff, &key->L[2]);
      for (i >>= 1; !(i&1); i >>= 1)
	block16_mulx_be (&diff, &diff);

      block16_xor (offset, &diff);
    }
}

static void
pad_block (union nettle_block16 *block, size_t length, const uint8_t *data)
{
  memcpy (block->b, data, length);
  block->b[length] = 0x80;
  memset (block->b + length + 1, 0, OCB_BLOCK_SIZE - 1 - length);
}

void
ocb_set_nonce (struct ocb_ctx *ctx,
	       const void *cipher, nettle_cipher_func *f,
	       size_t tag_length,
	       size_t nonce_length, const uint8_t *nonce)
{
  union nettle_block16 top;
  uint64_t stretch;

  unsigned bottom;
  assert (nonce_length < 16);
  assert (tag_length > 0);
  assert (tag_length <= 16);

  /* Bit size, or zero for tag_length == 16 */
  top.b[0] = (tag_length & 15) << 4;
  memset (top.b + 1, 0, 15 - nonce_length);
  top.b[15 - nonce_length] |= 1;
  memcpy (top.b + 16 - nonce_length, nonce, nonce_length);
  bottom = top.b[15] & 0x3f;
  top.b[15] &= 0xc0;

  f (cipher, OCB_BLOCK_SIZE, top.b, top.b);

  stretch = top.u64[0];
#if WORDS_BIGENDIAN
  stretch ^= (top.u64[0] << 8) | (top.u64[1] >> 56);
#else
  stretch ^= (top.u64[0] >> 8) | (top.u64[1] << 56);
#endif

  ctx->initial.u64[0] = extract(top.u64[0], top.u64[1], bottom);
  ctx->initial.u64[1] = extract(top.u64[1], stretch, bottom);
  ctx->sum.u64[0] = ctx->sum.u64[1] = 0;
  ctx->checksum.u64[0] = ctx->checksum.u64[1] = 0;

  ctx->data_count = ctx->message_count = 0;
}

void
ocb_update (struct ocb_ctx *ctx, const struct ocb_key *key,
	    const void *cipher, nettle_cipher_func *f,
	    size_t length, const uint8_t *data)
{
  assert (ctx->message_count == 0);

  if (ctx->data_count == 0)
    ctx->offset.u64[0] = ctx->offset.u64[1] = 0;

  for (; length >= OCB_BLOCK_SIZE;
       length -= OCB_BLOCK_SIZE, data += OCB_BLOCK_SIZE)
    {
      union nettle_block16 block;
      update_offset (key, &ctx->offset, ++ctx->data_count);
      memxor3 (block.b, ctx->offset.b, data, OCB_BLOCK_SIZE);
      f (cipher, OCB_BLOCK_SIZE, block.b, block.b);
      block16_xor (&ctx->sum, &block);
    }
  if (length > 0)
    {
      union nettle_block16 block;
      pad_block (&block, length, data);
      block16_xor (&ctx->offset, &key->L[0]);
      block16_xor (&block, &ctx->offset);

      f (cipher, OCB_BLOCK_SIZE, block.b, block.b);
      block16_xor (&ctx->sum, &block);
    }
}

void
ocb_encrypt (struct ocb_ctx *ctx, const struct ocb_key *key,
	     const void *cipher, nettle_cipher_func *f,
	     size_t length, uint8_t *dst, const uint8_t *src)
{
  if (ctx->message_count == 0)
    ctx->offset = ctx->initial;

  for (; length >= OCB_BLOCK_SIZE;
       length -= OCB_BLOCK_SIZE, src += OCB_BLOCK_SIZE, dst += OCB_BLOCK_SIZE)
    {
      union nettle_block16 block;
      memxor (ctx->checksum.b, src, OCB_BLOCK_SIZE);
      update_offset (key, &ctx->offset, ++ctx->message_count);

      memxor3 (block.b, ctx->offset.b, src, OCB_BLOCK_SIZE);
      f (cipher, OCB_BLOCK_SIZE, block.b, block.b);

      memxor3 (dst, ctx->offset.b, block.b, OCB_BLOCK_SIZE);
    }

  if (length > 0)
    {
      union nettle_block16 block;
      pad_block (&block, length, src);
      block16_xor (&ctx->checksum, &block);

      block16_xor (&ctx->offset, &key->L[0]);
      f (cipher, OCB_BLOCK_SIZE, block.b, ctx->offset.b);
      memxor3 (dst, block.b, src, length);
      ctx->message_count++;
    }
}

void
ocb_decrypt (struct ocb_ctx *ctx, const struct ocb_key *key,
	     const void *encrypt_ctx, nettle_cipher_func *encrypt,
	     const void *decrypt_ctx, nettle_cipher_func *decrypt,
	     size_t length, uint8_t *dst, const uint8_t *src)
{
  if (ctx->message_count == 0)
    ctx->offset = ctx->initial;

  for (; length >= OCB_BLOCK_SIZE;
       length -= OCB_BLOCK_SIZE, src += OCB_BLOCK_SIZE, dst += OCB_BLOCK_SIZE)
    {
      union nettle_block16 block;
      update_offset (key, &ctx->offset, ++ctx->message_count);

      memxor3 (block.b, ctx->offset.b, src, OCB_BLOCK_SIZE);
      decrypt (decrypt_ctx, OCB_BLOCK_SIZE, block.b, block.b);

      memxor3 (dst, ctx->offset.b, block.b, OCB_BLOCK_SIZE);
      memxor (ctx->checksum.b, dst, OCB_BLOCK_SIZE);
    }

  if (length > 0)
    {
      union nettle_block16 block;

      block16_xor (&ctx->offset, &key->L[0]);
      encrypt (encrypt_ctx, OCB_BLOCK_SIZE, block.b, ctx->offset.b);
      memxor3 (dst, block.b, src, length);

      pad_block (&block, length, dst);
      block16_xor (&ctx->checksum, &block);
      ctx->message_count++;
    }
}

void
ocb_digest (const struct ocb_ctx *ctx, const struct ocb_key *key,
	    const void *cipher, nettle_cipher_func *f,
	    size_t length, uint8_t *digest)
{
  union nettle_block16 block;
  assert (length <= OCB_DIGEST_SIZE);
  block16_xor3 (&block,  &key->L[1],
		(ctx->message_count > 0) ? &ctx->offset : &ctx->initial);
  block16_xor (&block, &ctx->checksum);
  f (cipher, OCB_BLOCK_SIZE, block.b, block.b);
  memxor3 (digest, block.b, ctx->sum.b, length);
}
