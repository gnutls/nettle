/* aes.c
 *
 * The aes/rijndael block cipher.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2000, 2001 Rafael R. Sevilla, Niels Möller
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

/* Originally written by Rafael R. Sevilla <dido@pacific.net.ph> */

#include "aes-internal.h"

#include <assert.h>

/* Key addition that also packs every byte in the key to a word rep. */
static void
key_addition_8to32(const uint8_t *txt, const uint32_t *keys, uint32_t *out)
{
  const uint8_t *ptr;
  unsigned i, j;
  uint32_t val;

  ptr = txt;
  for (i=0; i<4; i++)
    {
      /* FIXME: Use the READ_UINT32 or LE_READ_UINT32 macro. */
      val = 0;
      for (j=0; j<4; j++)
	val |= (*ptr++ << 8*j);
      out[i] = keys[i]^val;
    }
}

static void
key_addition32(const uint32_t *txt, const uint32_t *keys, uint32_t *out)
{
  unsigned i;

  for (i=0; i<4; i++)
    out[i] = keys[i] ^ txt[i];
}

static void
key_addition32to8(const uint32_t *txt, const uint32_t *keys, uint8_t *out)
{
  uint8_t *ptr;
  unsigned i, j;
  uint32_t val;

  ptr = out;
  for (i=0; i<4; i++)
    {
      /* FIXME: Use WRITE_UINT32 or LE_WRITE_UINT32 */
      val = txt[i] ^ keys[i];
      for (j=0; j<4; j++)
	*ptr++ = (val >> 8*j) & 0xff;
    }
}

static const unsigned idx[4][4] = {
  { 0, 1, 2, 3 },
  { 1, 2, 3, 0 },
  { 2, 3, 0, 1 },
  { 3, 0, 1, 2 } };

void
aes_encrypt(struct aes_ctx *ctx,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
  unsigned r, j;
  uint32_t wtxt[4], t[4];		/* working ciphertext */
  uint32_t e;

  assert(!(length % AES_BLOCK_SIZE));

  for (; length;
       length -= AES_BLOCK_SIZE, src += AES_BLOCK_SIZE, dst += AES_BLOCK_SIZE)
    {
      key_addition_8to32(src, ctx->keys, wtxt);
      for (r=1; r<ctx->nrounds; r++)
	{
	  for (j=0; j<4; j++)
	    {
	      t[j] = dtbl[wtxt[j] & 0xff] ^
		ROTRBYTE(dtbl[(wtxt[idx[1][j]] >> 8) & 0xff]^
			 ROTRBYTE(dtbl[(wtxt[idx[2][j]] >> 16) & 0xff] ^
				  ROTRBYTE(dtbl[(wtxt[idx[3][j]] >> 24) & 0xff])));
	    }
	  key_addition32(t, ctx->keys + r*4, wtxt);
	}
  
      /* last round is special: there is no mixcolumn, so we can't use the big
	 tables. */
      for (j=0; j<4; j++)
	{
	  e = wtxt[j] & 0xff;
	  e |= (wtxt[idx[1][j]]) & (0xff << 8);
	  e |= (wtxt[idx[2][j]]) & (0xff << 16);
	  e |= (wtxt[idx[3][j]]) & (0xff << 24);
	  t[j] = e;
	}
      for (j=0; j<4; j++)
	t[j] = SUBBYTE(t[j], sbox);

      key_addition32to8(t, ctx->keys + 4*ctx->nrounds, dst);
    }
}

static const unsigned iidx[4][4] = {
  { 0, 1, 2, 3 },
  { 3, 0, 1, 2 },
  { 2, 3, 0, 1 },
  { 1, 2, 3, 0 } };

void
aes_decrypt(struct aes_ctx *ctx,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
  unsigned r, j;
  uint32_t wtxt[4], t[4];		/* working ciphertext */
  uint32_t e;

  assert(!(length % AES_BLOCK_SIZE));

  for (; length;
       length -= AES_BLOCK_SIZE, src += AES_BLOCK_SIZE, dst += AES_BLOCK_SIZE)
    {
      key_addition_8to32(src, ctx->ikeys + 4*ctx->nrounds, wtxt);
      for (r=ctx->nrounds-1; r> 0;  r--)
	{
	  for (j=0; j<4; j++)
	    {
	      t[j] = itbl[wtxt[j] & 0xff] ^
		ROTRBYTE(itbl[(wtxt[iidx[1][j]] >> 8) & 0xff]^
			 ROTRBYTE(itbl[(wtxt[iidx[2][j]] >> 16) & 0xff] ^
				  ROTRBYTE(itbl[(wtxt[iidx[3][j]] >> 24) & 0xff])));
	    }
	  key_addition32(t, ctx->ikeys + r*4, wtxt);
	}
      /* last round is special: there is no mixcolumn, so we can't use the big
	 tables. */
      for (j=0; j<4; j++)
	{
	  e = wtxt[j] & 0xff;
	  e |= (wtxt[iidx[1][j]]) & (0xff << 8);
	  e |= (wtxt[iidx[2][j]]) & (0xff << 16);
	  e |= (wtxt[iidx[3][j]]) & (0xff << 24);
	  t[j] = e;
	}
      for (j=0; j<4; j++)
	t[j] = SUBBYTE(t[j], isbox);

      key_addition32to8(t, ctx->ikeys, dst);
    }
}
