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

#include "macros.h"

#include <assert.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
# include <stdio.h>
#endif

/* Get the byte with index 0, 1, 2 and 3 */
#define B0(x) ((x) & 0xff)
#define B1(x) (((x) >> 8) & 0xff)
#define B2(x) (((x) >> 16) & 0xff)
#define B3(x) (((x) >> 24) & 0xff)

#if AES_SMALL
static const unsigned idx[4][4] = {
  { 0, 1, 2, 3 },
  { 1, 2, 3, 0 },
  { 2, 3, 0, 1 },
  { 3, 0, 1, 2 } };
#endif /* AES_SMALL */

void
aes_encrypt(struct aes_ctx *ctx,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
  assert(!(length % AES_BLOCK_SIZE));

  for (; length; length -= AES_BLOCK_SIZE)
    {
      uint32_t wtxt[4];		/* working ciphertext */
      unsigned i;
      unsigned round;
      
      /* Get clear text, using little-endian byte order.
       * Also XOR with the first subkey. */
      for (i = 0; i<4; i++, src += 4)
	wtxt[i] = LE_READ_UINT32(src) ^ ctx->keys[i];

      for (round = 1; round < ctx->nrounds; round++)
	{
	  uint32_t t[4];
	  unsigned j;

#if DEBUG
	  fprintf(stderr, "round: %d\n  wtxt: ", round);
	  for (j = 0; j<4; j++)
	    fprintf(stderr, "%08x, ", wtxt[j]);
	  fprintf(stderr, "\n  key: ");
	  for (j = 0; j<4; j++)
	    fprintf(stderr, "%08x, ", ctx->keys[4*round + j]);
	  fprintf(stderr, "\n");

	  fprintf(stderr,
		  "  B0(wtxt[0]): %x\n"
		  "    dtbl[0]: %x\n",
		  B0(wtxt[0]), dtbl[0][ B0(wtxt[0]) ]);
	  fprintf(stderr,
		  "  B1(wtxt[1]): %x\n"
		  "    dtbl[1]: %x\n",
		  B1(wtxt[1]), dtbl[1][ B1(wtxt[1]) ]);
	  fprintf(stderr,
		  "  B2(wtxt[2]): %x\n"
		  "    dtbl[2]: %x\n",
		  B2(wtxt[2]), dtbl[2][ B2(wtxt[2]) ]);
	  fprintf(stderr,
		  "  B3(wtxt[3]): %x\n"
		  "    dtbl[3]: %x\n",
		  B3(wtxt[3]), dtbl[3][ B3(wtxt[3]) ]);
#endif

	  /* The row shift counts C1, C2 and C3 are (1, 2, 3) */
	  /* What's the best way to order this loop? Ideally,
	   * we'd want to keep both t and wtxt in registers. */

#if AES_SMALL
	  for (j=0; j<4; j++)
	    t[j] = dtbl[0][wtxt[j] & 0xff] ^
	      ROTRBYTE(dtbl[0][(wtxt[idx[1][j]] >> 8) & 0xff]^
		ROTRBYTE(dtbl[0][(wtxt[idx[2][j]] >> 16) & 0xff] ^
		  ROTRBYTE(dtbl[0][(wtxt[idx[3][j]] >> 24) & 0xff])));
#else /* !AES_SMALL */
	  
	  /* FIXME: Figure out how the indexing should really be done.
	   * It looks like this code shifts the rows in the wrong
	   * direction, but it passes the testsuite. */
	  t[0] = (  dtbl[0][ B0(wtxt[0]) ]
		  ^ dtbl[1][ B1(wtxt[1]) ]
		  ^ dtbl[2][ B2(wtxt[2]) ]
		  ^ dtbl[3][ B3(wtxt[3]) ]);
	  t[3] = (  dtbl[0][ B0(wtxt[3]) ]
		  ^ dtbl[1][ B1(wtxt[0]) ]
		  ^ dtbl[2][ B2(wtxt[1]) ]
		  ^ dtbl[3][ B3(wtxt[2]) ]);
	  t[2] = (  dtbl[0][ B0(wtxt[2]) ]
		  ^ dtbl[1][ B1(wtxt[3]) ]
		  ^ dtbl[2][ B2(wtxt[0]) ]
		  ^ dtbl[3][ B3(wtxt[1]) ]);
	  t[1] = (  dtbl[0][ B0(wtxt[1]) ]
		  ^ dtbl[1][ B1(wtxt[2]) ]
		  ^ dtbl[2][ B2(wtxt[3]) ]
		  ^ dtbl[3][ B3(wtxt[0]) ]);
#endif /* !AES_SMALL */

#if DEBUG
	  fprintf(stderr, "\n  t: ");
	  for (j = 0; j<4; j++)
	    fprintf(stderr, "%08x, ", t[j]);
	  fprintf(stderr, "\n");
#endif
	  for (j = 0; j<4; j++)
	    wtxt[j] = t[j] ^ ctx->keys[4*round + j];
	}
      /* Final round */
      {
	uint32_t t[4];
	unsigned j;

#if DEBUG
	fprintf(stderr, "round: %d\n  wtxt: ", round);
	for (j = 0; j<4; j++)
	  fprintf(stderr, "%08x, ", wtxt[j]);
	fprintf(stderr, "\n  key: ");
	for (j = 0; j<4; j++)
	  fprintf(stderr, "%08x, ", ctx->keys[4*round + j]);
	fprintf(stderr, "\n\n");
#endif
	/* FIXME: Figure out how the indexing should really be done.
	 * It looks like this code shifts the rows in the wrong
	 * direction, but it passes the testsuite. */
	t[0] = (   (uint32_t) sbox[ B0(wtxt[0]) ]
		| ((uint32_t) sbox[ B1(wtxt[1]) ] << 8)
		| ((uint32_t) sbox[ B2(wtxt[2]) ] << 16)
		| ((uint32_t) sbox[ B3(wtxt[3]) ] << 24));
	t[3] = (   (uint32_t) sbox[ B0(wtxt[3]) ]
		| ((uint32_t) sbox[ B1(wtxt[0]) ] << 8)
		| ((uint32_t) sbox[ B2(wtxt[1]) ] << 16)
		| ((uint32_t) sbox[ B3(wtxt[2]) ] << 24));
	t[2] = (   (uint32_t) sbox[ B0(wtxt[2]) ]
		| ((uint32_t) sbox[ B1(wtxt[3]) ] << 8)
		| ((uint32_t) sbox[ B2(wtxt[0]) ] << 16)
		| ((uint32_t) sbox[ B3(wtxt[1]) ] << 24));
	t[1] = (   (uint32_t) sbox[ B0(wtxt[1]) ]
		| ((uint32_t) sbox[ B1(wtxt[2]) ] << 8)
		| ((uint32_t) sbox[ B2(wtxt[3]) ] << 16)
		| ((uint32_t) sbox[ B3(wtxt[0]) ] << 24));
      
	for (j = 0; j<4; j++)
	  {
	    uint32_t cipher = t[j] ^ ctx->keys[4*round + j];
#if DEBUG
	    fprintf(stderr, "cipher[%d]: %08x\n", j, cipher);
#endif
	    LE_WRITE_UINT32(dst, cipher); dst += 4;
	  }
      }
    }
}
      
      
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
