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
# define DEBUG 0
#endif

#if DEBUG
# include <stdio.h>
#endif

/* Get the byte with index 0, 1, 2 and 3 */
#define B0(x) ((x) & 0xff)
#define B1(x) (((x) >> 8) & 0xff)
#define B2(x) (((x) >> 16) & 0xff)
#define B3(x) (((x) >> 24) & 0xff)

/* Column j are the shifts used when computing t[j].
 * Row i is says which byte is used */

/* FIXME: Figure out how the indexing should really be done. It looks
 * like this code shifts the rows in the wrong direction, but it
 * passes the testsuite. Perhaps the tables are rotated in the wrong
 * direction, but I don't think so. */

/* The row shift counts C1, C2 and C3 are (1, 2, 3) */

static const unsigned idx[4][4] = {
  { 0, 1, 2, 3 },
  { 1, 2, 3, 0 },
  { 2, 3, 0, 1 },
  { 3, 0, 1, 2 } };
#if 0
static const unsigned idx4[4][4] = {
  { 0, 4, 8, 12 }, 
  { 4, 8, 12, 0 }, 
  { 8, 12, 0, 4 }, 
  { 12, 0, 4, 8 } };
#endif
static const unsigned iidx[4][4] = {
  { 0, 1, 2, 3 },
  { 3, 0, 1, 2 },
  { 2, 3, 0, 1 },
  { 1, 2, 3, 0 } };

void
aes_encrypt(struct aes_ctx *ctx,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
  FOR_BLOCKS(length, dst, src, AES_BLOCK_SIZE)
    {
      uint32_t wtxt[4];		/* working ciphertext */
      unsigned i;
      unsigned round;
      
      /* Get clear text, using little-endian byte order.
       * Also XOR with the first subkey. */
      for (i = 0; i<4; i++)
	wtxt[i] = LE_READ_UINT32(src + 4*i) ^ ctx->keys[i];

      for (round = 1; round < ctx->nrounds; round++)
	{
	  uint32_t t[4];
	  unsigned j;

	  /* What's the best way to order this loop? Ideally,
	   * we'd want to keep both t and wtxt in registers. */

	  for (j=0; j<4; j++)
	    {
#if AES_SMALL
	      t[j] =         dtable[0][ B0(wtxt[j]) ] ^
		ROTRBYTE(    dtable[0][ B1(wtxt[idx[1][j]]) ]^
		  ROTRBYTE(  dtable[0][ B2(wtxt[idx[2][j]]) ] ^
		    ROTRBYTE(dtable[0][ B3(wtxt[idx[3][j]]) ])));
#else /* !AES_SMALL */
	      t[j] = (  dtable[0][ B0(wtxt[idx[0][j]]) ]
		      ^ dtable[1][ B1(wtxt[idx[1][j]]) ]
		      ^ dtable[2][ B2(wtxt[idx[2][j]]) ]
		      ^ dtable[3][ B3(wtxt[idx[3][j]]) ]);
#endif /* !AES_SMALL */
	    }

	  for (j = 0; j<4; j++)
	    wtxt[j] = t[j] ^ ctx->keys[4*round + j];
	}
      /* Final round */
      {
	uint32_t cipher;
	unsigned j;
	for (j = 0; j<4; j++)
	  {
	    /* FIXME: Figure out how the indexing should really be done.
	     * It looks like this code shifts the rows in the wrong
	     * direction, but it passes the testsuite. */

	    cipher = (   (uint32_t) sbox[ B0(wtxt[j]) ]
			 | ((uint32_t) sbox[ B1(wtxt[idx[1][j]]) ] << 8)
			 | ((uint32_t) sbox[ B2(wtxt[idx[2][j]]) ] << 16)
			 | ((uint32_t) sbox[ B3(wtxt[idx[3][j]]) ] << 24));
#if DEBUG
	    fprintf(stderr, "  t[%d]: %x, key: %x\n",
		    j, cipher, ctx->keys[4*round + j]);
#endif
	    cipher ^= ctx->keys[4*round + j];

	    LE_WRITE_UINT32(dst + 4*j, cipher);
	  }
      }
    }
}

void
aes_decrypt(struct aes_ctx *ctx,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
#if DEBUG
  {
    unsigned i, j;
    fprintf(stderr, "subkeys:\n");
    for (j = 0; j<=ctx->nrounds; j++)
      {
	printf(" %d: ", j);
	for (i = 0; i<4; i++)
	  printf("%08x, ", ctx->ikeys[i + 4*j]);
	printf("\n");
      }
  }
#endif
  FOR_BLOCKS(length, dst, src, AES_BLOCK_SIZE)
    {
      uint32_t wtxt[4];		/* working ciphertext */
      unsigned i;
      unsigned round;

      /* Get cipher text, using little-endian byte order.
       * Also XOR with the first subkey. */
      for (i = 0; i<4; i++)
	wtxt[i] = LE_READ_UINT32(src + 4*i) ^ ctx->ikeys[i];

      for (round = 1; round < ctx->nrounds; round++)
	{
	  uint32_t t[4];
	  unsigned j;

#if DEBUG
	  fprintf(stderr, "decrypt, round: %d\n  wtxt: ", round);
	  for (j = 0; j<4; j++)
	    fprintf(stderr, "%08x, ", wtxt[j]);
	  fprintf(stderr, "\n  key: ");
	  for (j = 0; j<4; j++)
	    fprintf(stderr, "%08x, ", ctx->ikeys[4*round + j]);
	  fprintf(stderr, "\n");
#endif
	  /* The row shift counts C1, C2 and C3 are (1, 2, 3) */
	  /* What's the best way to order this loop? Ideally,
	   * we'd want to keep both t and wtxt in registers. */

	  for (j=0; j<4; j++)
	    {
#if AES_SMALL
	      t[j] =         itable[0][ B0(wtxt[j]) ] ^
		ROTRBYTE(    itable[0][ B1(wtxt[iidx[1][j]]) ]^
		  ROTRBYTE(  itable[0][ B2(wtxt[iidx[2][j]]) ] ^
		    ROTRBYTE(itable[0][ B3(wtxt[iidx[3][j]]) ])));
#else /* !AES_SMALL */
	      /* FIXME: Figure out how the indexing should really be done.
	       * It looks like this code shifts the rows in the wrong
	       * direction, but it passes the testsuite. */
	      for (j=0; j<4; j++)
		t[j] = (  itable[0][ B0(wtxt[iidx[0][j]]) ]
			^ itable[1][ B1(wtxt[iidx[1][j]]) ]
			^ itable[2][ B2(wtxt[iidx[2][j]]) ]
			^ itable[3][ B3(wtxt[iidx[3][j]]) ]);
#endif /* !AES_SMALL */
	    }
#if DEBUG
	  fprintf(stderr, "  t: ");
	  for (j = 0; j<4; j++)
	    fprintf(stderr, "%08x, ", t[j]);
	  fprintf(stderr, "\n");
#endif
	  for (j = 0; j<4; j++)
	    wtxt[j] = t[j] ^ ctx->ikeys[4*round + j];
	}
      /* Final round */
      {
	uint32_t clear;
	unsigned j;
	for (j = 0; j<4; j++)
	  {
	    /* FIXME: Figure out how the indexing should really be done.
	     * It looks like this code shifts the rows in the wrong
	     * direction, but it passes the testsuite. */

	    clear = (   (uint32_t) isbox[ B0(wtxt[j]) ]
			| ((uint32_t) isbox[ B1(wtxt[iidx[1][j]]) ] << 8)
			| ((uint32_t) isbox[ B2(wtxt[iidx[2][j]]) ] << 16)
			| ((uint32_t) isbox[ B3(wtxt[iidx[3][j]]) ] << 24));

#if DEBUG
	    fprintf(stderr, "  t[%d]: %x, key: %x\n",
		    j, clear, ctx->ikeys[4*round + j]);
#endif
	    clear ^= ctx->ikeys[4*round + j];

	    LE_WRITE_UINT32(dst + 4*j, clear);
	  }
      }
    }
}
