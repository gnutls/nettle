/* des.c
 *
 * The des block cipher.
 *
 * $Id$
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

/*	des - fast & portable DES encryption & decryption.
 *	Copyright (C) 1992  Dana L. How
 *	Please see the file `descore.README' for the complete copyright notice.
 */

#include "des.h"

#include "desCode.h"

#include <assert.h>

static ENCRYPT(DesSmallFipsEncrypt,TEMPSMALL, LOADFIPS,KEYMAPSMALL,SAVEFIPS)
static DECRYPT(DesSmallFipsDecrypt,TEMPSMALL, LOADFIPS,KEYMAPSMALL,SAVEFIPS)

/* various tables */

uint32_t des_keymap[] = {
#include	"keymap.h"
};

static uint8_t rotors[] = {
#include	"rotors.h"
};
static char parity[] = {
#include	"parity.h"
};

void
des_fix_parity(unsigned length, uint8_t *dst,
	       const uint8_t *src)
{
  unsigned i;
  for (i = 0; i<length; i++)
    dst[i] = src[i] ^ (parity[src[i]] == 8);
}

int
des_set_key(struct des_ctx *ctx, const uint8_t *key)
{
  register uint32_t n, w;
  register char * b0, * b1;
  char bits0[56], bits1[56];
  uint32_t *method;
  uint8_t *k;
  
  /* check for bad parity and weak keys */
  b0 = parity;
  n  = b0[key[0]]; n <<= 4;
  n |= b0[key[1]]; n <<= 4;
  n |= b0[key[2]]; n <<= 4;
  n |= b0[key[3]]; n <<= 4;
  n |= b0[key[4]]; n <<= 4;
  n |= b0[key[5]]; n <<= 4;
  n |= b0[key[6]]; n <<= 4;
  n |= b0[key[7]];
  w  = 0x88888888l;
  /* report bad parity in key */
  if ( n & w )
    {
      ctx->status = DES_BAD_PARITY;
      return 0;
    }
  ctx->status = DES_WEAK_KEY; 
  /* report a weak or semi-weak key */
  if ( !((n - (w >> 3)) & w) ) {	/* 1 in 10^10 keys passes this test */
    if ( n < 0X41415151 ) {
      if ( n < 0X31312121 ) {
	if ( n < 0X14141515 ) {
	  /* 01 01 01 01 01 01 01 01 */
	  if ( n == 0X11111111 ) return 0;
	  /* 01 1F 01 1F 01 0E 01 0E */
	  if ( n == 0X13131212 ) return 0;
	} else {
	  /* 01 E0 01 E0 01 F1 01 F1 */
	  if ( n == 0X14141515 ) return 0;
	  /* 01 FE 01 FE 01 FE 01 FE */
	  if ( n == 0X16161616 ) return 0;
	}
      } else {
	if ( n < 0X34342525 ) {
	  /* 1F 01 1F 01 0E 01 0E 01 */
	  if ( n == 0X31312121 ) return 0;
	  /* 1F 1F 1F 1F 0E 0E 0E 0E */	/* ? */
	  if ( n == 0X33332222 ) return 0;;
	} else {
	  /* 1F E0 1F E0 0E F1 0E F1 */
	  if ( n == 0X34342525 ) return 0;;
	  /* 1F FE 1F FE 0E FE 0E FE */
	  if ( n == 0X36362626 ) return 0;;
	}
      }
    } else {
      if ( n < 0X61616161 ) {
	if ( n < 0X44445555 ) {
	  /* E0 01 E0 01 F1 01 F1 01 */
	  if ( n == 0X41415151 ) return 0;
	  /* E0 1F E0 1F F1 0E F1 0E */
	  if ( n == 0X43435252 ) return 0;
	} else {
	  /* E0 E0 E0 E0 F1 F1 F1 F1 */	/* ? */
	  if ( n == 0X44445555 ) return 0;
	  /* E0 FE E0 FE F1 FE F1 FE */
	  if ( n == 0X46465656 ) return 0;
	}
      } else {
	if ( n < 0X64646565 ) {
	  /* FE 01 FE 01 FE 01 FE 01 */
	  if ( n == 0X61616161 ) return 0;
	  /* FE 1F FE 1F FE 0E FE 0E */
	  if ( n == 0X63636262 ) return 0;
	} else {
	  /* FE E0 FE E0 FE F1 FE F1 */
	  if ( n == 0X64646565 ) return 0;
	  /* FE FE FE FE FE FE FE FE */
	  if ( n == 0X66666666 ) return 0;
	}
      }
    }
  }

  /* key is ok */
  ctx->status = DES_OK;
  
  /* explode the bits */
  n = 56;
  b0 = bits0;
  b1 = bits1;
  do {
    w = (256 | *key++) << 2;
    do {
      --n;
      b1[n] = 8 & w;
      w >>= 1;
      b0[n] = 4 & w;
    } while ( w >= 16 );
  } while ( n );

  /* put the bits in the correct places */
  n = 16;
  k = rotors;
  method = ctx->key;
  
  do {
    w   = (b1[k[ 0   ]] | b0[k[ 1   ]]) << 4;
    w  |= (b1[k[ 2   ]] | b0[k[ 3   ]]) << 2;
    w  |=  b1[k[ 4   ]] | b0[k[ 5   ]];
    w <<= 8;
    w  |= (b1[k[ 6   ]] | b0[k[ 7   ]]) << 4;
    w  |= (b1[k[ 8   ]] | b0[k[ 9   ]]) << 2;
    w  |=  b1[k[10   ]] | b0[k[11   ]];
    w <<= 8;
    w  |= (b1[k[12   ]] | b0[k[13   ]]) << 4;
    w  |= (b1[k[14   ]] | b0[k[15   ]]) << 2;
    w  |=  b1[k[16   ]] | b0[k[17   ]];
    w <<= 8;
    w  |= (b1[k[18   ]] | b0[k[19   ]]) << 4;
    w  |= (b1[k[20   ]] | b0[k[21   ]]) << 2;
    w  |=  b1[k[22   ]] | b0[k[23   ]];

    method[0] = w;

    w   = (b1[k[ 0+24]] | b0[k[ 1+24]]) << 4;
    w  |= (b1[k[ 2+24]] | b0[k[ 3+24]]) << 2;
    w  |=  b1[k[ 4+24]] | b0[k[ 5+24]];
    w <<= 8;
    w  |= (b1[k[ 6+24]] | b0[k[ 7+24]]) << 4;
    w  |= (b1[k[ 8+24]] | b0[k[ 9+24]]) << 2;
    w  |=  b1[k[10+24]] | b0[k[11+24]];
    w <<= 8;
    w  |= (b1[k[12+24]] | b0[k[13+24]]) << 4;
    w  |= (b1[k[14+24]] | b0[k[15+24]]) << 2;
    w  |=  b1[k[16+24]] | b0[k[17+24]];
    w <<= 8;
    w  |= (b1[k[18+24]] | b0[k[19+24]]) << 4;
    w  |= (b1[k[20+24]] | b0[k[21+24]]) << 2;
    w  |=  b1[k[22+24]] | b0[k[23+24]];

    ROR(w, 4, 28);		/* could be eliminated */
    method[1] = w;

    k	+= 48;
    method	+= 2;
  } while ( --n );

  return 1;
}

void
des_encrypt(struct des_ctx *ctx,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
  assert(!(length % DES_BLOCK_SIZE));
  assert(ctx->status == DES_OK);
  
  while (length)
    {
      DesSmallFipsEncrypt(dst, ctx->key, src);
      length -= DES_BLOCK_SIZE;
      src += DES_BLOCK_SIZE;
      dst += DES_BLOCK_SIZE;
    }
}

void
des_decrypt(struct des_ctx *ctx,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
  assert(!(length % DES_BLOCK_SIZE));
  assert(ctx->status == DES_OK);

  while (length)
    {
      DesSmallFipsDecrypt(dst, ctx->key, src);
      length -= DES_BLOCK_SIZE;
      src += DES_BLOCK_SIZE;
      dst += DES_BLOCK_SIZE;
    }
}
