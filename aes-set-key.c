/* aes-set-key.c
 *
 * Key setup for the aes/rijndael block cipher.
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

/* Used only by the key schedule */
static const uint8_t Logtable[256] = {
  0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,  3,
  100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28,
  193, 125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,
  9, 120, 101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53,
  147, 218, 142, 150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,
  64,  70, 131,  56, 102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226,
  152,  34, 136, 145,  16, 126, 110,  72, 195, 163, 182,  30,  66,  58, 107,
  40,  84, 250, 133,  61, 186, 43, 121,  10,  21, 155, 159,  94, 202,  78,
  212, 172, 229, 243, 115, 167,  87, 175,  88, 168,  80, 244, 234, 214, 116,
  79, 174, 233, 213, 231, 230, 173, 232, 44, 215, 117, 122, 235,  22,  11,
  245,  89, 203,  95, 176, 156, 169,  81, 160, 127,  12, 246, 111,  23, 196,
  73, 236, 216,  67,  31,  45, 164, 118, 123, 183, 204, 187,  62,  90, 251,
  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157, 151, 178, 135, 144,
  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209, 83,  57, 132,
  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171, 68,  17,
  146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165, 103,  
  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7, 
};

static const uint8_t Alogtable[256] = {
  1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19, 
  53, 95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34,
  102, 170, 229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144,
  171, 230,  49,  83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184,
  211, 110, 178, 205,  76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,
  8,  24,  40, 120, 136, 131, 158, 185, 208, 107, 189, 220, 127, 129, 152,
  179, 206,  73, 219, 118, 154, 181, 196,  87, 249,  16,  48,  80, 240,  11,
  29,  39, 105, 187, 214,  97, 163, 254,  25,  43, 125, 135, 146, 173, 236,
  47, 113, 147, 174, 233,  32,  96, 160, 251,  22,  58,  78, 210, 109, 183,
  194,  93, 231,  50,  86, 250,  21,  63,  65, 195,  94, 226,  61,  71, 201,
  64, 192,  91, 237,  44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172,
  239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 182, 193,  88,
  232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84, 252,  31,  33,
  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202,  69, 207,
  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14,  18,
  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23,
  57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246, 1, 
};

static uint8_t
mul(uint8_t a, uint8_t b)
{
  if (a && b) return Alogtable[(Logtable[a] + Logtable[b])%255];
  else return 0;
}

static void
inv_mix_column(uint32_t *a, uint32_t *b)
{
  uint8_t c[4][4];
  unsigned i, j;
	
  for(j = 0; j < 4; j++)
    {
      for(i = 0; i < 4; i++)
	{
	  c[j][i] = mul(0xe, (a[j] >> i*8) & 0xff)
	    ^ mul(0xb, (a[j] >> ((i+1)%4)*8) & 0xff)
	    ^ mul(0xd, (a[j] >> ((i+2)%4)*8) & 0xff)
	    ^ mul(0x9, (a[j] >> ((i+3)%4)*8) & 0xff);
	}
    }
  for(i = 0; i < 4; i++)
    {
      b[i] = 0;
      for(j = 0; j < 4; j++)
	b[i] |= c[i][j] << (j*8);
    }
}

static uint8_t
xtime(uint8_t a)
{
  uint8_t b;

  b = (a & 0x80) ? 0x1b : 0;
  a<<=1;
  a^=b;
  return(a);
}

/* FIXME: Perhaps we should have separate fucntion for encryption and
 * decryption keys? It seems unnecessary to compute the inverse
 * subkeys if we're not going to use them. Can one define an
 * aes_inverse function? */

void
aes_set_key(struct aes_ctx *ctx, unsigned keysize, const uint8_t *key)
{
  unsigned nk, nr, i, lastkey;
  uint32_t temp, rcon;

  assert(keysize >= AES_MIN_KEY_SIZE);
  assert(keysize <= AES_MAX_KEY_SIZE);
  
  /* Truncate keysizes to the valid key sizes provided by Rijndael */
  if (keysize == 32) {
    nk = 8;
    nr = 14;
  } else if (keysize >= 24) {
    nk = 6;
    nr = 12;
  } else { /* must be 16 or more */
    nk = 4;
    nr = 10;
  }

  lastkey = (AES_BLOCK_SIZE/4) * (nr + 1);
  ctx->nrounds = nr;
  rcon = 1;
  for (i=0; i<nk; i++)
    {
      ctx->keys[i] = key[i*4] + (key[i*4+1]<<8) + (key[i*4+2]<<16) +
	(key[i*4+3]<<24);
    }

  for (i=nk; i<lastkey; i++)
    {
      temp = ctx->keys[i-1];
      if (i % nk == 0)
	{
	  temp = SUBBYTE(ROTBYTE(temp), sbox) ^ rcon;
	  rcon = (uint32_t)xtime((uint8_t)rcon&0xff);
	}
      else if (nk > 6 && (i%nk) == 4)
	{
	  temp = SUBBYTE(temp, sbox);
	}
      ctx->keys[i] = ctx->keys[i-nk] ^ temp;
    }
  
  /* Generate the inverse keys */
  for (i=0; i<4; i++)
    {
      ctx->ikeys[i] = ctx->keys[i];
      ctx->ikeys[lastkey-4 + i] = ctx->keys[lastkey-4 + i];
    }
  for (i=4; i<lastkey-4; i+=4)
    inv_mix_column(&(ctx->keys[i]), &(ctx->ikeys[i]));
}
