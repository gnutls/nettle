/* camellia-set-encrypt-key.c
 *
 * Key setup for the camellia block cipher.
 */
/*
 * Copyright (C) 2006,2007
 * NTT (Nippon Telegraph and Telephone Corporation).
 *
 * Copyright (C) 2010 Niels Möller
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * Algorithm Specification 
 *  http://info.isl.ntt.co.jp/crypt/eng/camellia/specifications.html
 */

/* Based on camellia.c ver 1.2.0, see
   http://info.isl.ntt.co.jp/crypt/eng/camellia/dl/camellia-LGPL-1.2.0.tar.gz.
 */
#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>

#include "camellia-internal.h"

#include "macros.h"

/* key constants */

#define SIGMA1 0xA09E667F3BCC908BULL
#define SIGMA2 0xB67AE8584CAA73B2ULL
#define SIGMA3 0xC6EF372FE94F82BEULL
#define SIGMA4 0x54FF53A5F1D36F1CULL
#define SIGMA5 0x10E527FADE682D1DULL
#define SIGMA6 0xB05688C2B3E6C1FDULL

#define CAMELLIA_SP1110(INDEX) (_nettle_camellia_table.sp1110[(int)(INDEX)])
#define CAMELLIA_SP0222(INDEX) (_nettle_camellia_table.sp0222[(int)(INDEX)])
#define CAMELLIA_SP3033(INDEX) (_nettle_camellia_table.sp3033[(int)(INDEX)])
#define CAMELLIA_SP4404(INDEX) (_nettle_camellia_table.sp4404[(int)(INDEX)])

#define CAMELLIA_F(x, k, y) do {		\
    uint32_t __yl, __yr;			\
    uint64_t __i = (x) ^ (k);			\
    __yl					\
      = CAMELLIA_SP1110( __i & 0xff)		\
      ^ CAMELLIA_SP0222((__i >> 24) & 0xff)	\
      ^ CAMELLIA_SP3033((__i >> 16) & 0xff)	\
      ^ CAMELLIA_SP4404((__i >> 8) & 0xff);	\
    __yr					\
      = CAMELLIA_SP1110( __i >> 56)		\
      ^ CAMELLIA_SP0222((__i >> 48) & 0xff)	\
      ^ CAMELLIA_SP3033((__i >> 40) & 0xff)	\
      ^ CAMELLIA_SP4404((__i >> 32) & 0xff);	\
    __yl ^= __yr;				\
    __yr = ROL32(24, __yr);			\
    __yr ^= __yl;				\
    (y) = ((uint64_t) __yl << 32) | __yr;	\
  } while (0)

#define CAMELLIA_F_HALF_INV(x) do {		\
    uint32_t __t, __w;				\
    __t = (x) >> 32;				\
    __w = __t ^(x);				\
    __w = ROL32(8, __w);			\
    (x) = ((uint64_t) __w << 32) | (__t ^ __w);	\
  } while (0)


static void
camellia_setup128(uint64_t *subkey, const uint64_t *key)
{
    uint64_t k0, k1, w;

    /**
     *  k == k0 || k1 (|| is concatenation)
     */
    k0 = key[0];
    k1 = key[1];

    /**
     * generate KL dependent subkeys
     */
    subkey[0] = k0; subkey[1] = k1;
    ROL128(15, k0, k1);
    subkey[4] = k0; subkey[5] = k1;
    ROL128(30, k0, k1);
    subkey[10] = k0; subkey[11] = k1;
    ROL128(15, k0, k1);
    subkey[13] = k1;
    ROL128(17, k0, k1);
    subkey[16] = k0; subkey[17] = k1;
    ROL128(17, k0, k1);
    subkey[18] = k0; subkey[19] = k1;
    ROL128(17, k0, k1);
    subkey[22] = k0; subkey[23] = k1;

    /* generate KA. D1 is k0, d2 is k1. */
    /* FIXME: Make notation match the spec better. */
    /* For the 128-bit case, KR = 0, the construvtion of KA reduces to:

       D1 = KL >> 64;
       W = KL & MASK64;
       D2 = F(D1, Sigma1);
       W = D2 ^ W
       D1 = F(W, Sigma2)
       D2 = D2 ^ F(D1, Sigma3);
       D1 = D1 ^ F(D2, Sigma4);
       KA = (D1 << 64) | D2;
    */
    k0 = subkey[0]; w = subkey[1];
    CAMELLIA_F(k0, SIGMA1, k1);
    w ^= k1;
    CAMELLIA_F(w, SIGMA2, k0);
    CAMELLIA_F(k0, SIGMA3, w);
    k1 ^= w;
    CAMELLIA_F(k1, SIGMA4, w);
    k0 ^= w;

    /* generate KA dependent subkeys */
    subkey[2] = k0; subkey[3] = k1;
    ROL128(15, k0, k1);
    subkey[6] = k0; subkey[7] = k1;
    ROL128(15, k0, k1);
    subkey[8] = k0; subkey[9] = k1;
    ROL128(15, k0, k1);
    subkey[12] = k0;
    ROL128(15, k0, k1);
    subkey[14] = k0; subkey[15] = k1;
    ROL128(34, k0, k1);
    subkey[20] = k0; subkey[21] = k1;
    ROL128(17, k0, k1);
    subkey[24] = k0; subkey[25] = k1;

    return;
}

static void
camellia_setup256(uint64_t *subkey, const uint64_t *key)
{
    uint64_t k0, k1, k2, k3;
    uint64_t w;

    /**
     *  key = (kll || klr || krl || krr || krll || krlr || krrl || krrr)
     *  (|| is concatenation)
     */

    k0  = key[0];
    k1  = key[1];
    k2  = key[2];
    k3  = key[3];

    /* generate KL dependent subkeys */
    subkey[0] = k0; subkey[1] = k1;
    ROL128(45, k0, k1);
    subkey[12] = k0; subkey[13] = k1;
    ROL128(15, k0, k1);
    subkey[16] = k0; subkey[17] = k1;
    ROL128(17, k0, k1);
    subkey[22] = k0; subkey[23] = k1;
    ROL128(34, k0, k1);
    subkey[30] = k0; subkey[31] = k1;

    /* generate KR dependent subkeys */
    ROL128(15, k2, k3);
    subkey[4] = k2; subkey[5] = k3;
    ROL128(15, k2, k3);
    subkey[8] = k2; subkey[9] = k3;
    ROL128(30, k2, k3);
    subkey[18] = k2; subkey[19] = k3;
    ROL128(34, k2, k3);
    subkey[26] = k2; subkey[27] = k3;
    ROL128(34, k2, k3);

    /* generate KA */
    /* The construction of KA is done as

       D1 = (KL ^ KR) >> 64
       D2 = (KL ^ KR) & MASK64
       W = F(D1, SIGMA1)
       D2 = D2 ^ W
       D1 = F(D2, SIGMA2) ^ (KR >> 64)
       D2 = F(D1, SIGMA3) ^ W ^ (KR & MASK64)
       D1 = D1 ^ F(W, SIGMA2)
       D2 = D2 ^ F(D1, SIGMA3)
       D1 = D1 ^ F(D2, SIGMA4)
    */

    k0 = subkey[0] ^ k2;
    k1 = subkey[1] ^ k3;

    CAMELLIA_F(k0, SIGMA1, w);
    k1 ^= w;

    CAMELLIA_F(k1, SIGMA2, k0);
    k0 ^= k2;

    CAMELLIA_F(k0, SIGMA3, k1);
    k1 ^= w ^ k3;

    CAMELLIA_F(k1, SIGMA4, w);
    k0 ^= w;

    /* generate KB */
    k2 ^= k0; k3 ^= k1;
    CAMELLIA_F(k2, SIGMA5, w);
    k3 ^= w;
    CAMELLIA_F(k3, SIGMA6, w);
    k2 ^= w;

    /* generate KA dependent subkeys */
    ROL128(15, k0, k1);
    subkey[6] = k0; subkey[7] = k1;
    ROL128(30, k0, k1);
    subkey[14] = k0; subkey[15] = k1;
    ROL128(32, k0, k1);
    subkey[24] = k0; subkey[25] = k1;
    ROL128(17, k0, k1);
    subkey[28] = k0; subkey[29] = k1;

    /* generate KB dependent subkeys */
    subkey[2] = k2; subkey[3] = k3;
    ROL128(30, k2, k3);
    subkey[10] = k2; subkey[11] = k3;
    ROL128(30, k2, k3);
    subkey[20] = k2; subkey[21] = k3;
    ROL128(51, k2, k3);
    subkey[32] = k2; subkey[33] = k3;

    return;
}

void
camellia_set_encrypt_key(struct camellia_ctx *ctx,
			 unsigned length, const uint8_t *key)
{
  uint64_t k[4];

  /* Subkeys according to the spec, 26 for short keys and 34 for large
     keys */
  uint64_t subkey[34];
  uint64_t kw4;
  
  uint32_t dw, tl, tr;
  unsigned i;

  k[0] = READ_UINT64(key);
  k[1] = READ_UINT64(key +  8);
  
  if (length == 16)
    {
      ctx->nkeys = 26;
      camellia_setup128(subkey, k);
    }
  else
    {
      ctx->nkeys = 34;
      k[2] = READ_UINT64(key + 16);

      if (length == 24)
	k[3] = ~k[2];
      else
	{
	  assert (length == 32);
	  k[3] = READ_UINT64(key + 24);
	}
      camellia_setup256(subkey, k);
    }

  /* absorb kw2 to other subkeys */
  subkey[3] ^= subkey[1];
  subkey[5] ^= subkey[1];
  subkey[7] ^= subkey[1];
  /* FIXME: gcc for x86_32 is smart enough to fetch the 32 low bits
     and xor the result into the 32 high bits, but it still generates
     worse code than for explicit 32-bit operations. */
  subkey[1] ^= (subkey[1] & ~subkey[9]) << 32;
  dw = (subkey[1] & subkey[9]) >> 32; subkey[1] ^= ROL32(1, dw); 

  subkey[11] ^= subkey[1];
  subkey[13] ^= subkey[1];
  subkey[15] ^= subkey[1];
  subkey[1] ^= (subkey[1] & ~subkey[17]) << 32;
  dw = (subkey[1] & subkey[17]) >> 32; subkey[1] ^= ROL32(1, dw); 

  subkey[19] ^= subkey[1];
  subkey[21] ^= subkey[1];
  subkey[23] ^= subkey[1];
  if (ctx->nkeys < 32)
    {
      subkey[24] ^= subkey[1];
    }
  else
    {
      subkey[1] ^= (subkey[1] & ~subkey[25]) << 32;
      dw = (subkey[1] & subkey[25]) >> 32; subkey[1] ^= ROL32(1, dw); 

      subkey[27] ^= subkey[1];
      subkey[29] ^= subkey[1];
      subkey[31] ^= subkey[1];
      subkey[32] ^= subkey[1];
    }
    
  /* absorb kw4 to other subkeys */  
  kw4 = subkey[ctx->nkeys - 1];
  
  if (ctx->nkeys >= 32)
    {
      subkey[30] ^= kw4;
      subkey[28] ^= kw4;
      subkey[26] ^= kw4;
      kw4 ^= (kw4 & ~subkey[24]) << 32;
      dw = (kw4 & subkey[24]) >> 32; kw4 ^= ROL32(1, dw);      
    }

  subkey[22] ^= kw4;
  subkey[20] ^= kw4;
  subkey[18] ^= kw4;
  kw4 ^= (kw4 & ~subkey[16]) << 32;
  dw = (kw4 & subkey[16]) >> 32; kw4 ^= ROL32(1, dw);

  subkey[14] ^= kw4;
  subkey[12] ^= kw4;
  subkey[10] ^= kw4;
  kw4 ^= (kw4 & ~subkey[8]) << 32;
  dw = (kw4 & subkey[8]) >> 32; kw4 ^= ROL32(1, dw);

  subkey[6] ^= kw4;
  subkey[4] ^= kw4;
  subkey[2] ^= kw4;
  subkey[0] ^= kw4;

  /* key XOR is end of F-function */
  ctx->keys[0] = subkey[0] ^subkey[2];
    
  ctx->keys[2] = subkey[3];
  ctx->keys[3] = subkey[2] ^ subkey[4];
  ctx->keys[4] = subkey[3] ^ subkey[5];
  ctx->keys[5] = subkey[4] ^ subkey[6];
  ctx->keys[6] = subkey[5] ^ subkey[7];

  tl = (subkey[10] >> 32) ^ (subkey[10] & ~subkey[8]);
  dw = tl & (subkey[8] >> 32);
  tr = subkey[10] ^ROL32(1, dw);
  ctx->keys[7] = subkey[6] ^ ( ((uint64_t) tl << 32) | tr);

  ctx->keys[8] = subkey[8];
  ctx->keys[9] = subkey[9];

  tl = (subkey[7] >> 32) ^ (subkey[7] & ~subkey[9]);
  dw = tl & (subkey[9] >> 32);
  tr = subkey[7] ^ ROL32(1, dw);
  ctx->keys[10] = subkey[11] ^ ( ((uint64_t) tl << 32) | tr);

  ctx->keys[11] = subkey[10] ^ subkey[12];
  ctx->keys[12] = subkey[11] ^ subkey[13];
  ctx->keys[13] = subkey[12] ^ subkey[14];
  ctx->keys[14] = subkey[13] ^ subkey[15];

  tl = (subkey[18] >> 32) ^ (subkey[18] & ~subkey[16]);
  dw = tl & (subkey[16] >> 32);
  tr = subkey[18] ^ ROL32(1, dw);
  ctx->keys[15] = subkey[14] ^ ( ((uint64_t) tl << 32) | tr);

  ctx->keys[16] = subkey[16];
  ctx->keys[17] = subkey[17];

  tl = (subkey[15] >> 32) ^ (subkey[15] & ~subkey[17]);
  dw = tl & (subkey[17] >> 32);
  tr = subkey[15] ^ ROL32(1, dw);
  ctx->keys[18] = subkey[19] ^ ( ((uint64_t) tl << 32) | tr);

  ctx->keys[19] = subkey[18] ^ subkey[20];
  ctx->keys[20] = subkey[19] ^ subkey[21];
  ctx->keys[21] = subkey[20] ^ subkey[22];
  ctx->keys[22] = subkey[21] ^ subkey[23];

  if (ctx->nkeys < 32)
    {
      ctx->keys[23] = subkey[22];
      ctx->keys[24] = subkey[24] ^ subkey[23];
	  
    }
  else
    {
      tl = (subkey[26] >> 32) ^ (subkey[26] & ~subkey[24]);
      dw = tl & (subkey[24] >> 32);
      tr = subkey[26] ^ ROL32(1, dw);
      ctx->keys[23] = subkey[22] ^ ( ((uint64_t) tl << 32) | tr);

      ctx->keys[24] = subkey[24];
      ctx->keys[25] = subkey[25];

      tl = (subkey[23] >> 32) ^ (subkey[23] & ~subkey[25]);
      dw = tl & (subkey[25] >> 32);
      tr = subkey[23] ^ ROL32(1, dw);
      ctx->keys[26] = subkey[27] ^ ( ((uint64_t) tl << 32) | tr);

      ctx->keys[27] = subkey[26] ^ subkey[28];
      ctx->keys[28] = subkey[27] ^ subkey[29];
      ctx->keys[29] = subkey[28] ^ subkey[30];
      ctx->keys[30] = subkey[29] ^ subkey[31];

      ctx->keys[31] = subkey[30];
      ctx->keys[32] = subkey[32] ^ subkey[31];
	  
    }
  for (i = 0; i < ctx->nkeys - 2; i += 8)
    {

      /* apply the inverse of the last half of F-function */
      CAMELLIA_F_HALF_INV(ctx->keys[i+2]);
      CAMELLIA_F_HALF_INV(ctx->keys[i+3]);
      CAMELLIA_F_HALF_INV(ctx->keys[i+4]);
      CAMELLIA_F_HALF_INV(ctx->keys[i+5]);
      CAMELLIA_F_HALF_INV(ctx->keys[i+6]);
      CAMELLIA_F_HALF_INV(ctx->keys[i+7]);
    }
}
