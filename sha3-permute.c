/* sha3-permute.c
 *
 * The sha3 permutation function (aka Keccak).
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2012 Niels Möller
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

#include "sha3.h"

#include "macros.h"

#define SHA3_ROUNDS 24

/* Based on the pseudocode description at
   http://keccak.noekeon.org/specs_summary.html */
void
sha3_permute (struct sha3_state *state)
{
  /* Original permutation:
     
       0,10,20, 5,15,
      16, 1,11,21, 6,
       7,17, 2,12,22,
      23, 8,18, 3,13,
      14,24, 9,19, 4

     Rotation counts:

       0,  1, 62, 28, 27,
      36, 44,  6, 55, 20,
       3, 10, 43, 25, 39,
      41, 45, 15, 21,  8,
      18,  2, 61, 56, 14,
  */

  /* Inverse permutation, to generate the output array in order. */
  static const unsigned char iperm[25] =
    {
      0, 6, 12, 18, 24,
      3, 9, 10, 16, 22,
      1, 7, 13, 19, 20,
      4, 5, 11, 17, 23,
      2, 8, 14, 15, 21
    };

  /* Correspondingly permuted rotation counts. */
  static const unsigned char irot[25] =
    {
       0, 44, 43, 21, 14,
      28, 20,  3, 45, 61,
       1,  6, 25,  8, 18,      
      27, 36, 10, 15, 56,
      62, 55, 39, 41,  2
    };

  static const uint64_t rc[SHA3_ROUNDS] = {
    0x0000000000000001ULL, 0X0000000000008082ULL,
    0X800000000000808AULL, 0X8000000080008000ULL,
    0X000000000000808BULL, 0X0000000080000001ULL,
    0X8000000080008081ULL, 0X8000000000008009ULL,
    0X000000000000008AULL, 0X0000000000000088ULL,
    0X0000000080008009ULL, 0X000000008000000AULL,
    0X000000008000808BULL, 0X800000000000008BULL,
    0X8000000000008089ULL, 0X8000000000008003ULL,
    0X8000000000008002ULL, 0X8000000000000080ULL,
    0X000000000000800AULL, 0X800000008000000AULL,
    0X8000000080008081ULL, 0X8000000000008080ULL,
    0X0000000080000001ULL, 0X8000000080008008ULL,
  };
  unsigned i;
  uint64_t C[5];
  
#define A state->a

  C[0] = A[0] ^ A[5+0] ^ A[10+0] ^ A[15+0] ^ A[20+0];
  C[1] = A[1] ^ A[5+1] ^ A[10+1] ^ A[15+1] ^ A[20+1];
  C[2] = A[2] ^ A[5+2] ^ A[10+2] ^ A[15+2] ^ A[20+2];
  C[3] = A[3] ^ A[5+3] ^ A[10+3] ^ A[15+3] ^ A[20+3];
  C[4] = A[4] ^ A[5+4] ^ A[10+4] ^ A[15+4] ^ A[20+4];

  for (i = 0; i < SHA3_ROUNDS; i++)
    {
      uint64_t D[5], B[25];
      unsigned x, y;

      /* theta step */
      D[0] = C[4] ^ ROTL64(1, C[1]);
      D[1] = C[0] ^ ROTL64(1, C[2]);
      D[2] = C[1] ^ ROTL64(1, C[3]);
      D[3] = C[2] ^ ROTL64(1, C[4]);
      D[4] = C[3] ^ ROTL64(1, C[0]);

      for (x = 0; x < 5; x++)
	for (y = 0; y < 25; y += 5)
	  B[y + x] = A[y + x] ^ D[x];

      /* rho, pi, chi ant iota steps */
      D[0] = B[0];
      D[1] = ROTL64 (irot[1], B[iperm[1]]);
      D[2] = ROTL64 (irot[2], B[iperm[2]]);
      D[3] = ROTL64 (irot[3], B[iperm[3]]);
      D[4] = ROTL64 (irot[4], B[iperm[4]]);

      A[0] = C[0] = D[0] ^(~D[1] & D[2]) ^ rc[i];
      A[1] = C[1] = D[1] ^(~D[2] & D[3]);
      A[2] = C[2] = D[2] ^(~D[3] & D[4]);
      A[3] = C[3] = D[3] ^(~D[4] & D[0]);
      A[4] = C[4] = D[4] ^(~D[0] & D[1]);

      for (y = 5; y < 25; y += 5)
	{
	  D[0] = ROTL64 (irot[y],   B[iperm[y]]);
	  D[1] = ROTL64 (irot[y+1], B[iperm[y+1]]);
	  D[2] = ROTL64 (irot[y+2], B[iperm[y+2]]);
	  D[3] = ROTL64 (irot[y+3], B[iperm[y+3]]);
	  D[4] = ROTL64 (irot[y+4], B[iperm[y+4]]);

	  C[0] ^= (A[y] = D[0]   ^ (~D[1] & D[2]));
	  C[1] ^= (A[y+1] = D[1] ^ (~D[2] & D[3]));
	  C[2] ^= (A[y+2] = D[2] ^ (~D[3] & D[4]));
	  C[3] ^= (A[y+3] = D[3] ^ (~D[4] & D[0]));
	  C[4] ^= (A[y+4] = D[4] ^ (~D[0] & D[1]));
	}
    }
#undef A
}
