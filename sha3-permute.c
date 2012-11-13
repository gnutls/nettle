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
  static const unsigned char rot[25] =
    {
       0,  1, 62, 28, 27,
      36, 44,  6, 55, 20,
       3, 10, 43, 25, 39,
      41, 45, 15, 21,  8,
      18,  2, 61, 56, 14,
    };

  static const unsigned char perm[25] =
    {
       0,10,20, 5,15,
      16, 1,11,21, 6,
       7,17, 2,12,22,
      23, 8,18, 3,13,
      14,24, 9,19, 4
    };

  static const uint64_t rc[SHA3_ROUNDS] = {
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
  };
  unsigned i;

#define A state->a

  for (i = 0; i < SHA3_ROUNDS; i++)
    {
      uint64_t C[5], D[5], B[25];
      unsigned x, y;

      /* theta step */
      C[0] = A[0] ^ A[5+0] ^ A[10+0] ^ A[15+0] ^ A[20+0];
      C[1] = A[1] ^ A[5+1] ^ A[10+1] ^ A[15+1] ^ A[20+1];
      C[2] = A[2] ^ A[5+2] ^ A[10+2] ^ A[15+2] ^ A[20+2];
      C[3] = A[3] ^ A[5+3] ^ A[10+3] ^ A[15+3] ^ A[20+3];
      C[4] = A[4] ^ A[5+4] ^ A[10+4] ^ A[15+4] ^ A[20+4];

      D[0] = C[4] ^ ROTL64(1, C[1]);
      D[1] = C[0] ^ ROTL64(1, C[2]);
      D[2] = C[1] ^ ROTL64(1, C[3]);
      D[3] = C[2] ^ ROTL64(1, C[4]);
      D[4] = C[3] ^ ROTL64(1, C[0]);

      for (x = 0; x < 5; x++)
	for (y = 0; y < 25; y += 5)
	  A[y + x] ^= D[x];

      /* rho and pi steps */
      for (x = 0; x < 25; x++)
	B[perm[x]] = ROTL64 (rot[x], A[x]);

      /* chi step */
      for (y = 0; y < 25; y += 5)
	{
	  A[y]   = B[y]   ^ (~B[y+1] & B[y+2]);
	  A[y+1] = B[y+1] ^ (~B[y+2] & B[y+3]);
	  A[y+2] = B[y+2] ^ (~B[y+3] & B[y+4]);
	  A[y+3] = B[y+3] ^ (~B[y+4] & B[y+0]);
	  A[y+4] = B[y+4] ^ (~B[y+0] & B[y+1]);
	}
	  
      /* iota step */
      A[0] ^= rc[i];
    }
#undef A
}
