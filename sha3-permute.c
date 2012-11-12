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
  for (i = 0; i < SHA3_ROUNDS; i++)
    {
      uint64_t C[5], D[5], B[25];
      unsigned x, y;

      /* theta step */
      for (x = 0; x < 5; x++)
	C[x] = state->a[x] ^ state->a[5+x] ^ state->a[10+x]
	  ^ state->a[15+x] ^ state->a[20+x];
      for (x = 0; x < 5; x++)
	/* Use the simplest indexing expressions in the argument to
	   the ROTL64 macro */
	D[(x+4)%5] = C[(x+3)%5] ^ ROTL64(1, C[x]);
      for (x = 0; x < 5; x++)
	for (y = 0; y < 5; y++)
	  state->a[x +5*y] ^= D[x];

      /* rho step */
      for (x = 0; x < 25; x++)
	state->a[x] = ROTL64 (rot[x], state->a[x]);
      
      /* pi step */
      for (x = 0; x < 5; x++)
	for (y = 0; y < 5; y++)
	  /* B[y,2*x+3*y] = B[y+5*(2*x + 3*y)]= B[10*x + 16*y] */
	  B[(10*x+16*y) % 25] = state->a[x+5*y];

      /* chi step */
      for (x = 0; x < 5; x++)
	for (y = 0; y < 5; y++)
	  state->a[x+5*y] = B[x+5*y] ^ (~B[(x+1)%5 + 5*y] & B[(x+2)%5+5*y]);

      /* iota step */
      state->a[0] ^= rc[i];
    }
}
