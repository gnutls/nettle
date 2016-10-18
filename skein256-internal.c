/* skein256-internal.c

   Copyright (C) 2016 Niels Möller

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

#include "skein.h"

#include "macros.h"

/*
   Subkeys used:

   Round  0 * 4: k0, k1 + t0, k2 + t1, k3
   Round  1 * 4: k1, k2 + t1, k3 + t2, k4 + 1
   Round  2 * 4: k2, k3 + t2, k4 + t0, k0 + 2
   Round  3 * 4: k3, k4 + t0, k0 + t1, k1 + 3
   Round  4 * 4: k4, k0 + t1, k1 + t2, k2 + 4
   Round  5 * 4: k0, k1 + t2, k2 + t0, k3 + 5
   Round  6 * 4: k1, k2 + t0, k3 + t1, k4 + 6
   Round  7 * 4: k2, k3 + t1, k4 + t2, k0 + 7
   Round  8 * 4: k3, k4 + t2, k0 + t0, k1 + 8
   Round  9 * 4: k4, k0 + t0, k1 + t1, k2 + 9
   Round 10 * 4: k0, k1 + t1, k2 + t2, k3 + 10
   Round 11 * 4: k1, k2 + t2, k3 + t0, k4 + 11
   Round 12 * 4: k2, k3 + t0, k4 + t1, k0 + 12
   Round 13 * 4: k3, k4 + t1, k0 + t2, k1 + 13
   Round 14 * 4: k4, k0 + t2, k1 + t0, k2 + 14
   Round 15 * 4: k0, k1 + t0, k2 + t1, k3 + 15
   Round 16 * 4: k1, k2 + t1, k3 + t2, k4 + 16
   Round 17 * 4: k2, k3 + t2, k4 + t0, k0 + 17
   Round 18 * 4: k3, k4 + t0, k0 + t1, k1 + 18

   Single round mangling:

   w0 += w1;
   w1 <<<= r_d0; { 14, 52, 23,  5, 25, 46, 58, 32 }
   w1 ^= w0

   w2 += w3;
   w3 <<<= r_d1; { 16, 57, 40, 37, 33, 12, 22, 32 }
   w3 ^= w2;

   Permute, w1 <- w3, w3 <- w1

   Pairs mixed, if we fold out the permutations

   (0,1) (2,3)
   (0,3) (2,1),
*/

#define ROUND(w0, w1, w2, w3, c0, c1) do {	\
    w0 += w1;					\
    w1 = ROTL64(c0, w1);			\
    w1 ^= w0;					\
    						\
    w2 += w3;					\
    w3 = ROTL64(c1, w3);			\
    w3 ^= w2;					\
  } while(0)

void
_skein256_block (uint64_t dst[_SKEIN256_LENGTH],
		 const uint64_t keys[_SKEIN256_NKEYS],
		 const uint64_t tweak[_SKEIN_NTWEAK],
		 const uint8_t src[SKEIN256_BLOCK_SIZE])
{
  uint64_t s0, s1, s2, s3;
  uint64_t w0, w1, w2, w3;
  uint64_t k0, k1, k2, k3, k4;
  uint64_t t0, t1;
  unsigned i;

  w0 = s0 = LE_READ_UINT64(src);
  w1 = s1 = LE_READ_UINT64(src + 8);
  w2 = s2 = LE_READ_UINT64(src + 16);
  w3 = s3 = LE_READ_UINT64(src + 24);

  t0 = tweak[0];
  t1 = tweak[1];

  k0 = keys[0];
  k1 = keys[1] + t0;
  k2 = keys[2] + t1;
  k3 = keys[3];
  k4 = keys[4];

  for (i = 0; i < 18; i+=2)
    {
      uint64_t tmp;
      w0 += k0;
      w1 += k1;
      w2 += k2;
      w3 += k3 + i;

      ROUND(w0, w1, w2, w3, 14, 16);
      ROUND(w0, w3, w2, w1, 52, 57);
      ROUND(w0, w1, w2, w3, 23, 40);
      ROUND(w0, w3, w2, w1, 5, 37);

      w0 += k1 - t0; /* Right-hand side equal to new k4, below. */
      w1 += k2;
      t0 ^= t1;
      w2 += k3 + t0; /* Right-hand side equal to new k1, below. */
      w3 += k4 + i + 1;

      tmp = k1;
      k1 = k3 + t0;
      k3 = k0;
      k0 = k2 - t1;
      t1 ^= t0;
      k2 = k4 + t1;
      k4 = tmp - t1;

      ROUND(w0, w1, w2, w3, 25, 33);
      ROUND(w0, w3, w2, w1, 46, 12);
      ROUND(w0, w1, w2, w3, 58, 22);
      ROUND(w0, w3, w2, w1, 32, 32);
    }
  w0 += k0;
  w1 += k1;
  w2 += k2;
  w3 += k3 + 18;

  dst[0] = s0 ^ w0;
  dst[1] = s1 ^ w1;
  dst[2] = s2 ^ w2;
  dst[3] = s3 ^ w3;
}
