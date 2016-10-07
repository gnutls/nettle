/* skein256.c

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

#include <assert.h>

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
   w1 <<<= r_d0; { 46, 33, 17, 44, 39, 13, 25, 8 }
   w1 ^= w0

   w2 += w3;
   w3 <<<= r_d1; { 36, 27, 49, 9, 30, 50, 29, 35 }
   w3 ^= w2;

   Permute, w1 <- w3, w3 <- w1

   Pairs mixed, if we fold out the permutations

   (0,1) (2,3)
   (0,3) (2,1),
*/

#define ROUND(w0, w1, w2, w3, c0, c1) do {	\
    w0 += w1;								\
    w1 = ROTL64(c0, w1);						\
    w1 ^= w0;								\
									\
    w2 += w3;								\
    w3 = ROTL64(c1, w3);						\
    w3 ^= w2;								\
  } while(0)

#define ADD_SUBKEY(w0, w1, w2, w3, keys, tw, i) do { \
    w0 += (keys)[(i) % 5u];			    \
    w1 += (keys)[((i)+1u) % 5u] + (tw)[(i) % 3u];	    \
    w2 += (keys)[((i)+2u) % 5u] + (tw)[((i)+1u) % 3u]; \
    w3 += (keys)[((i)+3u) % 5u] + (i);		       \
  } while (0)

/* FIXME: Let src be uint8_t?  */
void
_skein256_block (uint64_t dst[_SKEIN256_LENGTH],
		 const uint64_t keys[_SKEIN256_NKEYS],
		 const uint64_t tweak[_SKEIN_NTWEAK],
		 const uint64_t src[_SKEIN256_LENGTH])
{
  uint64_t w0, w1, w2, w3;
  unsigned i;

  w0 = src[0];
  w1 = src[1];
  w2 = src[2];
  w3 = src[3];

  for (i = 0; i < 9; i++)
    {
      ADD_SUBKEY(w0, w1, w2, w3, keys, tweak, 2*i);

      ROUND(w0, w1, w2, w3, 14, 16);
      ROUND(w0, w3, w2, w1, 52, 57);
      ROUND(w0, w1, w2, w3, 23, 40);
      ROUND(w0, w3, w2, w1, 5, 37);

      ADD_SUBKEY(w0, w1, w2, w3, keys, tweak, 2*i+1);

      ROUND(w0, w1, w2, w3, 25, 33);
      ROUND(w0, w3, w2, w1, 46, 12);
      ROUND(w0, w1, w2, w3, 58, 22);
      ROUND(w0, w3, w2, w1, 32, 32);
    }
  ADD_SUBKEY(w0, w1, w2, w3, keys, tweak, 18);

  dst[0] = src[0] ^ w0;
  dst[1] = src[1] ^ w1;
  dst[2] = src[2] ^ w2;
  dst[3] = src[3] ^ w3;
}
