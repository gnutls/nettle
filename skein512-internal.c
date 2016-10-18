/* skein512-internal.c

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

   Round  0,9,18: k0, k1, k2, k3, k4, k5+t0, k6+t1, k7
   Round  1,10:   k1, k2, k3, k4, k5, k6+t1, k7+t2, k8+1
   Round  2,11:   k2, k3, k4, k5, k6, k7+t2, k8+t0, k0+2
   Round  3,12:   k3, k4, k5, k6, k7, k8+t0, k0+t1, k1+3
   Round  4,13:   k4, k5, k6, k7, k8, k0+t1, k1+t2, k2+4
   Round  5,14:   k5, k6, k7, k8, k0, k1+t2, k2+t0, k3+5
   Round  6,15:   k6, k7, k8, k0, k1, k2+t0, k3+t1, k4+6
   Round  7,16:   k7, k8, k0, k1, k2, k3+t1, k4+t2, k5+7
   Round  8,17:   k8, k0, k1, k2, k3, k4+t2, k5+t0, k6+8

   Single round mangling:

   w0 += w1;
   w1 <<<= r_d0; { 46, 33, 17, 44, 39, 13, 25, 8 }
   w1 ^= w0

   w2 += w3;
   w3 <<<= r_d1; { 36, 27, 49,  9, 30, 50, 29, 35 }
   w3 ^= w2;

   w4 += w5;
   w5 <<<= r_d2; { 19, 14, 36, 54, 34, 10, 39, 56 }
   w5 ^= w4

   w6 += w7;
   w7 <<<= r_d3; { 37, 42, 39, 56, 24, 17, 43, 22 }
   w7 ^= w6;

   Permute: 0->2->4->6->0, 3<->7, 1->1, 5->5
   Pairs mixed:

   (0,1),(2,3),(4,5),(6,7)
   (2,1),(4,7),(6,5),(0,3)
   (4,1),(6,3),(0,5),(2,7)
   (6,1),(0,7),(2,5),(4,3)
*/

#define ROUND(w0, w1, w2, w3, w4, w5, w6, w7, c0, c1, c2, c3) do {	\
    w0 += w1;								\
    w1 = ROTL64(c0, w1);						\
    w1 ^= w0;								\
									\
    w2 += w3;								\
    w3 = ROTL64(c1, w3);						\
    w3 ^= w2;								\
									\
    w4 += w5;								\
    w5 = ROTL64(c2, w5);						\
    w5 ^= w4;								\
									\
    w6 += w7;								\
    w7 = ROTL64(c3, w7);						\
    w7 ^= w6;								\
  } while(0)

void
_skein512_block (uint64_t dst[_SKEIN512_LENGTH],
		 const uint64_t keys[_SKEIN512_NKEYS],
		 const uint64_t tweak[_SKEIN_NTWEAK],
		 const uint8_t src[SKEIN512_BLOCK_SIZE])
{
  uint64_t w0, w1, w2, w3, w4, w5, w6, w7;
  uint64_t t0, t1;
  unsigned i;

  w0 = LE_READ_UINT64(src);
  w1 = LE_READ_UINT64(src + 8);
  w2 = LE_READ_UINT64(src + 16);
  w3 = LE_READ_UINT64(src + 24);
  w4 = LE_READ_UINT64(src + 32);
  w5 = LE_READ_UINT64(src + 40);
  w6 = LE_READ_UINT64(src + 48);
  w7 = LE_READ_UINT64(src + 56);

  t0 = tweak[0];
  t1 = tweak[1];

  for (i = 0; i < 18; i+=2)
    {
      w0 += keys[(i+0) % 9];
      w1 += keys[(i+1) % 9];
      w2 += keys[(i+2) % 9];
      w3 += keys[(i+3) % 9];
      w4 += keys[(i+4) % 9];
      w5 += keys[(i+5) % 9] + t0;
      w6 += keys[(i+6) % 9] + t1;
      w7 += keys[(i+7) % 9] + i;

      t0 ^= t1;

      ROUND(w0, w1, w2, w3, w4, w5, w6, w7, 46, 36, 19, 37);
      ROUND(w2, w1, w4, w7, w6, w5, w0, w3, 33, 27, 14, 42);
      ROUND(w4, w1, w6, w3, w0, w5, w2, w7, 17, 49, 36, 39);
      ROUND(w6, w1, w0, w7, w2, w5, w4, w3, 44,  9, 54, 56);

      w0 += keys[(i+1) % 9];
      w1 += keys[(i+2) % 9];
      w2 += keys[(i+3) % 9];
      w3 += keys[(i+4) % 9];
      w4 += keys[(i+5) % 9];
      w5 += keys[(i+6) % 9] + t1;
      w6 += keys[(i+7) % 9] + t0;
      w7 += keys[(i+8) % 9] + i + 1;

      t1 ^= t0;

      ROUND(w0, w1, w2, w3, w4, w5, w6, w7, 39, 30, 34, 24);
      ROUND(w2, w1, w4, w7, w6, w5, w0, w3, 13, 50, 10, 17);
      ROUND(w4, w1, w6, w3, w0, w5, w2, w7, 25, 29, 39, 43);
      ROUND(w6, w1, w0, w7, w2, w5, w4, w3,  8, 35, 56, 22);
    }
  w0 += keys[0];
  w1 += keys[1];
  w2 += keys[2];
  w3 += keys[3];
  w4 += keys[4];
  w5 += keys[5] + t0;
  w6 += keys[6] + t1;
  w7 += keys[7] + 18;

  dst[0] = w0 ^ LE_READ_UINT64(src);
  dst[1] = w1 ^ LE_READ_UINT64(src + 8);
  dst[2] = w2 ^ LE_READ_UINT64(src + 16);
  dst[3] = w3 ^ LE_READ_UINT64(src + 24);
  dst[4] = w4 ^ LE_READ_UINT64(src + 32);
  dst[5] = w5 ^ LE_READ_UINT64(src + 40);
  dst[6] = w6 ^ LE_READ_UINT64(src + 48);
  dst[7] = w7 ^ LE_READ_UINT64(src + 56);
}
