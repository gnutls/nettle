/* ripemd160-compress.c  -  RIPE-MD160 (Transform function)
 * Copyright (C) 1998, 2001, 2002, 2003 Free Software Foundation, Inc.
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

#include <string.h>

#include "ripemd160.h"

/****************
 * Rotate the 32 bit unsigned integer X by N bits left/right
 */
#if defined(__GNUC__) && defined(__i386__)
static inline uint32_t
rol(uint32_t x, int n)
{
  __asm__("roll %%cl,%0"
    :"=r" (x)
    :"0" (x),"c" (n));
  return x;
}
#else
#define rol(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#endif

/****************
 * Transform the message X which consists of 16 32-bit-words
 */
void
_nettle_ripemd160_compress(uint32_t *state, const uint8_t *data)
{
  register uint32_t a,b,c,d,e;
  uint32_t aa,bb,cc,dd,ee,t;
#ifdef WORDS_BIGENDIAN
  uint32_t x[16];
  {
    int i;
    uint8_t *p2, *p1;
    for (i=0, p1=data, p2=(uint8_t*)x; i < 16; i++, p2 += 4 )
    {
      p2[3] = *p1++;
      p2[2] = *p1++;
      p2[1] = *p1++;
      p2[0] = *p1++;
    }
  }
#else
  /* This version is better because it is always aligned;
   * The performance penalty on a 586-100 is about 6% which
   * is acceptable - because the data is more local it might
   * also be possible that this is faster on some machines.
   * This function (when compiled with -02 on gcc 2.7.2)
   * executes on a 586-100 (39.73 bogomips) at about 1900kb/sec;
   * [measured with a 4MB data and "gpgm --print-md rmd160"] */
  uint32_t x[16];
  memcpy(x, data, 64);
#endif


#define K0  0x00000000
#define K1  0x5A827999
#define K2  0x6ED9EBA1
#define K3  0x8F1BBCDC
#define K4  0xA953FD4E
#define KK0 0x50A28BE6
#define KK1 0x5C4DD124
#define KK2 0x6D703EF3
#define KK3 0x7A6D76E9
#define KK4 0x00000000
#define F0(x,y,z)   ( (x) ^ (y) ^ (z) )
#define F1(x,y,z)   ( ((x) & (y)) | (~(x) & (z)) )
#define F2(x,y,z)   ( ((x) | ~(y)) ^ (z) )
#define F3(x,y,z)   ( ((x) & (z)) | ((y) & ~(z)) )
#define F4(x,y,z)   ( (x) ^ ((y) | ~(z)) )
#define R(a,b,c,d,e,f,k,r,s) do { t = a + f(b,c,d) + k + x[r]; \
          a = rol(t,s) + e;        \
          c = rol(c,10);         \
        } while(0)

  /* left lane */
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  R( a, b, c, d, e, F0, K0,  0, 11 );
  R( e, a, b, c, d, F0, K0,  1, 14 );
  R( d, e, a, b, c, F0, K0,  2, 15 );
  R( c, d, e, a, b, F0, K0,  3, 12 );
  R( b, c, d, e, a, F0, K0,  4,  5 );
  R( a, b, c, d, e, F0, K0,  5,  8 );
  R( e, a, b, c, d, F0, K0,  6,  7 );
  R( d, e, a, b, c, F0, K0,  7,  9 );
  R( c, d, e, a, b, F0, K0,  8, 11 );
  R( b, c, d, e, a, F0, K0,  9, 13 );
  R( a, b, c, d, e, F0, K0, 10, 14 );
  R( e, a, b, c, d, F0, K0, 11, 15 );
  R( d, e, a, b, c, F0, K0, 12,  6 );
  R( c, d, e, a, b, F0, K0, 13,  7 );
  R( b, c, d, e, a, F0, K0, 14,  9 );
  R( a, b, c, d, e, F0, K0, 15,  8 );
  R( e, a, b, c, d, F1, K1,  7,  7 );
  R( d, e, a, b, c, F1, K1,  4,  6 );
  R( c, d, e, a, b, F1, K1, 13,  8 );
  R( b, c, d, e, a, F1, K1,  1, 13 );
  R( a, b, c, d, e, F1, K1, 10, 11 );
  R( e, a, b, c, d, F1, K1,  6,  9 );
  R( d, e, a, b, c, F1, K1, 15,  7 );
  R( c, d, e, a, b, F1, K1,  3, 15 );
  R( b, c, d, e, a, F1, K1, 12,  7 );
  R( a, b, c, d, e, F1, K1,  0, 12 );
  R( e, a, b, c, d, F1, K1,  9, 15 );
  R( d, e, a, b, c, F1, K1,  5,  9 );
  R( c, d, e, a, b, F1, K1,  2, 11 );
  R( b, c, d, e, a, F1, K1, 14,  7 );
  R( a, b, c, d, e, F1, K1, 11, 13 );
  R( e, a, b, c, d, F1, K1,  8, 12 );
  R( d, e, a, b, c, F2, K2,  3, 11 );
  R( c, d, e, a, b, F2, K2, 10, 13 );
  R( b, c, d, e, a, F2, K2, 14,  6 );
  R( a, b, c, d, e, F2, K2,  4,  7 );
  R( e, a, b, c, d, F2, K2,  9, 14 );
  R( d, e, a, b, c, F2, K2, 15,  9 );
  R( c, d, e, a, b, F2, K2,  8, 13 );
  R( b, c, d, e, a, F2, K2,  1, 15 );
  R( a, b, c, d, e, F2, K2,  2, 14 );
  R( e, a, b, c, d, F2, K2,  7,  8 );
  R( d, e, a, b, c, F2, K2,  0, 13 );
  R( c, d, e, a, b, F2, K2,  6,  6 );
  R( b, c, d, e, a, F2, K2, 13,  5 );
  R( a, b, c, d, e, F2, K2, 11, 12 );
  R( e, a, b, c, d, F2, K2,  5,  7 );
  R( d, e, a, b, c, F2, K2, 12,  5 );
  R( c, d, e, a, b, F3, K3,  1, 11 );
  R( b, c, d, e, a, F3, K3,  9, 12 );
  R( a, b, c, d, e, F3, K3, 11, 14 );
  R( e, a, b, c, d, F3, K3, 10, 15 );
  R( d, e, a, b, c, F3, K3,  0, 14 );
  R( c, d, e, a, b, F3, K3,  8, 15 );
  R( b, c, d, e, a, F3, K3, 12,  9 );
  R( a, b, c, d, e, F3, K3,  4,  8 );
  R( e, a, b, c, d, F3, K3, 13,  9 );
  R( d, e, a, b, c, F3, K3,  3, 14 );
  R( c, d, e, a, b, F3, K3,  7,  5 );
  R( b, c, d, e, a, F3, K3, 15,  6 );
  R( a, b, c, d, e, F3, K3, 14,  8 );
  R( e, a, b, c, d, F3, K3,  5,  6 );
  R( d, e, a, b, c, F3, K3,  6,  5 );
  R( c, d, e, a, b, F3, K3,  2, 12 );
  R( b, c, d, e, a, F4, K4,  4,  9 );
  R( a, b, c, d, e, F4, K4,  0, 15 );
  R( e, a, b, c, d, F4, K4,  5,  5 );
  R( d, e, a, b, c, F4, K4,  9, 11 );
  R( c, d, e, a, b, F4, K4,  7,  6 );
  R( b, c, d, e, a, F4, K4, 12,  8 );
  R( a, b, c, d, e, F4, K4,  2, 13 );
  R( e, a, b, c, d, F4, K4, 10, 12 );
  R( d, e, a, b, c, F4, K4, 14,  5 );
  R( c, d, e, a, b, F4, K4,  1, 12 );
  R( b, c, d, e, a, F4, K4,  3, 13 );
  R( a, b, c, d, e, F4, K4,  8, 14 );
  R( e, a, b, c, d, F4, K4, 11, 11 );
  R( d, e, a, b, c, F4, K4,  6,  8 );
  R( c, d, e, a, b, F4, K4, 15,  5 );
  R( b, c, d, e, a, F4, K4, 13,  6 );

  aa = a; bb = b; cc = c; dd = d; ee = e;

  /* right lane */
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  R( a, b, c, d, e, F4, KK0,  5,  8);
  R( e, a, b, c, d, F4, KK0, 14,  9);
  R( d, e, a, b, c, F4, KK0,  7,  9);
  R( c, d, e, a, b, F4, KK0,  0, 11);
  R( b, c, d, e, a, F4, KK0,  9, 13);
  R( a, b, c, d, e, F4, KK0,  2, 15);
  R( e, a, b, c, d, F4, KK0, 11, 15);
  R( d, e, a, b, c, F4, KK0,  4,  5);
  R( c, d, e, a, b, F4, KK0, 13,  7);
  R( b, c, d, e, a, F4, KK0,  6,  7);
  R( a, b, c, d, e, F4, KK0, 15,  8);
  R( e, a, b, c, d, F4, KK0,  8, 11);
  R( d, e, a, b, c, F4, KK0,  1, 14);
  R( c, d, e, a, b, F4, KK0, 10, 14);
  R( b, c, d, e, a, F4, KK0,  3, 12);
  R( a, b, c, d, e, F4, KK0, 12,  6);
  R( e, a, b, c, d, F3, KK1,  6,  9);
  R( d, e, a, b, c, F3, KK1, 11, 13);
  R( c, d, e, a, b, F3, KK1,  3, 15);
  R( b, c, d, e, a, F3, KK1,  7,  7);
  R( a, b, c, d, e, F3, KK1,  0, 12);
  R( e, a, b, c, d, F3, KK1, 13,  8);
  R( d, e, a, b, c, F3, KK1,  5,  9);
  R( c, d, e, a, b, F3, KK1, 10, 11);
  R( b, c, d, e, a, F3, KK1, 14,  7);
  R( a, b, c, d, e, F3, KK1, 15,  7);
  R( e, a, b, c, d, F3, KK1,  8, 12);
  R( d, e, a, b, c, F3, KK1, 12,  7);
  R( c, d, e, a, b, F3, KK1,  4,  6);
  R( b, c, d, e, a, F3, KK1,  9, 15);
  R( a, b, c, d, e, F3, KK1,  1, 13);
  R( e, a, b, c, d, F3, KK1,  2, 11);
  R( d, e, a, b, c, F2, KK2, 15,  9);
  R( c, d, e, a, b, F2, KK2,  5,  7);
  R( b, c, d, e, a, F2, KK2,  1, 15);
  R( a, b, c, d, e, F2, KK2,  3, 11);
  R( e, a, b, c, d, F2, KK2,  7,  8);
  R( d, e, a, b, c, F2, KK2, 14,  6);
  R( c, d, e, a, b, F2, KK2,  6,  6);
  R( b, c, d, e, a, F2, KK2,  9, 14);
  R( a, b, c, d, e, F2, KK2, 11, 12);
  R( e, a, b, c, d, F2, KK2,  8, 13);
  R( d, e, a, b, c, F2, KK2, 12,  5);
  R( c, d, e, a, b, F2, KK2,  2, 14);
  R( b, c, d, e, a, F2, KK2, 10, 13);
  R( a, b, c, d, e, F2, KK2,  0, 13);
  R( e, a, b, c, d, F2, KK2,  4,  7);
  R( d, e, a, b, c, F2, KK2, 13,  5);
  R( c, d, e, a, b, F1, KK3,  8, 15);
  R( b, c, d, e, a, F1, KK3,  6,  5);
  R( a, b, c, d, e, F1, KK3,  4,  8);
  R( e, a, b, c, d, F1, KK3,  1, 11);
  R( d, e, a, b, c, F1, KK3,  3, 14);
  R( c, d, e, a, b, F1, KK3, 11, 14);
  R( b, c, d, e, a, F1, KK3, 15,  6);
  R( a, b, c, d, e, F1, KK3,  0, 14);
  R( e, a, b, c, d, F1, KK3,  5,  6);
  R( d, e, a, b, c, F1, KK3, 12,  9);
  R( c, d, e, a, b, F1, KK3,  2, 12);
  R( b, c, d, e, a, F1, KK3, 13,  9);
  R( a, b, c, d, e, F1, KK3,  9, 12);
  R( e, a, b, c, d, F1, KK3,  7,  5);
  R( d, e, a, b, c, F1, KK3, 10, 15);
  R( c, d, e, a, b, F1, KK3, 14,  8);
  R( b, c, d, e, a, F0, KK4, 12,  8);
  R( a, b, c, d, e, F0, KK4, 15,  5);
  R( e, a, b, c, d, F0, KK4, 10, 12);
  R( d, e, a, b, c, F0, KK4,  4,  9);
  R( c, d, e, a, b, F0, KK4,  1, 12);
  R( b, c, d, e, a, F0, KK4,  5,  5);
  R( a, b, c, d, e, F0, KK4,  8, 14);
  R( e, a, b, c, d, F0, KK4,  7,  6);
  R( d, e, a, b, c, F0, KK4,  6,  8);
  R( c, d, e, a, b, F0, KK4,  2, 13);
  R( b, c, d, e, a, F0, KK4, 13,  6);
  R( a, b, c, d, e, F0, KK4, 14,  5);
  R( e, a, b, c, d, F0, KK4,  0, 15);
  R( d, e, a, b, c, F0, KK4,  3, 13);
  R( c, d, e, a, b, F0, KK4,  9, 11);
  R( b, c, d, e, a, F0, KK4, 11, 11);


  t    = state[1] + d + cc;
  state[1] = state[2] + e + dd;
  state[2] = state[3] + a + ee;
  state[3] = state[4] + b + aa;
  state[4] = state[0] + c + bb;
  state[0] = t;
}
