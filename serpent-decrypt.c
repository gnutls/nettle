/* serpent-decrypt.c
 *
 * The serpent block cipher.
 *
 * For more details on this algorithm, see the Serpent website at
 * http://www.cl.cam.ac.uk/~rja14/serpent.html
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2011  Niels Möller
 * Copyright (C) 2010, 2011  Simon Josefsson
 * Copyright (C) 2003, 2004, 2005 Free Software Foundation, Inc.
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

/* This file is derived from cipher/serpent.c in Libgcrypt v1.4.6.
   The adaption to Nettle was made by Simon Josefsson on 2010-12-07
   with final touches on 2011-05-30.  Changes include replacing
   libgcrypt with nettle in the license template, renaming
   serpent_context to serpent_ctx, renaming u32 to uint32_t, removing
   libgcrypt stubs and selftests, modifying entry function prototypes,
   using FOR_BLOCKS to iterate through data in encrypt/decrypt, using
   LE_READ_UINT32 and LE_WRITE_UINT32 to access data in
   encrypt/decrypt, and running indent on the code. */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <limits.h>

#include "serpent.h"

#include "macros.h"
#include "serpent-internal.h"

/* These are the S-Boxes of Serpent.  They are copied from Serpents
   reference implementation (the optimized one, contained in
   `floppy2') and are therefore:

     Copyright (C) 1998 Ross Anderson, Eli Biham, Lars Knudsen.

  To quote the Serpent homepage
  (http://www.cl.cam.ac.uk/~rja14/serpent.html):

  "Serpent is now completely in the public domain, and we impose no
   restrictions on its use.  This was announced on the 21st August at
   the First AES Candidate Conference. The optimised implementations
   in the submission package are now under the GNU PUBLIC LICENSE
   (GPL), although some comments in the code still say otherwise. You
   are welcome to use Serpent for any application."  */

/* FIXME: Except when used within the key schedule, the inputs are not
   used after the substitution, and hence we could allow them to be
   destroyed. Can this freedom be used to optimize the sboxes? */

#define SBOX0_INVERSE(type, a, b, c, d, w, x, y, z)	\
  do { \
    type t02, t03, t04, t05, t06, t08, t09, t10;	\
    type t12, t13, t14, t15, t17, t18, t01; \
    t01 = c   ^ d  ; \
    t02 = a   | b  ; \
    t03 = b   | c  ; \
    t04 = c   & t01; \
    t05 = t02 ^ t01; \
    t06 = a   | t04; \
    y   =     ~ t05; \
    t08 = b   ^ d  ; \
    t09 = t03 & t08; \
    t10 = d   | y  ; \
    x   = t09 ^ t06; \
    t12 = a   | t05; \
    t13 = x   ^ t12; \
    t14 = t03 ^ t10; \
    t15 = a   ^ c  ; \
    z   = t14 ^ t13; \
    t17 = t05 & t13; \
    t18 = t14 | t17; \
    w   = t15 ^ t18; \
  } while (0)

#define SBOX1_INVERSE(type, a, b, c, d, w, x, y, z) \
  do { \
    type t02, t03, t04, t05, t06, t07, t08; \
    type t09, t10, t11, t14, t15, t17, t01; \
    t01 = a   ^ b  ; \
    t02 = b   | d  ; \
    t03 = a   & c  ; \
    t04 = c   ^ t02; \
    t05 = a   | t04; \
    t06 = t01 & t05; \
    t07 = d   | t03; \
    t08 = b   ^ t06; \
    t09 = t07 ^ t06; \
    t10 = t04 | t03; \
    t11 = d   & t08; \
    y   =     ~ t09; \
    x   = t10 ^ t11; \
    t14 = a   | y  ; \
    t15 = t06 ^ x  ; \
    z   = t01 ^ t04; \
    t17 = c   ^ t15; \
    w   = t14 ^ t17; \
  } while (0)

#define SBOX2_INVERSE(type, a, b, c, d, w, x, y, z) \
  do {						\
    type t02, t03, t04, t06, t07, t08, t09; \
    type t10, t11, t12, t15, t16, t17, t01; \
    t01 = a   ^ d  ; \
    t02 = c   ^ d  ; \
    t03 = a   & c  ; \
    t04 = b   | t02; \
    w   = t01 ^ t04; \
    t06 = a   | c  ; \
    t07 = d   | w  ; \
    t08 =     ~ d  ; \
    t09 = b   & t06; \
    t10 = t08 | t03; \
    t11 = b   & t07; \
    t12 = t06 & t02; \
    z   = t09 ^ t10; \
    x   = t12 ^ t11; \
    t15 = c   & z  ; \
    t16 = w   ^ x  ; \
    t17 = t10 ^ t15; \
    y   = t16 ^ t17; \
  } while (0)

#define SBOX3_INVERSE(type, a, b, c, d, w, x, y, z) \
  do { \
    type t02, t03, t04, t05, t06, t07, t09; \
    type t11, t12, t13, t14, t16, t01; \
    t01 = c   | d  ; \
    t02 = a   | d  ; \
    t03 = c   ^ t02; \
    t04 = b   ^ t02; \
    t05 = a   ^ d  ; \
    t06 = t04 & t03; \
    t07 = b   & t01; \
    y   = t05 ^ t06; \
    t09 = a   ^ t03; \
    w   = t07 ^ t03; \
    t11 = w   | t05; \
    t12 = t09 & t11; \
    t13 = a   & y  ; \
    t14 = t01 ^ t05; \
    x   = b   ^ t12; \
    t16 = b   | t13; \
    z   = t14 ^ t16; \
  } while (0)

#define SBOX4_INVERSE(type, a, b, c, d, w, x, y, z) \
  do { \
    type t02, t03, t04, t05, t06, t07, t09; \
    type t10, t11, t12, t13, t15, t01; \
    t01 = b   | d  ; \
    t02 = c   | d  ; \
    t03 = a   & t01; \
    t04 = b   ^ t02; \
    t05 = c   ^ d  ; \
    t06 =     ~ t03; \
    t07 = a   & t04; \
    x   = t05 ^ t07; \
    t09 = x   | t06; \
    t10 = a   ^ t07; \
    t11 = t01 ^ t09; \
    t12 = d   ^ t04; \
    t13 = c   | t10; \
    z   = t03 ^ t12; \
    t15 = a   ^ t04; \
    y   = t11 ^ t13; \
    w   = t15 ^ t09; \
  } while (0)

#define SBOX5_INVERSE(type, a, b, c, d, w, x, y, z) \
  do { \
    type t02, t03, t04, t05, t07, t08, t09; \
    type t10, t12, t13, t15, t16, t01; \
    t01 = a   & d  ; \
    t02 = c   ^ t01; \
    t03 = a   ^ d  ; \
    t04 = b   & t02; \
    t05 = a   & c  ; \
    w   = t03 ^ t04; \
    t07 = a   & w  ; \
    t08 = t01 ^ w  ; \
    t09 = b   | t05; \
    t10 =     ~ b  ; \
    x   = t08 ^ t09; \
    t12 = t10 | t07; \
    t13 = w   | x  ; \
    z   = t02 ^ t12; \
    t15 = t02 ^ t13; \
    t16 = b   ^ d  ; \
    y   = t16 ^ t15; \
  } while (0)

#define SBOX6_INVERSE(type, a, b, c, d, w, x, y, z) \
  do { \
    type t02, t03, t04, t05, t06, t07, t08, t09; \
    type t12, t13, t14, t15, t16, t17, t01;	     \
    t01 = a   ^ c  ; \
    t02 =     ~ c  ; \
    t03 = b   & t01; \
    t04 = b   | t02; \
    t05 = d   | t03; \
    t06 = b   ^ d  ; \
    t07 = a   & t04; \
    t08 = a   | t02; \
    t09 = t07 ^ t05; \
    x   = t06 ^ t08; \
    w   =     ~ t09; \
    t12 = b   & w  ; \
    t13 = t01 & t05; \
    t14 = t01 ^ t12; \
    t15 = t07 ^ t13; \
    t16 = d   | t02; \
    t17 = a   ^ x  ; \
    z   = t17 ^ t15; \
    y   = t16 ^ t14; \
  } while (0)

#define SBOX7_INVERSE(type, a, b, c, d, w, x, y, z) \
  do { \
    type t02, t03, t04, t06, t07, t08, t09; \
    type t10, t11, t13, t14, t15, t16, t01; \
    t01 = a   & b  ; \
    t02 = a   | b  ; \
    t03 = c   | t01; \
    t04 = d   & t02; \
    z   = t03 ^ t04; \
    t06 = b   ^ t04; \
    t07 = d   ^ z  ; \
    t08 =     ~ t07; \
    t09 = t06 | t08; \
    t10 = b   ^ d  ; \
    t11 = a   | d  ; \
    x   = a   ^ t09; \
    t13 = c   ^ t06; \
    t14 = c   & t11; \
    t15 = d   | x  ; \
    t16 = t01 | t10; \
    w   = t13 ^ t15; \
    y   = t14 ^ t16; \
  } while (0)

/* In-place inverse linear transformation.  */
#define LINEAR_TRANSFORMATION_INVERSE(x0,x1,x2,x3)	 \
  do {                                                   \
    x2 = ROL32 (x2, 10);                    \
    x0 = ROL32 (x0, 27);                    \
    x2 = x2 ^ x3 ^ (x1 << 7); \
    x0 = x0 ^ x1 ^ x3;        \
    x3 = ROL32 (x3, 25);                     \
    x1 = ROL32 (x1, 31);                     \
    x3 = x3 ^ x2 ^ (x0 << 3); \
    x1 = x1 ^ x0 ^ x2;        \
    x2 = ROL32 (x2, 29);                     \
    x0 = ROL32 (x0, 19);                    \
  } while (0)

/* Round inputs are x0,x1,x2,x3 (destroyed), and round outputs are
   y0,y1,y2,y3. */
#define ROUND_INVERSE(which, subkey, x0,x1,x2,x3, y0,y1,y2,y3) \
  do {							       \
    LINEAR_TRANSFORMATION_INVERSE (x0,x1,x2,x3);	       \
    SBOX##which##_INVERSE(uint32_t, x0,x1,x2,x3, y0,y1,y2,y3);	       \
    KEYXOR(y0,y1,y2,y3, subkey);			       \
  } while (0)

#if HAVE_NATIVE_64_BIT

/* In-place inverse linear transformation.  */
#define LINEAR_TRANSFORMATION64_INVERSE(x0,x1,x2,x3)	 \
  do {                                                   \
    x2 = ROL64 (x2, 10);                    \
    x0 = ROL64 (x0, 27);                    \
    x2 = x2 ^ x3 ^ RSHIFT64(x1, 7); \
    x0 = x0 ^ x1 ^ x3;        \
    x3 = ROL64 (x3, 25);                     \
    x1 = ROL64 (x1, 31);                     \
    x3 = x3 ^ x2 ^ RSHIFT64(x0, 3); \
    x1 = x1 ^ x0 ^ x2;        \
    x2 = ROL64 (x2, 29);                     \
    x0 = ROL64 (x0, 19);                    \
  } while (0)

#define ROUND64_INVERSE(which, subkey, x0,x1,x2,x3, y0,y1,y2,y3) \
  do {							       \
    LINEAR_TRANSFORMATION64_INVERSE (x0,x1,x2,x3);	       \
    SBOX##which##_INVERSE(uint64_t, x0,x1,x2,x3, y0,y1,y2,y3);	       \
    KEYXOR64(y0,y1,y2,y3, subkey);			       \
  } while (0)

#endif /* HAVE_NATIVE_64_BIT */

void
serpent_decrypt (const struct serpent_ctx *ctx,
		 unsigned length, uint8_t * dst, const uint8_t * src)
{
  assert( !(length % SERPENT_BLOCK_SIZE));

#if HAVE_NATIVE_64_BIT
  if (length & SERPENT_BLOCK_SIZE)
#else
  while (length >= SERPENT_BLOCK_SIZE)
#endif
    {
      uint32_t x0,x1,x2,x3, y0,y1,y2,y3;
      unsigned k;

      x0 = LE_READ_UINT32 (src);
      x1 = LE_READ_UINT32 (src + 4);
      x2 = LE_READ_UINT32 (src + 8);
      x3 = LE_READ_UINT32 (src + 12);

      /* Inverse of special round */
      KEYXOR (x0,x1,x2,x3, ctx->keys[32]);
      SBOX7_INVERSE (uint32_t, x0,x1,x2,x3, y0,y1,y2,y3);
      KEYXOR (y0,y1,y2,y3, ctx->keys[31]);

      k = 24;
      goto start32;
      while (k > 0)
	{
	  k -= 8;
	  ROUND_INVERSE (7, ctx->keys[k+7], x0,x1,x2,x3, y0,y1,y2,y3);
	start32:
	  ROUND_INVERSE (6, ctx->keys[k+6], y0,y1,y2,y3, x0,x1,x2,x3);
	  ROUND_INVERSE (5, ctx->keys[k+5], x0,x1,x2,x3, y0,y1,y2,y3);
	  ROUND_INVERSE (4, ctx->keys[k+4], y0,y1,y2,y3, x0,x1,x2,x3);
	  ROUND_INVERSE (3, ctx->keys[k+3], x0,x1,x2,x3, y0,y1,y2,y3);
	  ROUND_INVERSE (2, ctx->keys[k+2], y0,y1,y2,y3, x0,x1,x2,x3);
	  ROUND_INVERSE (1, ctx->keys[k+1], x0,x1,x2,x3, y0,y1,y2,y3);
	  ROUND_INVERSE (0, ctx->keys[k], y0,y1,y2,y3, x0,x1,x2,x3);
	}
      
      LE_WRITE_UINT32 (dst, x0);
      LE_WRITE_UINT32 (dst + 4, x1);
      LE_WRITE_UINT32 (dst + 8, x2);
      LE_WRITE_UINT32 (dst + 12, x3);

      src += SERPENT_BLOCK_SIZE;
      dst += SERPENT_BLOCK_SIZE;
      length -= SERPENT_BLOCK_SIZE;
    }
#if HAVE_NATIVE_64_BIT
  FOR_BLOCKS(length, dst, src, 2*SERPENT_BLOCK_SIZE)
    {
      uint64_t x0,x1,x2,x3, y0,y1,y2,y3;
      unsigned k;

      x0 = LE_READ_UINT32 (src);
      x1 = LE_READ_UINT32 (src + 4);
      x2 = LE_READ_UINT32 (src + 8);
      x3 = LE_READ_UINT32 (src + 12);

      x0 <<= 32; x0 |= LE_READ_UINT32 (src + 16);
      x1 <<= 32; x1 |= LE_READ_UINT32 (src + 20);
      x2 <<= 32; x2 |= LE_READ_UINT32 (src + 24);
      x3 <<= 32; x3 |= LE_READ_UINT32 (src + 28);

      /* Inverse of special round */
      KEYXOR64 (x0,x1,x2,x3, ctx->keys[32]);
      SBOX7_INVERSE (uint64_t, x0,x1,x2,x3, y0,y1,y2,y3);
      KEYXOR64 (y0,y1,y2,y3, ctx->keys[31]);

      k = 24;
      goto start64;
      while (k > 0)
	{
	  k -= 8;
	  ROUND64_INVERSE (7, ctx->keys[k+7], x0,x1,x2,x3, y0,y1,y2,y3);
	start64:
	  ROUND64_INVERSE (6, ctx->keys[k+6], y0,y1,y2,y3, x0,x1,x2,x3);
	  ROUND64_INVERSE (5, ctx->keys[k+5], x0,x1,x2,x3, y0,y1,y2,y3);
	  ROUND64_INVERSE (4, ctx->keys[k+4], y0,y1,y2,y3, x0,x1,x2,x3);
	  ROUND64_INVERSE (3, ctx->keys[k+3], x0,x1,x2,x3, y0,y1,y2,y3);
	  ROUND64_INVERSE (2, ctx->keys[k+2], y0,y1,y2,y3, x0,x1,x2,x3);
	  ROUND64_INVERSE (1, ctx->keys[k+1], x0,x1,x2,x3, y0,y1,y2,y3);
	  ROUND64_INVERSE (0, ctx->keys[k], y0,y1,y2,y3, x0,x1,x2,x3);
	}
    
      LE_WRITE_UINT32 (dst + 16, x0);
      LE_WRITE_UINT32 (dst + 20, x1);
      LE_WRITE_UINT32 (dst + 24, x2);
      LE_WRITE_UINT32 (dst + 28, x3);
      x0 >>= 32; LE_WRITE_UINT32 (dst, x0);
      x1 >>= 32; LE_WRITE_UINT32 (dst + 4, x1);
      x2 >>= 32; LE_WRITE_UINT32 (dst + 8, x2);
      x3 >>= 32; LE_WRITE_UINT32 (dst + 12, x3);
    }
#endif /* HAVE_NATIVE_64_BIT */  
}
