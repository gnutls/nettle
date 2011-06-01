/* serpent.c
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

#include "serpent.h"

#include "macros.h"

/* Magic number, used during generating of the subkeys.  */
#define PHI 0x9E3779B9

/* FIXME: Unify ROL macros used here, in camellia.c and cast128.c. */
#define ROL32(x,n) ((((uint32_t)(x))<<(n))|	\
                  (((uint32_t)(x))>>(32-(n))))
#define ROR32(x,n) ((((uint32_t)(x))<<(32-(n)))|	\
                  (((uint32_t)(x))>>(n)))

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
#define SBOX0(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t05, t06, t07, t08, t09; \
    uint32_t t11, t12, t13, t14, t15, t17, t01; \
    t01 = b   ^ c  ; \
    t02 = a   | d  ; \
    t03 = a   ^ b  ; \
    z   = t02 ^ t01; \
    t05 = c   | z  ; \
    t06 = a   ^ d  ; \
    t07 = b   | c  ; \
    t08 = d   & t05; \
    t09 = t03 & t07; \
    y   = t09 ^ t08; \
    t11 = t09 & y  ; \
    t12 = c   ^ d  ; \
    t13 = t07 ^ t11; \
    t14 = b   & t06; \
    t15 = t06 ^ t13; \
    w   =     ~ t15; \
    t17 = w   ^ t14; \
    x   = t12 ^ t17; \
  } while (0)

#define SBOX0_INVERSE(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t04, t05, t06, t08, t09, t10; \
    uint32_t t12, t13, t14, t15, t17, t18, t01; \
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

#define SBOX1(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t04, t05, t06, t07, t08; \
    uint32_t t10, t11, t12, t13, t16, t17, t01; \
    t01 = a   | d  ; \
    t02 = c   ^ d  ; \
    t03 =     ~ b  ; \
    t04 = a   ^ c  ; \
    t05 = a   | t03; \
    t06 = d   & t04; \
    t07 = t01 & t02; \
    t08 = b   | t06; \
    y   = t02 ^ t05; \
    t10 = t07 ^ t08; \
    t11 = t01 ^ t10; \
    t12 = y   ^ t11; \
    t13 = b   & d  ; \
    z   =     ~ t10; \
    x   = t13 ^ t12; \
    t16 = t10 | x  ; \
    t17 = t05 & t16; \
    w   = c   ^ t17; \
  } while (0)

#define SBOX1_INVERSE(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t04, t05, t06, t07, t08; \
    uint32_t t09, t10, t11, t14, t15, t17, t01; \
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

#define SBOX2(a, b, c, d, w, x, y, z) \
  do {					   \
    uint32_t t02, t03, t05, t06, t07, t08; \
    uint32_t t09, t10, t12, t13, t14, t01; \
    t01 = a   | c  ; \
    t02 = a   ^ b  ; \
    t03 = d   ^ t01; \
    w   = t02 ^ t03; \
    t05 = c   ^ w  ; \
    t06 = b   ^ t05; \
    t07 = b   | t05; \
    t08 = t01 & t06; \
    t09 = t03 ^ t07; \
    t10 = t02 | t09; \
    x   = t10 ^ t08; \
    t12 = a   | d  ; \
    t13 = t09 ^ x  ; \
    t14 = b   ^ t13; \
    z   =     ~ t09; \
    y   = t12 ^ t14; \
  } while (0)

#define SBOX2_INVERSE(a, b, c, d, w, x, y, z) \
  do {						\
    uint32_t t02, t03, t04, t06, t07, t08, t09; \
    uint32_t t10, t11, t12, t15, t16, t17, t01; \
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

#define SBOX3(a, b, c, d, w, x, y, z) \
  do {						\
    uint32_t t02, t03, t04, t05, t06, t07, t08; \
    uint32_t t09, t10, t11, t13, t14, t15, t01; \
    t01 = a   ^ c  ; \
    t02 = a   | d  ; \
    t03 = a   & d  ; \
    t04 = t01 & t02; \
    t05 = b   | t03; \
    t06 = a   & b  ; \
    t07 = d   ^ t04; \
    t08 = c   | t06; \
    t09 = b   ^ t07; \
    t10 = d   & t05; \
    t11 = t02 ^ t10; \
    z   = t08 ^ t09; \
    t13 = d   | z  ; \
    t14 = a   | t07; \
    t15 = b   & t13; \
    y   = t08 ^ t11; \
    w   = t14 ^ t15; \
    x   = t05 ^ t04; \
  } while (0)

#define SBOX3_INVERSE(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t04, t05, t06, t07, t09; \
    uint32_t t11, t12, t13, t14, t16, t01; \
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

#define SBOX4(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t04, t05, t06, t08, t09; \
    uint32_t t10, t11, t12, t13, t14, t15, t16, t01; \
    t01 = a   | b  ; \
    t02 = b   | c  ; \
    t03 = a   ^ t02; \
    t04 = b   ^ d  ; \
    t05 = d   | t03; \
    t06 = d   & t01; \
    z   = t03 ^ t06; \
    t08 = z   & t04; \
    t09 = t04 & t05; \
    t10 = c   ^ t06; \
    t11 = b   & c  ; \
    t12 = t04 ^ t08; \
    t13 = t11 | t03; \
    t14 = t10 ^ t09; \
    t15 = a   & t05; \
    t16 = t11 | t12; \
    y   = t13 ^ t08; \
    x   = t15 ^ t16; \
    w   =     ~ t14; \
  } while (0)

#define SBOX4_INVERSE(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t04, t05, t06, t07, t09; \
    uint32_t t10, t11, t12, t13, t15, t01; \
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

#define SBOX5(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t04, t05, t07, t08, t09; \
    uint32_t t10, t11, t12, t13, t14, t01; \
    t01 = b   ^ d  ; \
    t02 = b   | d  ; \
    t03 = a   & t01; \
    t04 = c   ^ t02; \
    t05 = t03 ^ t04; \
    w   =     ~ t05; \
    t07 = a   ^ t01; \
    t08 = d   | w  ; \
    t09 = b   | t05; \
    t10 = d   ^ t08; \
    t11 = b   | t07; \
    t12 = t03 | w  ; \
    t13 = t07 | t10; \
    t14 = t01 ^ t11; \
    y   = t09 ^ t13; \
    x   = t07 ^ t08; \
    z   = t12 ^ t14; \
  } while (0)

#define SBOX5_INVERSE(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t04, t05, t07, t08, t09; \
    uint32_t t10, t12, t13, t15, t16, t01; \
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

#define SBOX6(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t04, t05, t07, t08, t09, t10; \
    uint32_t t11, t12, t13, t15, t17, t18, t01; \
    t01 = a   & d  ; \
    t02 = b   ^ c  ; \
    t03 = a   ^ d  ; \
    t04 = t01 ^ t02; \
    t05 = b   | c  ; \
    x   =     ~ t04; \
    t07 = t03 & t05; \
    t08 = b   & x  ; \
    t09 = a   | c  ; \
    t10 = t07 ^ t08; \
    t11 = b   | d  ; \
    t12 = c   ^ t11; \
    t13 = t09 ^ t10; \
    y   =     ~ t13; \
    t15 = x   & t03; \
    z   = t12 ^ t07; \
    t17 = a   ^ b  ; \
    t18 = y   ^ t15; \
    w   = t17 ^ t18; \
  } while (0)

#define SBOX6_INVERSE(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t04, t05, t06, t07, t08, t09; \
    uint32_t t12, t13, t14, t15, t16, t17, t01; \
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

#define SBOX7(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t04, t05, t06, t08, t09, t10; \
    uint32_t t11, t13, t14, t15, t16, t17, t01; \
    t01 = a   & c  ; \
    t02 =     ~ d  ; \
    t03 = a   & t02; \
    t04 = b   | t01; \
    t05 = a   & b  ; \
    t06 = c   ^ t04; \
    z   = t03 ^ t06; \
    t08 = c   | z  ; \
    t09 = d   | t05; \
    t10 = a   ^ t08; \
    t11 = t04 & z  ; \
    x   = t09 ^ t10; \
    t13 = b   ^ x  ; \
    t14 = t01 ^ x  ; \
    t15 = c   ^ t05; \
    t16 = t11 | t13; \
    t17 = t02 | t14; \
    w   = t15 ^ t17; \
    y   = a   ^ t16; \
  } while (0)

#define SBOX7_INVERSE(a, b, c, d, w, x, y, z) \
  do { \
    uint32_t t02, t03, t04, t06, t07, t08, t09; \
    uint32_t t10, t11, t13, t14, t15, t16, t01; \
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

/* In-place linear transformation.  */
#define LINEAR_TRANSFORMATION(x0,x1,x2,x3)		 \
  do {                                                   \
    x0 = ROL32 (x0, 13);                    \
    x2 = ROL32 (x2, 3);                     \
    x1 = x1 ^ x0 ^ x2;        \
    x3 = x3 ^ x2 ^ (x0 << 3); \
    x1 = ROL32 (x1, 1);                     \
    x3 = ROL32 (x3, 7);                     \
    x0 = x0 ^ x1 ^ x3;        \
    x2 = x2 ^ x3 ^ (x1 << 7); \
    x0 = ROL32 (x0, 5);                     \
    x2 = ROL32 (x2, 22);                    \
  } while (0)

/* In-place inverse linear transformation.  */
#define LINEAR_TRANSFORMATION_INVERSE(x0,x1,x2,x3)	 \
  do {                                                   \
    x2 = ROR32 (x2, 22);                    \
    x0 = ROR32 (x0 , 5);                    \
    x2 = x2 ^ x3 ^ (x1 << 7); \
    x0 = x0 ^ x1 ^ x3;        \
    x3 = ROR32 (x3, 7);                     \
    x1 = ROR32 (x1, 1);                     \
    x3 = x3 ^ x2 ^ (x0 << 3); \
    x1 = x1 ^ x0 ^ x2;        \
    x2 = ROR32 (x2, 3);                     \
    x0 = ROR32 (x0, 13);                    \
  } while (0)

#define KEYXOR(x0,x1,x2,x3, subkey)		       \
  do {						       \
    (x0) ^= (subkey)[0];			       \
    (x1) ^= (subkey)[1];			       \
    (x2) ^= (subkey)[2];			       \
    (x3) ^= (subkey)[3];			       \
  } while (0)

/* Round inputs are x0,x1,x2,x3 (destroyed), and round outputs are
   y0,y1,y2,y3. */
#define ROUND(which, subkey, x0,x1,x2,x3, y0,y1,y2,y3) \
  do {						       \
    KEYXOR(x0,x1,x2,x3, subkey);		       \
    SBOX##which(x0,x1,x2,x3, y0,y1,y2,y3);	       \
    LINEAR_TRANSFORMATION(y0,y1,y2,y3);		       \
  } while (0)

/* Round inputs are x0,x1,x2,x3 (destroyed), and round outputs are
   y0,y1,y2,y3. */
#define ROUND_INVERSE(which, subkey, x0,x1,x2,x3, y0,y1,y2,y3) \
  do {							       \
    LINEAR_TRANSFORMATION_INVERSE (x0,x1,x2,x3);	       \
    SBOX##which##_INVERSE(x0,x1,x2,x3, y0,y1,y2,y3);	       \
    KEYXOR(y0,y1,y2,y3, subkey);			       \
  } while (0)

/* Key schedule */
/* Note: Increments k */
#define KS_RECURRENCE(w, i, k)						\
  do {									\
    uint32_t _wn = (w)[(i)] ^ (w)[((i)+3)&7] ^ w[((i)+5)&7]		\
      ^ w[((i)+7)&7] ^ PHI ^ (k)++;					\
    ((w)[(i)] = ROL32(_wn, 11));					\
  } while (0)

/* Note: Increments k four times and keys once */
#define KS(keys, s, w, i, k)					\
  do {								\
    KS_RECURRENCE(w, (i), (k));					\
    KS_RECURRENCE(w, (i)+1, (k));				\
    KS_RECURRENCE(w, (i)+2, (k));				\
    KS_RECURRENCE(w, (i)+3, (k));				\
    SBOX##s(w[(i)],w[(i)+1],w[(i)+2],w[(i)+3],			\
	    (*keys)[0],(*keys)[1],(*keys)[2],(*keys)[3]);	\
    (keys)++;							\
  } while (0)

/* Pad user key and convert to an array of 8 uint32_t. */
static void
serpent_key_pad (const uint8_t *key, unsigned int key_length,
		 uint32_t *w)
{
  unsigned int i;

  assert (key_length <= SERPENT_MAX_KEY_SIZE);
  
  for (i = 0; key_length >= 4; key_length -=4, key += 4)
    w[i++] = LE_READ_UINT32(key);

  if (i < 8)
    {
      /* Key must be padded according to the Serpent specification.
         "aabbcc" -> "aabbcc0100...00" -> 0x01ccbbaa. */
      uint32_t pad = 0x01;
      
      while (key_length > 0)
	pad = pad << 8 | key[--key_length];

      w[i++] = pad;

      while (i < 8)
	w[i++] = 0;
    }
}

/* Initialize CONTEXT with the key KEY of KEY_LENGTH bits.  */
void
serpent_set_key (struct serpent_ctx *ctx,
		 unsigned length, const uint8_t * key)
{
  uint32_t w[8];
  uint32_t (*keys)[4];
  unsigned k;
  
  serpent_key_pad (key, length, w);

  /* Derive the 33 subkeys from KEY and store them in SUBKEYS. We do
     the recurrence in the key schedule using W as a circular buffer
     of just 8 uint32_t. */

  /* FIXME: Would be better to invoke SBOX with scalar variables as
     arguments, no arrays. To do that, unpack w into separate
     variables, use temporary variables as the SBOX destination. */

  keys = ctx->keys;
  k = 0;
  for (;;)
    {
      KS(keys, 3, w, 0, k);
      if (k == 132)
	break;
      KS(keys, 2, w, 4, k);
      KS(keys, 1, w, 0, k);
      KS(keys, 0, w, 4, k);
      KS(keys, 7, w, 0, k);
      KS(keys, 6, w, 4, k);
      KS(keys, 5, w, 0, k);
      KS(keys, 4, w, 4, k);
    }
  assert (keys == ctx->keys + 33);
}

void
serpent_encrypt (const struct serpent_ctx *ctx,
		 unsigned length, uint8_t * dst, const uint8_t * src)
{
  FOR_BLOCKS (length, dst, src, SERPENT_BLOCK_SIZE)
    {
      uint32_t x0,x1,x2,x3, y0,y1,y2,y3;
      unsigned k;

      x0 = LE_READ_UINT32 (src);
      x1 = LE_READ_UINT32 (src + 4);
      x2 = LE_READ_UINT32 (src + 8);
      x3 = LE_READ_UINT32 (src + 12);

      for (k = 0; ; k += 8)
	{
	  ROUND (0, ctx->keys[k+0], x0,x1,x2,x3, y0,y1,y2,y3);
	  ROUND (1, ctx->keys[k+1], y0,y1,y2,y3, x0,x1,x2,x3);
	  ROUND (2, ctx->keys[k+2], x0,x1,x2,x3, y0,y1,y2,y3);
	  ROUND (3, ctx->keys[k+3], y0,y1,y2,y3, x0,x1,x2,x3);
	  ROUND (4, ctx->keys[k+4], x0,x1,x2,x3, y0,y1,y2,y3);
	  ROUND (5, ctx->keys[k+5], y0,y1,y2,y3, x0,x1,x2,x3);
	  ROUND (6, ctx->keys[k+6], x0,x1,x2,x3, y0,y1,y2,y3);
	  if (k == 24)
	    break;
	  ROUND (7, ctx->keys[k+7], y0,y1,y2,y3, x0,x1,x2,x3);
	}

      /* Special final round, using two subkeys. */
      KEYXOR (y0,y1,y2,y3, ctx->keys[31]);
      SBOX7 (y0,y1,y2,y3, x0,x1,x2,x3);
      KEYXOR (x0,x1,x2,x3, ctx->keys[32]);
    
      LE_WRITE_UINT32 (dst, x0);
      LE_WRITE_UINT32 (dst + 4, x1);
      LE_WRITE_UINT32 (dst + 8, x2);
      LE_WRITE_UINT32 (dst + 12, x3);
    }
}

void
serpent_decrypt (const struct serpent_ctx *ctx,
		 unsigned length, uint8_t * dst, const uint8_t * src)
{
  FOR_BLOCKS (length, dst, src, SERPENT_BLOCK_SIZE)
    {
      uint32_t x0,x1,x2,x3, y0,y1,y2,y3;
      unsigned k;

      x0 = LE_READ_UINT32 (src);
      x1 = LE_READ_UINT32 (src + 4);
      x2 = LE_READ_UINT32 (src + 8);
      x3 = LE_READ_UINT32 (src + 12);

      /* Inverse of special round */
      KEYXOR (x0,x1,x2,x3, ctx->keys[32]);
      SBOX7_INVERSE (x0,x1,x2,x3, y0,y1,y2,y3);
      KEYXOR (y0,y1,y2,y3, ctx->keys[31]);

      k = 24;
      goto start;
      while (k > 0)
	{
	  k -= 8;
	  ROUND_INVERSE (7, ctx->keys[k+7], x0,x1,x2,x3, y0,y1,y2,y3);
	start:
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
    }
}
