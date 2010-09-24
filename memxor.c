/* memxor.c
 *
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 1991, 1993, 1995 Free Software Foundation, Inc.
 * Copyright (C) 2010 Niels Möller
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

/* Implementation inspired by memcmp in glibc, contributed to the FSF by Torbjorn Granlund.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <limits.h>

#include "memxor.h"

#if 1
typedef unsigned long int word_t;

#if SIZEOF_LONG & (SIZEOF_LONG - 1)
#error Word size must be a power of two
#endif

#define ALIGN_OFFSET(p) ((uintptr_t) (p) % sizeof(word_t))

#ifndef WORDS_BIGENDIAN
#define MERGE(w0, sh_1, w1, sh_2) (((w0) >> (sh_1)) | ((w1) << (sh_2)))
#else
#define MERGE(w0, sh_1, w1, sh_2) (((w0) << (sh_1)) | ((w1) >> (sh_2)))
#endif

#define WORD_T_THRESH 16

/* XOR word-aligned areas. n is the number of words, not bytes. */
static void
memxor_common_alignment (word_t *dst, const word_t *src, size_t n)
{
  size_t i;
  /* FIXME: Unroll four times, like memcmp? */
  i = n & 1;
  if (i)
    dst[0] ^= src[0];

  for (; i < n; i += 2)
    {
      dst[i] ^= src[i];
      dst[i+1] ^= src[i+1];
    }
}

/* XOR *un-aligned* src-area onto aligned dst area. n is numer of
   words, not bytes. Assumes we can read complete words at the start
   and end of the src operand. */
static void
memxor_different_alignment (word_t *dst, const uint8_t *src, size_t n)
{
  size_t i;
  int shl, shr;
  const word_t *src_word;
  unsigned offset = ALIGN_OFFSET (src);
  word_t s0, s1;

  shl = CHAR_BIT * offset;
  shr = CHAR_BIT * (sizeof(word_t) - offset);

  src_word = (const word_t *) (src - offset);

  /* FIXME: Unroll four times, like memcmp? */
  i = n & 1;
  s0 = src_word[i];
  if (i)
    {
      s1 = src_word[0];
      s0 = src_word[1];
      dst[0] ^= MERGE (s1, shl, s0, shr);
    }

  for (; i < n; i += 2)
    {
      s1 = src_word[i+1];
      dst[i] ^= MERGE(s0, shl, s1, shr);
      s0 = src_word[i+2];
      dst[i+1] ^= MERGE(s1, shl, s0, shr);
    }
}

/* XOR LEN bytes starting at SRCADDR onto DESTADDR. Result undefined
   if the source overlaps with the destination. Return DESTADDR. */
uint8_t *
memxor(uint8_t *dst, const uint8_t *src, size_t n)
{
  uint8_t *orig_dst = dst;

  if (n >= WORD_T_THRESH)
    {
      size_t left_over;

      /* There are at least some bytes to compare.  No need to test
	 for N == 0 in this alignment loop.  */
      while (ALIGN_OFFSET (dst))
	{
	  *dst++ ^= *src++;
	  n--;
	}
      if (ALIGN_OFFSET (src))
	memxor_different_alignment ((word_t *) dst, src, n / sizeof(word_t));
      else
	memxor_common_alignment ((word_t *) dst, (const word_t *) src, n / sizeof(word_t));

      left_over = n % sizeof(word_t);
      dst += n - left_over;
      src += n - left_over;
      n = left_over;
    }
  for (; n > 0; n--)
    *dst++ ^= *src++;

  return orig_dst;
}
#else
uint8_t *
memxor(uint8_t *dst, const uint8_t *src, size_t n)
{
  size_t i;
  for (i = 0; i<n; i++)
    dst[i] ^= src[i];

  return dst;
}
#endif

uint8_t *
memxor3(uint8_t *dst, const uint8_t *a, const uint8_t *b, size_t n)
{
  size_t i;
  for (i = 0; i<n; i++)
    dst[i] = a[i] ^ b[i];

  return dst;
}

