/* memxor.c

   Copyright (C) 2010, 2014 Niels Möller

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

/* Implementation inspired by memcmp in glibc, contributed to the FSF
   by Torbjorn Granlund.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <limits.h>

#include "memxor.h"
#include "memxor-internal.h"

#define WORD_T_THRESH 16

/* XOR word-aligned areas. n is the number of words, not bytes. */
static void
memxor3_common_alignment (word_t *dst,
			  const word_t *a, const word_t *b, size_t n)
{
  /* FIXME: Require n > 0? */
  if (n & 1)
    {
      n--;
      dst[n] = a[n] ^ b[n];
    }
  while (n > 0)
    {
      n -= 2;
      dst[n+1] = a[n+1] ^ b[n+1];
      dst[n] = a[n] ^ b[n];
    }
}

static void
memxor3_different_alignment_b (word_t *dst,
			       const word_t *a, const char *b, unsigned offset, size_t n)
{
  int shl, shr;
  const word_t *b_word;

  word_t s0, s1;

  shl = CHAR_BIT * offset;
  shr = CHAR_BIT * (sizeof(word_t) - offset);

  b_word = (const word_t *) ((uintptr_t) b & -sizeof(word_t));

  if (n & 1)
    {
      n--;
      s1 = b_word[n];
      s0 = b_word[n+1];
      dst[n] = a[n] ^ MERGE (s1, shl, s0, shr);
    }
  else
    s1 = b_word[n];

  while (n > 0)
    {
      n -= 2;
      s0 = b_word[n+1];
      dst[n+1] = a[n+1] ^ MERGE(s0, shl, s1, shr);
      s1 = b_word[n];
      dst[n] = a[n] ^ MERGE(s1, shl, s0, shr);
    }
}

static void
memxor3_different_alignment_ab (word_t *dst,
				const char *a, const char *b,
				unsigned offset, size_t n)
{
  int shl, shr;
  const word_t *a_word;
  const word_t *b_word;

  word_t s0, s1;

  shl = CHAR_BIT * offset;
  shr = CHAR_BIT * (sizeof(word_t) - offset);

  a_word = (const word_t *) ((uintptr_t) a & -sizeof(word_t));
  b_word = (const word_t *) ((uintptr_t) b & -sizeof(word_t));

  if (n & 1)
    {
      n--;
      s1 = a_word[n] ^ b_word[n];
      s0 = a_word[n+1] ^ b_word[n+1];
      dst[n] = MERGE (s1, shl, s0, shr);
    }
  else
    s1 = a_word[n] ^ b_word[n];

  while (n > 0)
    {
      n -= 2;
      s0 = a_word[n+1] ^ b_word[n+1];
      dst[n+1] = MERGE(s0, shl, s1, shr);
      s1 = a_word[n] ^ b_word[n];
      dst[n] = MERGE(s1, shl, s0, shr);
    }
}

static void
memxor3_different_alignment_all (word_t *dst,
				 const char *a, const char *b,
				 unsigned a_offset, unsigned b_offset,
				 size_t n)
{
  int al, ar, bl, br;
  const word_t *a_word;
  const word_t *b_word;

  word_t a0, a1, b0, b1;

  al = CHAR_BIT * a_offset;
  ar = CHAR_BIT * (sizeof(word_t) - a_offset);
  bl = CHAR_BIT * b_offset;
  br = CHAR_BIT * (sizeof(word_t) - b_offset);

  a_word = (const word_t *) ((uintptr_t) a & -sizeof(word_t));
  b_word = (const word_t *) ((uintptr_t) b & -sizeof(word_t));

  if (n & 1)
    {
      n--;
      a1 = a_word[n]; a0 = a_word[n+1];
      b1 = b_word[n]; b0 = b_word[n+1];

      dst[n] = MERGE (a1, al, a0, ar) ^ MERGE (b1, bl, b0, br);
    }
  else
    {
      a1 = a_word[n];
      b1 = b_word[n];
    }

  while (n > 0)
    {
      n -= 2;
      a0 = a_word[n+1]; b0 = b_word[n+1];
      dst[n+1] = MERGE(a0, al, a1, ar) ^ MERGE(b0, bl, b1, br);
      a1 = a_word[n]; b1 = b_word[n];
      dst[n] = MERGE(a1, al, a0, ar) ^ MERGE(b1, bl, b0, br);
    }
}

/* Current implementation processes data in descending order, to
   support overlapping operation with one of the sources overlapping
   the start of the destination area. This feature is used only
   internally by cbc decrypt, and it is not advertised or documented
   to nettle users. */
void *
memxor3(void *dst_in, const void *a_in, const void *b_in, size_t n)
{
  char *dst = dst_in;
  const char *a = a_in;
  const char *b = b_in;

  if (n >= WORD_T_THRESH)
    {
      unsigned i;
      unsigned a_offset;
      unsigned b_offset;
      size_t nwords;

      for (i = ALIGN_OFFSET(dst + n); i > 0; i--)
	{
	  n--;
	  dst[n] = a[n] ^ b[n];
	}

      a_offset = ALIGN_OFFSET(a + n);
      b_offset = ALIGN_OFFSET(b + n);

      nwords = n / sizeof (word_t);
      n %= sizeof (word_t);

      if (a_offset == b_offset)
	{
	  if (!a_offset)
	    memxor3_common_alignment((word_t *) (dst + n),
				     (const word_t *) (a + n),
				     (const word_t *) (b + n), nwords);
	  else
	    memxor3_different_alignment_ab((word_t *) (dst + n),
					   a + n, b + n, a_offset,
					   nwords);
	}
      else if (!a_offset)
	memxor3_different_alignment_b((word_t *) (dst + n),
				      (const word_t *) (a + n), b + n,
				      b_offset, nwords);
      else if (!b_offset)
	memxor3_different_alignment_b((word_t *) (dst + n),
				      (const word_t *) (b + n), a + n,
				      a_offset, nwords);
      else
	memxor3_different_alignment_all((word_t *) (dst + n), a + n, b + n,
					a_offset, b_offset, nwords);

    }
  while (n-- > 0)
    dst[n] = a[n] ^ b[n];

  return dst;
}
