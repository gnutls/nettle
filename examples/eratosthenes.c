/* eratosthenes.c
 *
 * An implementation of the sieve of Eratosthenes, to generate a list of primes.
 *
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2007 Niels Möller
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "getopt.h"

#ifdef SIZEOF_LONG
# define BITS_PER_LONG (CHAR_BIT * SIZEOF_LONG)
# if BITS_PER_LONG > 32
#  define NEED_HANDLE_LARGE_LONG 1
# else
#  define NEED_HANDLE_LARGE_LONG 0
# endif
#else
# define BITS_PER_LONG (CHAR_BIT * sizeof(unsigned long))
# define NEED_HANDLE_LARGE_LONG 1
#endif


static void
usage(void)
{
  fprintf(stderr, "Usage: erathostenes [OPTIONS] [LIMIT]\n\n"
	  "Options:\n"
	  "      -?         Display this message.\n"
	  "      -b  SIZE   Block size.\n");
}

static unsigned
isqrt(unsigned long n)
{
  unsigned long x;

  /* FIXME: Better initialization. */
  if (n < ULONG_MAX)
    x = n;
  else
    /* Must avoid overflow in the first step. */
    x = n-1;

  for (;;)
    {
      unsigned long y = (x + n/x) / 2;
      if (y >= x)
	return x;

      x = y;
    }
}

/* Size is in bits */
static unsigned long *
vector_alloc(unsigned long size)
{
  unsigned long end = (size + BITS_PER_LONG - 1) / BITS_PER_LONG;
  unsigned long i;
  unsigned long *vector = malloc (end * sizeof(long));

  if (!vector)
    return NULL;

  for (i = 0; i < end; i++)
    vector[i] = ~0;

  return vector;
}

static void
vector_clear_bits (unsigned long *vector, unsigned long step,
		   unsigned long start, unsigned long size)
{
  unsigned long bit;

  for (bit = start; bit < size; bit += step)
    {
      unsigned long i = bit / BITS_PER_LONG;
      unsigned long mask = 1L << (bit % BITS_PER_LONG);

      vector[i] &= ~mask;
    }
}

static unsigned
find_first_one (unsigned long x)
{
  unsigned table[0x10] =
    {
      /* 0, 1,  2,  3,  4,  5,  6,  7 */
	-1, 0,  1,  0,  2,  0,  1 , 0,
      /* 8, 9, 10, 11, 12, 13, 14, 15 */
	 3, 0,  1,  0,  2,  0,  1,  0
    };

  /* Isolate least significant bit */
  x &= -x;

  unsigned i = 0;
#if NEED_HANDLE_LARGE_LONG
#ifndef SIZEOF_LONG
  /* Can't not be tested by the preprocessor. May generate warnings
     when long is 32 bits. */
  if (BITS_PER_LONG > 32)
#endif
    while (x >= 0x100000000L)
      {
	x >>= 32;
	i += 32;
      }
#endif /* NEED_HANDLE_LARGE_LONG */

  if (x >= 0x10000)
    {
      x >>= 16;
      i =+ 16;
    }
  if (x >= 0x100)
    {
      x >>= 8;
      i += 8;
    }
  if (x >= 0x10)
    {
      x >>= 4;
      i += 4;
    }
  return i + table[x & 0xf];
}

/* Returns size if there's no more bits set */
static unsigned long
vector_find_next (const unsigned long *vector, unsigned long bit, unsigned long size)
{
  unsigned long end = (size + BITS_PER_LONG - 1) / BITS_PER_LONG;
  unsigned long i = bit / BITS_PER_LONG;
  unsigned long mask = 1L << (bit % BITS_PER_LONG);
  unsigned long word;

  if (i >= end)
    return size;

  for (word = vector[i] & ~(mask - 1); !word; word = vector[i])
    if (++i >= end)
      return size;

  /* Next bit is the least significant bit of word */
  return i * BITS_PER_LONG + find_first_one(word);
}

int
main (int argc, char **argv)
{
  unsigned long *vector;
  /* Generate all primes p <= limit */
  unsigned long limit;
  unsigned long size;
  unsigned long bit;
  unsigned long sieve_limit;
  unsigned long block_size;
  unsigned long block;

  int c;

  block_size = 0;

  while ( (c = getopt(argc, argv, "?b:")) != -1)
    switch (c)
      {
      case '?':
	usage();
	return EXIT_FAILURE;
      case 'b':
	{
	  long arg = atoi(optarg);
	  if (arg <= 10)
	    {
	      usage();
	      return EXIT_FAILURE;
	    }
	  block_size = (arg - 3) / 2;
	  break;
	}
      default:
	abort();
      }

  argc -= optind;
  argv += optind;

  if (argc == 0)
    limit = 1000;
  else if (argc == 1)
    {
      limit = atoi(argv[0]);
      if (limit < 2)
	return EXIT_SUCCESS;
    }
  else
    {
      usage();
      return EXIT_FAILURE;
    }

  size = (limit - 1) / 2;

  if (!block_size || block_size > size)
    block_size = size;

  vector = vector_alloc (size);
  if (!vector)
    {
      fprintf(stderr, "Insufficient memory.\n");
      return EXIT_FAILURE;
    }

  printf("2\n");

  bit = 0;

  if (limit == 2)
    return EXIT_SUCCESS;

  sieve_limit = (isqrt(2*block_size + 1) - 1) / 2;

  while (bit < sieve_limit)
    {
      unsigned long n = 3 + 2 * bit;

      printf("%lu\n", n);

      /* First bit to clear corresponds to n^2, which is bit

	 (n^2 - 3) / 2 = n * bit + 3 (bit + 1)
      */
      vector_clear_bits (vector, n, n*bit + 3*(bit + 1), block_size);

      bit = vector_find_next (vector, bit + 1, block_size);
    }

  /* No more marking, just output the remaining primes. */
  for (; bit < block_size ;
       bit = vector_find_next (vector, bit + 1, size))

    printf("%lu\n", 3 + 2 * bit);

  for (block = block_size; block < size; block += block_size)
    {
      unsigned long block_start;
      unsigned long block_end;

      if (block + block_size > size)
	/* For the final block */
	block_size = size - block;

      block_start = 2*block + 3;
      block_end = 2*(block + block_size) + 3;

      sieve_limit = (isqrt(block_end) - 1) / 2;
      for (bit = 0; bit < sieve_limit ;)
	{
	  unsigned long n = 3 + 2 * bit;

	  unsigned long start = n*bit + 3*(bit + 1);
	  if (start < block)
	    {
	      unsigned long k = (block + 1) / n;
	      start = bit + k*n;
	    }
	  vector_clear_bits (vector, n, start, block + block_size);

	  bit = vector_find_next (vector, bit + 1, block + block_size);
	}
      for (bit = vector_find_next (vector, block, block + block_size);
	   bit < block + block_size;
	   bit = vector_find_next (vector, bit + 1, block + block_size))
	printf("%lu\n", 3 + 2 * bit);
    }

  return EXIT_SUCCESS;
}
