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
	  "      --help         Display this message.\n"
	  "      --quiet        No summary line.\n"
	  "      --odd-only     Omit the prime 2.\n"
	  "      --primes-only  Suppress output of differences.\n"
	  "      --diff-only    Supress output of primes.\n"
	  "      --tabular      Tabular output (default is one prime per line).\n"
	  "      --binary       Binary output.\n"
	  "      --block SIZE   Block size.\n");
}

static unsigned
isqrt(unsigned n)
{
  unsigned x;

  /* FIXME: Better initialization. */
  if (n < UINT_MAX)
    x = n;
  else
    /* Must avoid overflow in the first step. */
    x = n-1;  

  for (;;)
    {
      unsigned y = (x + n/x) / 2;
      if (y >= x)
	return x;

      x = y;
    }
}

/* Size is in bits */
static unsigned long *
vector_alloc(unsigned size)
{
  unsigned end = (size + BITS_PER_LONG - 1) / BITS_PER_LONG;
  unsigned i;
  unsigned long *vector = malloc (end * sizeof(long));
  
  if (!vector)
    return NULL;

  for (i = 0; i < end; i++)
    vector[i] = ~0;

  return vector;
}

static void
vector_clear_bits (unsigned long *vector, unsigned step, unsigned start, unsigned size)
{
  unsigned bit;

  for (bit = start; bit < size; bit += step)
    {
      unsigned i = bit / BITS_PER_LONG;
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
static unsigned
vector_find_next (const unsigned long *vector, unsigned bit, unsigned size)
{
  unsigned end = (size + BITS_PER_LONG - 1) / BITS_PER_LONG;
  unsigned i = bit / BITS_PER_LONG;
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

struct output_info
{
  int output_2;
  enum {
    FORMAT_PRIMES = 1, FORMAT_DIFF = 2, FORMAT_TABULAR = 4, FORMAT_BINARY = 8
  } format;

  unsigned long last;
  unsigned column;

  /* For the binary output */
  unsigned size;
};

static void
output_init(struct output_info *info)
{
  info->output_2 = 1;
  info->format = FORMAT_PRIMES | FORMAT_DIFF;
  info->last = 0;
  info->size = 1;
}

static void
output(struct output_info *info, unsigned long p)
{
  if (info->format & FORMAT_BINARY)
    {
      /* Overrides the other formats. */
      unsigned char buf[4];
      unsigned diff = (p - info->last) / 2;
      switch (info->size)
	{
	case 1:
	  if (diff < 0x100)
	    {
	      putchar(diff);
	      break;
	    }
	  else
	    {
	      info->size++;
	      putchar(0);
	      /* Fall through */
	    }
	case 2:
	  if (diff < 0x10000)
	    {
	      buf[0] = diff >> 8;
	      buf[1] = diff & 0xff;
	      putchar(buf[0]);
	      putchar(buf[1]);
	      break;
	    }
	  else
	    {
	      info->size++;
	      putchar(0);
	      putchar(0);
	      /* Fall through */
	    }
	case 3:
	  if (diff < 0x1000000)
	    {
	      buf[0] = diff >> 16;
	      buf[1] = (diff >> 8) & 0xff;
	      buf[2] = diff & 0xff;
	      putchar(buf[0]);
	      putchar(buf[1]);
	      putchar(buf[2]);
	      break;
	    }
	  else
	    {
	      info->size++;
	      putchar(0);
	      putchar(0);
	      putchar(0);
	      /* Fall through */
	    }
	case 4:
	  buf[0] = diff >> 24;
	  buf[1] = (diff >> 16) & 0xff;
	  buf[2] = (diff >> 8) & 0xff;
	  buf[3] = diff & 0xff;
	  putchar(buf[0]);
	  putchar(buf[1]);
	  putchar(buf[2]);
	  putchar(buf[3]);
	  break;
	}
    }
  else if (info->format & (FORMAT_PRIMES | FORMAT_DIFF))
    {
      if (info->format & FORMAT_PRIMES)
	printf("%ld", p);
      if (info->format & FORMAT_DIFF)
	printf(" %ld", p - info->last);

      if (info->format & FORMAT_TABULAR)
	{
	  printf(",");
	  info->column++;
	  if (info->column == 16)
	    {
	      printf("\n");
	      info->column = 0;
	    }
	  else
	    printf(" ");
	}
      else
	printf("\n");
    }
  info->last = p;
}

static void
output_first(struct output_info *info)
{
  if (info->format & FORMAT_BINARY)
    {
      /* Omit 2, and start with 1, so that differences are odd. */
      info->last = 1;
    }
  else
    {
      info->column = 0;
      if (info->output_2)
	output(info, 2);

      info->last = 2;
    }
}

int
main (int argc, char **argv)
{
  unsigned long *vector;
  /* Generate all primes p <= limit */
  unsigned limit;
  unsigned size;
  unsigned bit;
  unsigned prime_count;
  unsigned sieve_limit;
  unsigned block_size;
  unsigned block;

  struct output_info info;
  int quiet;
  int c;
  
  enum { FLAG_ODD = -100, FLAG_PRIME, FLAG_DIFF, FLAG_TABULAR, FLAG_BINARY,
	 FLAG_QUIET, FLAG_BLOCK };
  
  static const struct option options[] =
    {
      /* Name, args, flag, val */
      { "help", no_argument, NULL, '?' },
      { "quiet", no_argument, NULL, FLAG_QUIET },
      { "odd-only", no_argument, NULL, FLAG_ODD },
      { "prime-only", no_argument, NULL, FLAG_PRIME },
      { "diff-only", no_argument, NULL, FLAG_DIFF },
      { "tabular", no_argument, NULL, FLAG_TABULAR },
      { "binary", no_argument, NULL, FLAG_BINARY },
      { "block" , required_argument, NULL, FLAG_BLOCK },
      { NULL, 0, NULL, 0}
    };

  output_init(&info);

  quiet = 0;
  block_size = 0;
  
  while ( (c = getopt_long(argc, argv, "?", options, NULL)) != -1)
    switch (c)
      {
      case '?':
	usage();
	return EXIT_FAILURE;
      case FLAG_ODD:
	info.output_2 = 0;
	break;
      case FLAG_PRIME:
	info.format &= ~FORMAT_DIFF;
	break;
      case FLAG_DIFF:
	info.format &= ~FORMAT_PRIMES;
	break;
      case FLAG_TABULAR:
	info.format |= FORMAT_TABULAR;
	break;
      case FLAG_BINARY:
	info.format |= FORMAT_BINARY;
	break;
      case FLAG_QUIET:
	quiet = 1;
	break;
      case FLAG_BLOCK:
	{
	  int arg = atoi(optarg);
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

  output_first(&info);
  prime_count = 1;

  bit = 0;

  if (limit == 2)
    return EXIT_SUCCESS;

  sieve_limit = (isqrt(2*block_size + 1) - 1) / 2;
  
  while (bit < sieve_limit)
    {
      unsigned n = 3 + 2 * bit;
      
      output(&info, n);
      prime_count++;

      /* First bit to clear corresponds to n^2, which is bit

	 (n^2 - 3) / 2 = n * bit + 3 (bit + 1)
      */
      vector_clear_bits (vector, n, n*bit + 3*(bit + 1), block_size);

      bit = vector_find_next (vector, bit + 1, block_size);
    }

  /* No more marking, just output the remaining primes. */
  while (bit < block_size)
    {
      output(&info, 3 + 2 * bit);
      prime_count++;

      bit = vector_find_next (vector, bit + 1, size);
    }

  for (block = block_size; block < size; block += block_size)
    {
      unsigned block_start;
      unsigned block_end;

      if (block + block_size > size)
	/* For the final block */
	block_size = size - block;

      block_start = 2*block + 3;
      block_end = 2*(block + block_size) + 3;

      sieve_limit = (isqrt(block_end) - 1) / 2;
      for (bit = 0; bit < sieve_limit ;)
	{
	  unsigned n = 3 + 2 * bit;

	  unsigned start = n*bit + 3*(bit + 1);
	  if (start < block)
	    {
	      unsigned k = (block + 1) / n;
	      start = bit + k*n;
	    }
	  vector_clear_bits (vector, n, start, block + block_size);
	  
	  bit = vector_find_next (vector, bit + 1, block + block_size);
	}
      for (bit = vector_find_next (vector, block, block + block_size);
	   bit < block + block_size;
	   bit = vector_find_next (vector, bit + 1, block + block_size))
	{
	  output(&info, 3 + 2 * bit);
	  prime_count++;
	}
    }

  if (!quiet)
    {
      printf("\n");
      fprintf(stderr, "Prime #%d = %ld\n", prime_count, info.last);
    }

  return EXIT_SUCCESS;
}
