/* next-prime.c
 *
 * Command line tool for prime search.
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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "bignum.h"

#include "getopt.h"

static void
usage(void)
{
  fprintf(stderr, "Usage: next-prime [OPTIONS] number\n\n"
	  "Options:\n"
	  "      --help         Display this message.\n"
	  "  -v, --verbose      Display timing information.\n"
	  "      --factorial    Use factorial of input number.\n"
	  "  -s  --sieve-limit  Number of primes to use for sieving.\n");
}

/* For timing */
struct timing {
  clock_t start;
  clock_t sieve_start;
  clock_t sieve_time;
  clock_t fermat_start;
  clock_t fermat_time;
  unsigned fermat_count;
  clock_t miller_start;
  clock_t miller_time;
  unsigned miller_count;
  clock_t end;
};

static void
progress(void *ctx, int c)
{
  struct timing *timing = (struct timing *) ctx;
  clock_t now = clock();
  switch (c)
    {
    case '.':
      timing->sieve_time += (now - timing->sieve_start);
      timing->fermat_count++;
      timing->fermat_start = now;
      break;
    case ',':
      timing->sieve_start = now;
      timing->fermat_time += (now - timing->fermat_start);
      break;
    case '+':
      timing->fermat_time += (now - timing->fermat_start);
      timing->miller_count++;
      timing->miller_start = now;
      break;
    case '*':
      timing->sieve_start = now;
      timing->miller_time += (now - timing->miller_start);
      break;
      
    default:
      abort();
    }
}

int
main(int argc, char **argv)
{
  mpz_t n;
  mpz_t p;

  int c;
  int verbose = 0;  
  int factorial = 0;
  int prime_limit = 200;

  struct timing timing;

  enum { OPT_FACTORIAL = -100, OPT_RANDOM };
  static const struct option options[] =
    {
      /* Name, args, flag, val */
      { "help", no_argument, NULL, '?' },
      { "verbose", no_argument, NULL, 'v' },
      { "factorial", no_argument, NULL, 'f' },
      { "sieve-limit", required_argument, NULL, 's' },
      { NULL, 0, NULL, 0}
    };

  while ( (c = getopt_long(argc, argv, "v?s:", options, NULL)) != -1)
    switch (c)
      {
      case 'v':
	verbose = 1;
	break;
      case '?':
	usage();
	return EXIT_FAILURE;
      case 'f':
	factorial = 1;
	break;
      case 's':
	prime_limit = atoi(optarg);
	if (prime_limit < 0)
	  {
	    usage();
	    return EXIT_FAILURE;
	  }
	break;
      default:
	abort();
	
      }

  argc -= optind;
  argv += optind;

  if (argc != 1)
    usage();

  mpz_init(n);

  if (factorial)
    {
      long arg;
      char *end;
      arg = strtol(argv[0], &end, 0);
      if (*end || arg < 0)
	{
	  fprintf(stderr, "Invalid number.\n");
	  return EXIT_FAILURE;
	}
      mpz_fac_ui(n, arg);
    }
  else if (mpz_set_str(n, argv[0], 0))
    {
      fprintf(stderr, "Invalid number.\n");
      return EXIT_FAILURE;
    }

  if (mpz_cmp_ui(n, 2) <= 0)
    {
      printf("2\n");
      return EXIT_SUCCESS;
    }

  mpz_init(p);

  timing.fermat_count = timing.miller_count = 0;
  timing.sieve_time = timing.fermat_time = timing.miller_time = 0;
  timing.start = timing.sieve_start = clock();
  nettle_next_prime(p, n, 25, prime_limit, &timing, verbose ? progress : NULL);
  timing.end = clock();
  
  mpz_out_str(stdout, 10, p);
  printf("\n");

  if (verbose)
    {
      mpz_t d;
      
      mpz_init(d);
      mpz_sub(d, p, n);

      timing.miller_time += (timing.end - timing.miller_start);

      gmp_fprintf(stderr, "bit size: %lu, diff: %Zd, total time: %.3g s\n",
		  mpz_sizeinbase(p, 2), d,
		  (double)(timing.end - timing.start) / CLOCKS_PER_SEC);

      fprintf(stderr, "sieve time = %.3g s\n",
	      (double)(timing.sieve_time) / CLOCKS_PER_SEC);
      fprintf(stderr, "fermat count: %d, time: %.3g s\n",
	      timing.fermat_count, (double)(timing.fermat_time) / CLOCKS_PER_SEC);
      fprintf(stderr, "miller count: %d, time: %.3g s\n",
	      timing.miller_count, (double)(timing.miller_time) / CLOCKS_PER_SEC);
    }
  return EXIT_SUCCESS;
}
