#include "yarrow.h"

#include "macros.h"
#include "testutils.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verbose = 0;

/* Lagged fibonacci sequence as described in Knuth 3.6 */

#define KK 100
#define LL 37
#define MM (1UL << 30)
#define TT 70

uint32_t ran_x[KK];
unsigned ran_index;

static void
ran_init(uint32_t seed)
{
  uint32_t t,j;
  uint32_t x[2*KK - 1];
  uint32_t ss = (seed + 2) & (MM-2);

  for (j = 0; j<KK; j++)
    {
      x[j] = ss;
      ss <<= 1;  if (ss >= MM) ss -= (MM-2);
    }
  for (;j< 2*KK-1; j++)
    x[j] = 0;

  x[1]++;

  ss = seed & (MM-1);
  for (t = TT-1; t; )
    {
      for (j = KK-1; j>0; j--)
        x[j+j] = x[j];
      for (j = 2*KK-2; j > KK-LL; j-= 2)
        x[2*KK-1-j] = x[j] & ~1;
      for (j = 2*KK-2; j>=KK; j--)
        if (x[j] & 1)
          {
            x[j-(KK-LL)] = (x[j - (KK-LL)] - x[j]) & (MM-1);
            x[j-KK] = (x[j-KK] - x[j]) & (MM-1);
          }
      if (ss & 1)
        {
          for (j=KK; j>0; j--)
            x[j] = x[j-1];
          x[0] = x[KK];
          if (x[KK] & 1)
            x[LL] = (x[LL] - x[KK]) & (MM-1);
        }
      if (ss)
        ss >>= 1;
      else
        t--;
    }
  for (j=0; j<LL; j++)
    ran_x[j+KK-LL] = x[j];
  for (; j<KK; j++)
    ran_x[j-LL] = x[j];

  ran_index = 0;
}

static uint32_t
ran_get(void)
{
  uint32_t value;
  assert(ran_index < KK);
  
  value = ran_x[ran_index];
  ran_x[ran_index] -= ran_x[(ran_index + KK - LL) % KK];
  ran_x[ran_index] &= (MM-1);
  
  ran_index = (ran_index + 1) % KK;

  return value;
}

static void
ran_array(uint32_t *a, unsigned n)
{
  unsigned i;
  
  for (i = 0; i<n; i++)
    a[i] = ran_get();
}

static void
ran_test(void)
{
  uint32_t a[2009];
  uint32_t x;
  
  unsigned m;
  
  ran_init(310952);
  for (m = 0; m<2009; m++)
    ran_array(a, 1009);

  x = ran_get();
  assert(x == 461390032);
}

static int
get_event(FILE *f, struct sha256_ctx *hash,
          unsigned *key, unsigned *time)
{
  static int t = 0;
  uint8_t buf[1];
  
  int c = getc(f);
  if (c == EOF)
    return 0;

  buf[0] = c;
  sha256_update(hash, sizeof(buf), buf);
    
  *key = c;

  t += (ran_get() % 10000);
  *time = t;

  return 1;
}

static void
print_hex(unsigned length, uint8_t *digest)
{
  unsigned i;
  
  for (i = 0; i < length; i++)
    {
      if (! (i % 8))
        printf(" ");
      printf("%02x", digest[i]);
    }
}

static FILE *
open_file(const char *name)
{
  /* Tries opening the file in $srcdir, if set, otherwise the current
   * working directory */

  const char *srcdir = getenv("srcdir");
  if (srcdir && srcdir[0])
    {
      char *buf = alloca(strlen(name) + strlen(srcdir) + 10);
      sprintf(buf, "%s/%s", srcdir, name);
      name = buf;
    }

  /* Opens the file in text mode. */
  return fopen(name, "r");
}

int
main(int argc, char **argv)
{
  FILE *input;
  
  struct yarrow256_ctx yarrow;
  struct yarrow_key_event_ctx estimator;

  struct yarrow_source sources[2];

  struct sha256_ctx output_hash;
  struct sha256_ctx input_hash;
  uint8_t digest[SHA256_DIGEST_SIZE];

  const uint8_t *expected_output
    = decode_hex_dup("06ca66b204a92939 e75e09e11922153e"
		     "a2391000e0686da4 c7d27afb37a4630f");

  const uint8_t *expected_input
    = decode_hex_dup("fec4c0767434a8a3 22d6d5d0c9f49c42"
		     "988ce8c159b1a806 29d51aa40c2e99aa");

  const uint8_t *expected_seed_file
    = decode_hex_dup("87213a8a863a91f9 0e776c01e0d7c3a8"
		     "6b2ecf9977b06da5 34f3df8375918ac9");
  
  unsigned c; unsigned t;

  unsigned processed = 0;
  unsigned output = 0;

  unsigned i;
  
  static const char zeroes[100];

  if ((argc == 2)
      && (argv[1][0] == '-')
      && (argv[1][1] == 'v'))
    verbose = 1;
  
  yarrow256_init(&yarrow, 2, sources);
  memset(&yarrow.seed_file, 0, sizeof(yarrow.seed_file));
  
  yarrow_key_event_init(&estimator);
  sha256_init(&input_hash);
  sha256_init(&output_hash);

  ran_test();

  ran_init(31416);

  /* Fake input to source 0 */
  yarrow256_update(&yarrow, 0, 200, sizeof(zeroes), zeroes);

  if (verbose)
    printf("source 0 entropy: %d\n",
	   sources[0].estimate[YARROW_SLOW]);
  
  assert(!yarrow256_is_seeded(&yarrow));

  input = open_file("rfc1750.txt");

  if (!input)
    {
      fprintf(stderr, "Couldn't open `rfc1750.txt', errno = %d\n",
              errno);
      return EXIT_FAILURE;
    }
  
  while (get_event(input, &input_hash, &c, &t))
    {
      uint8_t buf[8];

      processed++;
      
      WRITE_UINT32(buf, c);
      WRITE_UINT32(buf + 4, t);
      yarrow256_update(&yarrow, 1,
                       yarrow_key_event_estimate(&estimator, c, t),
                       sizeof(buf), buf);

      if (yarrow256_is_seeded(&yarrow))
        {
          static const unsigned sizes[4] = { 1, 16, 500, 37 };
          unsigned size = sizes[processed % 4];
          
          uint8_t buf[500];

          if (verbose && !output)
            printf("Generator was seeded after %d events\n",
		   processed);
          
          yarrow256_random(&yarrow, size, buf);

          sha256_update(&output_hash, size, buf);

	  if (verbose)
	    {
	      printf("%02x ", buf[0]);
	      if (! (processed % 16))
		printf("\n");
	    }
          output += size;
        }
    }

  if (verbose)
    {
      printf("\n");
      
      for (i = 0; i<2; i++)
	printf("source %d, (fast, slow) entropy: (%d, %d)\n",
	       i,
	       sources[i].estimate[YARROW_FAST],
	       sources[i].estimate[YARROW_SLOW]); 
      
      printf("Processed input: %d octets\n", processed);
      printf("         sha256:");
    }

  sha256_digest(&input_hash, sizeof(digest), digest);

  if (verbose)
    {
      print_hex(sizeof(digest), digest);
      printf("\n");
    }
  
  if (memcmp(digest, expected_input, sizeof(digest)))
    {
      fprintf(stderr, "Failed.\n");
      return EXIT_FAILURE;
    }

  if (verbose)
    {
      printf("New seed file: ");
      print_hex(sizeof(yarrow.seed_file), yarrow.seed_file);
      printf("\n");
    }

  if (memcmp(yarrow.seed_file, expected_seed_file, sizeof(yarrow.seed_file)))
    {
      fprintf(stderr, "Failed.\n");
      return EXIT_FAILURE;
    }
  
  if (verbose)
    {
      printf("Generated output: %d octets\n", output);
      printf("          sha256:");
    }
  
  sha256_digest(&output_hash, sizeof(digest), digest);

  if (verbose)
    {
      print_hex(sizeof(digest), digest);
      printf("\n");
    }
  
  if (memcmp(digest, expected_output, sizeof(digest)))
    {
      fprintf(stderr, "Failed.\n");
      return EXIT_FAILURE;
    }
  
  return EXIT_SUCCESS;
}
