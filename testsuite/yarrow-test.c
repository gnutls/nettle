#include "yarrow.h"

#include "macros.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

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
get_event(unsigned *key, unsigned *time)
{
  static int t = 0;
  
  int c = getchar();
  if (c == EOF)
    return 0;

  *key = c;

  t += (ran_get() % 10000);
  *time = t;

  return 1;
}

int
main(int argc, char **argv)
{
  struct yarrow256_ctx yarrow;
  struct yarrow_key_event_ctx estimator;

  struct yarrow_source sources[2];

  unsigned c; unsigned t;
  unsigned processed;

  static const char zeroes[100];
  
  yarrow256_init(&yarrow, 2, sources);
  yarrow_key_event_init(&estimator);

  ran_test();

  ran_init(31416);

  /* Fake input to source 0 */
  yarrow256_update(&yarrow, 0, 200, sizeof(zeroes), zeroes);

  fprintf(stderr, "source 0 entropy: %d\n",
          sources[0].estimate[YARROW_SLOW]);

  fprintf(stderr, "seeded: %s\n", yarrow.seeded ? "yes": "no");
  
  while (get_event(&c, &t))
    {
      uint8_t buf[8];

      processed++;
      
      WRITE_UINT32(buf, c);
      WRITE_UINT32(buf + 4, t);
      yarrow256_update(&yarrow, 1,
                       yarrow_key_event_estimate(&estimator, c, t),
                       sizeof(buf), buf);

      if (yarrow.seeded)
        {
          static const unsigned sizes[4] = { 1, 16, 500, 37 };
          unsigned size = sizes[processed % 4];
          
          uint8_t buf[500];
          yarrow256_random(&yarrow, size, buf);

          fprintf(stderr, "%02x ", buf[0]);
          if (! (processed % 16))
            fprintf(stderr, "\n");
        }
    }

  fprintf(stderr, "\n\nseeded: %s\n", yarrow.seeded ? "yes": "no");
  
  fprintf(stderr, "source 0 entropy: %d\n",
          sources[0].estimate[YARROW_SLOW]);
  fprintf(stderr, "source 1 entropy: %d\n",
          sources[1].estimate[YARROW_SLOW]);
  
  return EXIT_SUCCESS;
}
