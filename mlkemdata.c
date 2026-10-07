#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define Q 3329
#define Z 17

static unsigned
bitrev_7 (unsigned i)
{
  unsigned j, r;
  for (j = r = 0; j < 7; j++, i>>=1)
    r = (r << 1) | (i & 1);
  return r;
}

static void
powertable (void)
{
  unsigned table[128];
  unsigned x, i;
  for (x = 1, i = 0; i < 128; i++, x = (x*Z) % Q)
    table[i] = x;
  printf ("static const uint16_t zeta_pow_table[128] = {");
  for (i = 0; i < 128; i++)
    {
      if (!(i % 8))
	printf("\n ");
      printf (" 0x%04x,", table[bitrev_7(i)]);
    }
  printf ("\n};\n");

  printf ("static const uint16_t zeta_pow_table2[128] = {");
  for (i = 0; i < 128; i++)
    {
      if (!(i % 8))
	printf("\n ");
      x = table[bitrev_7(i)];
      printf (" 0x%04x,", (x*x*Z) % Q);
    }
  printf ("\n};\n");
}

static uint16_t
reduce (uint32_t u)
{
  uint32_t q, r, p;
  q = ((uint32_t) 315 * u) >> 20;
  p = q * Q;
  r = u - p; /* Interpreted as two's complement, |r| < Q */
  r += ((r >> 16) & Q);
  return r;
}

static void
test_reduce (void)
{
  unsigned u;
  for (u = 0; u <= 13634816; u++)
    {
      unsigned ref = u % Q;
      unsigned r = reduce (u);
      if (r != ref)
	{
	  fprintf (stderr, "reduce failed for u = %d, got %d, ref %d\n",
		   u, r, ref);
	  exit (EXIT_FAILURE);
	}
    }
}

int
main (void)
{
  test_reduce ();
  powertable ();
  return EXIT_SUCCESS;
}
