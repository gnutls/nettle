/* testutils.c */

#include "testutils.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

int
decode_hex(uint8_t *dst, const char *hex)
{  
  /* -1 means invalid */
  const signed char hex_digits[0x100] =
  {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  };
  unsigned i = 0;
    
  for (;;)
  {
    int high, low;
    
    while (*hex && isspace((unsigned)*hex))
      hex++;

    if (!*hex)
      return 1;

    high = hex_digits[(unsigned)*hex++];
    if (high < 0)
      return 0;

    while (*hex && isspace((unsigned)*hex))
      hex++;

    if (!*hex)
      return 0;

    low = hex_digits[(unsigned)*hex++];
    if (low < 0)
      return 0;

    dst[i++] = (high << 4) | low;
  }
}

const uint8_t *
decode_hex_dup(const char *hex)
{
  uint8_t *p;
  unsigned length = strlen(hex);

  /* Allocates a little more than necessary. */
  p = malloc(length/2);
  if (!p)
    abort();

  if (decode_hex(p, hex))
    return p;
  else
    {
      free(p);
      return NULL;
    }
}
