/* bf_test.c
 *
 * $Id$
 * Test the blow fish implementation. */

#include "blowfish.h"

#include <stdio.h>
#include <stdlib.h>

int main (int argc, char **argv)
{
  if (bf_selftest())
    {
      fprintf(stderr, "Blowfish works.\n");
      exit(EXIT_SUCCESS);
    }
  else
    {
      fprintf(stderr, "ERROR: Blowfish failed.\n");
      exit(EXIT_FAILURE);
    }
}

