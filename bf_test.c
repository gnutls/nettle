/* bf_test.c
 *
 * $Id$
 * Test the blow fish implementation. */

#include "blowfish.h"

#include <stdio.h>
#include <stdlib.h>

int main (int argc UNUSED, char **argv UNUSED)
{
  if (bf_selftest())
    {
      fprintf(stderr, "Blowfish works.\n");
      return EXIT_SUCCESS;
    }
  else
    {
      fprintf(stderr, "ERROR: Blowfish failed.\n");
      return EXIT_FAILURE;
    }
}

