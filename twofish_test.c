/* twofish_test.c
 *
 * $Id$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "twofish.h"

#include <stdio.h>
#include <stdlib.h>

int main (int argc UNUSED, char **argv UNUSED)
{
  if (twofish_selftest())
    {
      fprintf(stderr, "Twofish works.\n");
      return EXIT_SUCCESS;
    }
  else
    {
      fprintf(stderr, "ERROR: Twofish failed.\n");
      return EXIT_FAILURE;
    }
}
