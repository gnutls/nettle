/* rsa-verify.c
 *
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2002 Niels Möller
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
#endif /* HAVE_CONFIG_H */

#if !WITH_PUBLIC_KEY
int
main(int argc, char **argv)
{
  fprintf(stderr,
	  "You need to install GMP somewhere where Nettle can find it,\n"
	  "and recompile Nettle\n");
  return EXIT_FAILURE;
}
#else /* WITH_PUBLIC_KEY */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rsa.h"
#include "io.h"

static int
read_signature(const char *name, mpz_t s)
{
  char *buffer;
  unsigned length;
  int res;
  
  length = read_file(name, 0, &buffer);
  if (!length)
    return 0;

  res = (mpz_set_str(s, buffer, 16) == 0);
  free(buffer);

  return res;
}

int
main(int argc, char **argv)
{
  struct rsa_public_key key;
  struct sha1_ctx hash;
  mpz_t s;
  
  if (argc != 3)
    {
      fprintf(stderr, "Usage: rsa-sign PUBLIC-KEY SIGNATURE-FILE < file\n");
      return EXIT_FAILURE;
    }

  rsa_init_public_key(&key);
  
  if (!read_rsa_key(argv[1], &key, NULL))
    {
      fprintf(stderr, "Invalid key\n");
      return EXIT_FAILURE;
    }

  mpz_init(s);

  if (!read_signature(argv[2], s))
    {
      fprintf(stderr, "Failed to read signature file `%s'\n",
	      argv[2]);
      return EXIT_FAILURE;
    }
  
  sha1_init(&hash);
  if (!hash_file(&nettle_sha1, &hash, stdin))
    {
      fprintf(stderr, "Failed reading stdin: %s\n",
	      strerror(errno));
      return 0;
    }

  if (!rsa_sha1_verify(&key, &hash, s))
    {
      fprintf(stderr, "Invalid signature!\n");
      return EXIT_FAILURE;
    }
    
  mpz_clear(s);
  rsa_clear_public_key(&key);

  return EXIT_SUCCESS;
}
#endif /* WITH_PUBLIC_KEY */
