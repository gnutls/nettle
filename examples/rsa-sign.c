/* rsa-sign.c
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

#if !HAVE_LIBGMP
int
main(int argc, char **argv)
{
  fprintf(stderr,
	  "You need to install GMP somewhere where Nettle can find it,\n"
	  "and recompile Nettle\n");
  return EXIT_FAILURE;
}
#endif /* !HAVE_LIBGMP */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include "rsa.h"

#define BUFSIZE 1000

static int
read_key(const char *name,
	 struct rsa_private_key *key)
{
  uint8_t buffer[BUFSIZE];
  unsigned done;

  int fd = open(name, O_RDONLY);
  if (fd < 0)
    {
      fprintf(stderr, "Failed to open `%s': %s\n",
	      name, strerror(errno));
      return 0;
    }

  for (done = 0; done < sizeof(buffer) ;)
    {
      int res = read(fd, buffer, sizeof(buffer) - done);
      if (!res)
	break;
      else if (res < 0 && errno == EINTR)
	continue;
      else if (res < 0)
	{
	  fprintf(stderr, "Failed reading `%s': %s\n",
		  name, strerror(errno));
	  return 0;
	}
      else
	done += res;
    }
  return rsa_keypair_from_sexp(NULL, key,
			       done, buffer);
}

int
main(int argc, char **argv)
{
  struct rsa_private_key key;
  struct sha1_ctx hash;
  mpz_t s;
  
  if (argc != 2)
    {
      fprintf(stderr, "Usage: rsa-sign PRIVATE-KEY < file\n");
      return EXIT_FAILURE;
    }

  rsa_init_private_key(&key);
  
  if (!read_key(argv[1], &key))
    {
      fprintf(stderr, "Invalid key\n");
      return EXIT_FAILURE;
    }

  sha1_init(&hash);
  for (;;)
    {
      uint8_t buffer[BUFSIZE];
      int res = read(STDIN_FILENO, buffer, sizeof(buffer));
      if (!res)
	/* EOF */
	break;
      else if (res < 0 && errno == EINTR)
	continue;
      else if (res < 0)
	{
	  fprintf(stderr, "Failed reading stdin: %s\n",
		  strerror(errno));
	  return 0;
	}
      else
	sha1_update(&hash, res, buffer);
    }

  mpz_init(s);
  rsa_sha1_sign(&key, &hash, s);

  if (!mpz_out_str(stdout, 16, s))
    {
      fprintf(stderr, "Failed writing signature: %s\n",
	      strerror(errno));
      return 0;
    }

  putchar('\n');
  
  mpz_clear(s);
  rsa_clear_private_key(&key);

  return EXIT_SUCCESS;
}
