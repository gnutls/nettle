/* rsa-keygen.c
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

/* For asprintf */
#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "buffer.h"
#include "rsa.h"
#include "sexp.h"
#include "yarrow.h"

#define KEYSIZE 500
#define ESIZE 30

#define RANDOM_DEVICE "/dev/urandom"

static void
progress(void *ctx, int c)
{
  (void) ctx;
  fputc(c, stderr);
}

static int
write_file(const char *name, struct nettle_buffer *buffer)
{
  const uint8_t *data = buffer->contents;
  unsigned length = buffer->size;
  int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  
  if (fd < 0)
    return 0;

  while (length)
    {
      int res = write(fd, data, length);
      if (res < 0)
	{
	  if (errno == EINTR)
	    continue;
	  else
	    return 0;
	}
      data += res;
      length -= res;
    }

  return 1;
}

int
main(int argc, char **argv)
{
  struct yarrow256_ctx yarrow;
  struct rsa_public_key pub;
  struct rsa_private_key priv;
  char buf[16];
  int fd;

  int c;
  char *pub_name = NULL;
  char *priv_name = NULL;
  struct stat sbuf;
  
  struct nettle_buffer pub_buffer;
  struct nettle_buffer priv_buffer;

  while ( (c = getopt(argc, argv, "o:")) != -1)
    switch (c)
      {
      case 'o':
	priv_name = optarg;
	break;
      case '?':
	if (isprint (optopt))
	  fprintf(stderr, "Unknown option `-%c'.\n", optopt);
	else
	  fprintf(stderr, "Unknown option character `\\x%x'.\n",
		  optopt);
	return EXIT_FAILURE;
      default:
	abort();
      }

  if (!priv_name)
    {
      fprintf(stderr, "No filename provided.\n");
      return EXIT_FAILURE;
    }

  if (stat(priv_name, &sbuf) == 0)
    {
      fprintf(stderr, "The output file `%s' already exists.\n", priv_name);
      return EXIT_FAILURE;
    }

  asprintf(&pub_name, "%s.pub", priv_name);
  if (!pub_name)
    {
      fprintf(stderr, "Memory exhausted.\n");
      return EXIT_FAILURE;
    }
  
  if (stat(pub_name, &sbuf) == 0)
    {
      fprintf(stderr, "The output file `%s' already exists.\n", pub_name);
      return EXIT_FAILURE;
    }
    
  /* Read some data to seed the generator */
  if ( ( (fd = open(RANDOM_DEVICE, O_RDONLY)) < 0)
       || (sizeof(buf) != read(fd, buf, sizeof(buf))))
    {
      fprintf(stderr, "Failed to open `%s': %s\n",
	      RANDOM_DEVICE, strerror(errno));
      return EXIT_FAILURE;
    }
  
  /* NOTE: No sources */
  yarrow256_init(&yarrow, 0, NULL);
  yarrow256_seed(&yarrow, sizeof(buf), buf);
  
  rsa_init_public_key(&pub);
  rsa_init_private_key(&priv);

  if (!rsa_generate_keypair
      (&pub, &priv,
       (void *) &yarrow, (nettle_random_func) yarrow256_random,
       NULL, progress,
       KEYSIZE, ESIZE))
    {
      fprintf(stderr, "Key generation failed.\n");
      return EXIT_FAILURE;
    }

  nettle_buffer_init(&priv_buffer);
  nettle_buffer_init(&pub_buffer);
  
  if (!rsa_keypair_to_sexp(&pub_buffer, &pub, NULL))
    {
      fprintf(stderr, "Formatting public key failed.\n");
      return EXIT_FAILURE;
    }

  if (!rsa_keypair_to_sexp(&pub_buffer, &pub, &priv))
    {
      fprintf(stderr, "Formatting private key failed.\n");
      return EXIT_FAILURE;
    }
  
  if (!write_file(pub_name, &pub_buffer))
    {
      fprintf(stderr, "Failed to write public key: %s\n",
	      strerror(errno));
      return EXIT_FAILURE;
    }

  if (!write_file(priv_name, &priv_buffer))
    {
      fprintf(stderr, "Failed to write private key: %s\n",
	      strerror(errno));
      return EXIT_FAILURE;
    }

  return EXIT_SUCCESS;
}
