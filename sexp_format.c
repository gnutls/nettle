/* sexp-output.c
 *
 * Writing s-expressions.
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
#include "config.h"
#endif

#include "sexp.h"
#include "buffer.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if HAVE_LIBGMP
# include "bignum.h"
#endif

static int
format_prefix(struct nettle_buffer *output,
	      unsigned length)
{
  unsigned prefix_length;
  char prefix[10];

  /* NOTE: Using the return value of sprintf is not entirely
   * portable. */
  prefix_length = snprintf(prefix, sizeof(prefix), "%u:", length);
  if (prefix_length >= sizeof(prefix))
    return 0;

  return nettle_buffer_write(buffer, prefix_length, prefix);
}

static int
format_length_string(struct nettle_buffer *buffer,
		     unsigned length, const char *s)
{
  return format_prefix(buffer, length)
    && nettle_buffer_write(buffer, length, s);
}

static uint8_t *
format_space(struct nettle_buffer *buffer,
	     unsigned length)
{
  return format_prefix(output, length)
    ? nettle_buffer_space(output, length) : NULL;
}

static int
format_string(struct nettle_buffer *buffer,
	      const char *s)
{
  return format_length_string(buffer, strlen(s), s);
}

int
sexp_format(struct nettle_buffer *buffer, const char *format, ...)
{
  va_list args;
  va_start(args, format);

  unsigned nesting = 0;
  
  for (;;)
    switch (*format++)
      {
      case '\0':
	if (nesting)
	  {
	  fail:
	    va_end(args);
	    return 0;
	  }
	else
	  {
	    va_end(args);
	    return 1;
	  }
      case '(':
	if (!NETTLE_BUFFER_PUTC(buffer, '('))
	  goto fail;

	nesting++;
	break;

      case ')':
	if (!nesting)
	  abort();
	if (!NETTLE_BUFFER_PUTC(buffer, ')'))
	  goto fail;
	
	nesting--;
	break;

      case '%':
	switch (*format++)
	  {
	  case 's':
	    {
	      const char *s = va_arg(args, const char *);
	      format_string(buffer, s);
	      break;
	    }
	  case 'b':
	    {
#if HAVE_LIBGMP
	      const MP_INT *n = va_arg(args, const MP_INT *);
	      uint8_t *space;
	      unsigned length;
	      
	      if (mpz_sgn(n) < 0)
		goto fail;

	      length = nettle_mpz_sizeinbase_256(n);

	      space = format_space(buffer, length);
	      if (!space)
		goto fail;
	      nettle_mpz_get_str_256(length, space, n);
#else /* ! HAVE_LIBGMP */
	      abort();
#endif /* ! HAVE_LIBGMP */
	      break;
	    }
	  default:
	    abort();
	  }
      }
}
