/* sexp.h
 *
 * Parsing s-expressions.
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
 
#ifndef NETTLE_SEXP_H_INCLUDED
#define NETTLE_SEXP_H_INCLUDED

#include <inttypes.h>

enum sexp_type
  { SEXP_START, SEXP_ATOM, SEXP_LIST, SEXP_END };

struct sexp_iterator
{
  unsigned length;
  const uint8_t *buffer;
  unsigned pos;
  unsigned level;

  enum sexp_type type;
  
  unsigned display_length;
  const uint8_t *display;

  unsigned atom_length;
  const uint8_t *atom;
};

struct sexp_assoc_key
{
  unsigned length;
  const uint8_t *name;
};

/* Initializes the iterator. You have to call next to get to the first
 * element. */
void
sexp_iterator_init(struct sexp_iterator *iterator,
		   unsigned length, const uint8_t *input);

/* All these functions return 1 on success, 0 on failure */
int
sexp_iterator_next(struct sexp_iterator *iterator);

/* Current element must be a list. */
int
sexp_iterator_enter_list(struct sexp_iterator *iterator);

/* Skips the rest of the current list */
int
sexp_iterator_exit_list(struct sexp_iterator *iterator);

/* Current element must be a list. Looks up element of type
 *
 *   (key rest...)
 *
 * For a matching key, the corersponding iterator is initialized
 * pointing at the start of REST.
 */
int
sexp_iterator_assoc(struct sexp_iterator *iterator,
		    unsigned nkeys,
		    const struct sexp_assoc_key *keys,
		    struct sexp_iterator *values);

#endif /* NETTLE_SEXP_H_INCLUDED */
