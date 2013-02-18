/* gmp-glue.c */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2013 Niels Möller
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
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>

#include "gmp-glue.h"

/* This implementation tries to make a minimal use of GMP internals.
   We access and _mp_size and _mp_d, but not _mp_alloc. */

/* Use macros compatible with gmp-impl.h. */
#define ABS(x) ((x) >= 0 ? (x) : -(x))
#define PTR(x) ((x)->_mp_d)
#define SIZ(x) ((x)->_mp_size)
#define ABSIZ(x) ABS (SIZ (x))

#define MPN_NORMALIZE(xp, xn) do {		\
    while ( (xn) > 0 && (xp)[xn-1] == 0)	\
      (xn)--;					\
  }  while (0)

/* NOTE: Makes an unnecessary realloc if allocation is already large
   enough, but looking at _mp_alloc may break in future GMP
   versions. */
#define MPZ_REALLOC(x, n) \
  (ABSIZ(x) >= (n) ? PTR(x) : (_mpz_realloc ((x),(n)), PTR (x)))

#define MPZ_NEWALLOC MPZ_REALLOC

int
_mpz_cmp_limbs (mpz_srcptr a, const mp_limb_t *bp, mp_size_t bn)
{
  mp_size_t an = SIZ (a);
  if (an < bn)
    return -1;
  if (an > bn)
    return 1;
  if (an == 0)
    return 0;

  return mpn_cmp (PTR(a), bp, an);
}


/* Read access to mpz numbers. */

/* Return limb pointer, for read-only operations. Use mpz_size to get
   the number of limbs. */
const mp_limb_t *
_mpz_read_limbs (mpz_srcptr x)
{
  return PTR (x);
}

/* Get a pointer to an n limb area, for read-only operation. n must be
   greater or equal to the current size, and the mpz is zero-padded if
   needed. */
const mp_limb_t *
_mpz_read_limbs_n (mpz_ptr x, mp_size_t n)
{
  mp_size_t xn = ABSIZ (x);

  assert (xn <= n);

  if (xn < n)
    {
      /* Makes an unnecessary realloc if allocation is already large
	 enough. */
      mpz_realloc (x, n);
      mpn_zero (PTR(x) + xn, n - xn);
    }

  return PTR(x);
}

void
_mpz_copy_limbs (mp_limb_t *xp, mpz_srcptr x, mp_size_t n)
{
  mp_size_t xn = ABSIZ (x);

  assert (xn <= n);
  mpn_copyi (xp, PTR(x), xn);
  if (xn < n)
    mpn_zero (xp + xn, n - xn);
}

/* Write access to mpz numbers. */

/* Get a limb pointer for writing, previous contents may be
   destroyed. */
mp_limb_t *
_mpz_write_limbs (mpz_ptr x, mp_size_t n)
{
  assert (n > 0);
  return MPZ_NEWALLOC (x, n);
}

/* Get a limb pointer for writing, previous contents is intact. */
mp_limb_t *
_mpz_modify_limbs (mpz_ptr x, mp_size_t n)
{
  assert (n > 0);
  return MPZ_REALLOC (x, n);
}

void
_mpz_done_limbs (mpz_ptr x, mp_size_t n)
{
  assert (n >= 0);
  MPN_NORMALIZE (PTR(x), n);

  SIZ (x) = n;
}

void
_mpz_set_mpn (mpz_t r, const mp_limb_t *xp, mp_size_t xn)
{
  mpn_copyi (_mpz_write_limbs (r, xn), xp, xn);
  _mpz_done_limbs (r, xn);
}

/* Needs some ugly casts. */
mpz_srcptr
_mpz_init_mpn (mpz_ptr x, const mp_limb_t *xp, mp_size_t xs)
{
  mp_size_t xn = ABS (xs);
  
  MPN_NORMALIZE (xp, xn);

  x->_mp_size = xs < 0 ? -xn : xn;
  x->_mp_alloc = 0;
  x->_mp_d = (mp_limb_t *) xp;
  return x;
}

void
_mpn_set_base256 (mp_limb_t *rp, mp_size_t rn,
		 const uint8_t *xp, size_t xn)
{
  size_t xi;
  mp_limb_t out;
  unsigned bits;
  for (xi = xn, out = bits = 0; xi > 0 && rn > 0; )
    {
      mp_limb_t in = xp[--xi];
      out |= (in << bits) & GMP_NUMB_MASK;
      bits += 8;
      if (bits >= GMP_NUMB_BITS)
	{
	  *rp++ = out;
	  rn--;

	  bits -= GMP_NUMB_BITS;
	  out = in >> (8 - bits);
	}
    }
  if (rn > 0)
    {
      *rp++ = out;
      if (--rn > 0)
	mpn_zero (rp, rn);
    }
}

mp_limb_t *
_gmp_alloc_limbs (mp_size_t n)
{

  void *(*alloc_func)(size_t);

  assert (n > 0);

  mp_get_memory_functions (&alloc_func, NULL, NULL);
  return (mp_limb_t *) alloc_func ( (size_t) n * sizeof(mp_limb_t));
}

void
_gmp_free_limbs (mp_limb_t *p, mp_size_t n)
{
  void (*free_func)(void *, size_t);
  assert (n > 0);
  assert (p != 0);
  mp_get_memory_functions (NULL, NULL, &free_func);

  free_func (p, (size_t) n * sizeof(mp_limb_t));
}
