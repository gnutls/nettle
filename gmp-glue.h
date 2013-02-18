/* gmp-glue.h */

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

#ifndef NETTLE_GMP_GLUE_H_INCLUDED
#define NETTLE_GMP_GLUE_H_INCLUDED

#include <gmp.h>

#include "nettle-stdint.h"

/* Name mangling. */
#define _mpz_cmp_limbs _nettle_mpz_cmp_limbs
#define _mpz_read_limbs _nettle_mpz_read_limbs
#define _mpz_read_limbs_n _nettle_mpz_read_limbs_n
#define _mpz_copy_limbs _nettle_mpz_copy_limbs
#define _mpz_write_limbs _nettle_mpz_write_limbs
#define _mpz_modify_limbs _nettle_mpz_modify_limbs
#define _mpz_done_limbs _nettle_mpz_done_limbs
#define _mpz_set_mpn _nettle_mpz_set_mpn
#define _mpz_init_mpn _nettle_mpz_init_mpn
#define _mpn_set_base256 _nettle_mpn_set_base256
#define _gmp_alloc_limbs _nettle_gmp_alloc_limbs
#define _gmp_free_limbs _nettle_gmp_free_limbs

/* Some functions for interfacing between mpz and mpn code. Signs of
   the mpz numbers are generally ignored. */

int
_mpz_cmp_limbs (mpz_srcptr a, const mp_limb_t *bp, mp_size_t bn);

/* Read access to mpz numbers. */

/* Return limb pointer, for read-only operations. Use mpz_size to get
   the number of limbs. */
const mp_limb_t *
_mpz_read_limbs (const mpz_srcptr x);

/* Get a pointer to an n limb area, for read-only operation. n must be
   greater or equal to the current size, and the mpz is zero-padded if
   needed. */
const mp_limb_t *
_mpz_read_limbs_n (mpz_ptr x, mp_size_t n);

/* Copy limbs, with zero-padding. */
/* FIXME: Reorder arguments, on the theory that the first argument of
   an _mpz_* fucntion should be an mpz_t? Or rename to _mpz_get_limbs,
   with argument order consistent with mpz_get_*. */
void
_mpz_copy_limbs (mp_limb_t *xp, mpz_srcptr x, mp_size_t n);

/* Write access to mpz numbers. */

/* Get a limb pointer for writing, previous contents may be
   destroyed. */
mp_limb_t *
_mpz_write_limbs (mpz_ptr x, mp_size_t n);

/* Get a limb pointer for writing, previous contents is intact. */
mp_limb_t *
_mpz_modify_limbs (mpz_ptr x, mp_size_t n);

/* Update size. */
void
_mpz_done_limbs (mpz_ptr x, mp_size_t n);

void
_mpz_set_mpn (mpz_t r, const mp_limb_t *xp, mp_size_t xn);

/* Using an mpn number as an mpz. Can be used for read-only access
   only. x must not be cleared or reallocated. */
mpz_srcptr
_mpz_init_mpn (mpz_ptr x, const mp_limb_t *xp, mp_size_t xs);

/* Like mpn_set_str, but always writes rn limbs. If input is larger,
   higher bits are ignored. */
void
_mpn_set_base256 (mp_limb_t *rp, mp_size_t rn,
		  const uint8_t *xp, size_t xn);


mp_limb_t *
_gmp_alloc_limbs (mp_size_t n);

void
_gmp_free_limbs (mp_limb_t *p, mp_size_t n);


#endif /* NETTLE_GMP_GLUE_H_INCLUDED */
