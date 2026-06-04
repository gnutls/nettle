/* sntrup-internal.h

   Copyright (C) 2023 Simon Josefsson
   Copyright (C) 2026 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

/*
 * Derived from public domain source, written by (in alphabetical order):
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#ifndef NETTLE_SNTRUP_INTERNAL_H
#define NETTLE_SNTRUP_INTERNAL_H

/* Name mangling */
#define _sntrup_hash_prefix _nettle_sntrup_hash_prefix
#define _sntrup_hash_session _nettle_sntrup_hash_session
#define _sntrup_hash_confirm _nettle_sntrup_hash_confirm
#define _sntrup_urandom32 _nettle_sntrup_urandom32
#define _sntrup_encode _nettle_sntrup_encode
#define _sntrup_decode _nettle_sntrup_decode
#define _sntrup_mod_3 _nettle_sntrup_mod_3
#define _sntrup761_mod_q _nettle_sntrup761_mod_q
#define _sntrup761_short_random _nettle__sntrup761_short_random
#define _sntrup761_small_encode _nettle_sntrup761_small_encode
#define _sntrup761_Rq_mult_small _nettle_sntrup761_Rq_mult_small
#define _sntrup761_encap_internal _nettle_sntrup761_encap_internal
#define _sntrup761_encoding_Rq _nettle_sntrup761_encoding_Rq
#define _sntrup761_encoding_rounded _nettle_sntrup761_encoding_rounded

/* Defines the coefficient field Z/q, with q = 1 (mod 6). */
#define SNTRUP761_Q 4591
/* Elements canonicalized to range |x| <= (q-1)/2 */
#define SNTRUP761_Q12 ((SNTRUP761_Q-1)/2)

/* Defines polynomial x^p - x - 1, irreducible over Z/q. */
#define SNTRUP761_P 761

/* Target polynomial weight. */
#define SNTRUP761_W 286

#define SNTRUP_HASH_SIZE 32

/* Octet size of an encoded R3 polynomial, 191. */
#define SNTRUP761_R3_SIZE ((SNTRUP761_P+3)/4)

/* Octet size of an encoded rounded polynomial, 1007. */
#define SNTRUP761_ROUNDED_SIZE (SNTRUP761_CIPHER_SIZE - SNTRUP_HASH_SIZE)

/* Return -1 if high bit set, otherwise zero. */
static inline int
uint16_highbit_mask (uint16_t x)
{
  return -(x >> 15);
}

/* Return -1 if non-zero, otherwise 0. */
static inline int
uint16_nonzero_mask (uint16_t x)
{
  return uint16_highbit_mask (x | -x);
}

void
_sntrup_hash_prefix (uint8_t *out, uint8_t b, size_t size, const uint8_t *in);

/* k = HashSession(b,y,z) */
void
_sntrup_hash_session (uint8_t *k, uint8_t b,
		      const uint8_t y[SNTRUP761_R3_SIZE],
		      const uint8_t z[SNTRUP761_CIPHER_SIZE]);

/* h = HashConfirm(r,pk,cache); cache is Hash4(pk) */
void
_sntrup_hash_confirm (uint8_t *h, const uint8_t r[SNTRUP761_R3_SIZE],
		      const uint8_t cache[SNTRUP_HASH_SIZE]);

uint32_t
_sntrup_urandom32 (void *random_ctx, nettle_random_func * random);

struct sntrup_encoding_step
{
  size_t len;
  uint16_t M0;
  uint16_t M1;
  uint32_t M0_inv;
  uint32_t M1_inv;
  unsigned char M0_count;
  unsigned char M1_count;
};

#define SNTRUP761_ENCODING_STEPS 10

extern struct sntrup_encoding_step
_sntrup761_encoding_Rq[SNTRUP761_ENCODING_STEPS];
extern struct sntrup_encoding_step
_sntrup761_encoding_rounded[SNTRUP761_ENCODING_STEPS];

void
_sntrup_encode (const struct sntrup_encoding_step *step, uint8_t *out, uint16_t * R);

void
_sntrup_decode (unsigned n, const struct sntrup_encoding_step *step,
		uint16_t *R, const uint8_t *S /* Must point at *end* of input. */);

int8_t
_sntrup_mod_3 (int16_t x);

int16_t
_sntrup761_mod_q (int32_t x);

/* Polynomial typedefs, passed by reference. */
/* Coefficients mod 3, canonically represented as -1, 0, 1. But this
   type may is also used with values outside of this range during
   decapsulation. */
typedef int8_t sntrup761_R3_t[SNTRUP761_P];

/* Coefficients mod q, represented as -(q-1)/2, ... , (q-1)/2. */
typedef int16_t sntrup761_Rq_t[SNTRUP761_P];

void
_sntrup761_short_random (sntrup761_R3_t out, void *random_ctx, nettle_random_func * random);

void
_sntrup761_small_encode (uint8_t *s, const sntrup761_R3_t f);

void
_sntrup761_Rq_mult_small (sntrup761_Rq_t h, const sntrup761_Rq_t f, const sntrup761_R3_t g);

void
_sntrup761_encap_internal (const uint8_t *pk, const uint8_t *cache,
			   uint8_t *r_enc, uint8_t *c,
			   const sntrup761_R3_t r);

#endif /* NETTLE_SNTRUP_INTERNAL_H */
