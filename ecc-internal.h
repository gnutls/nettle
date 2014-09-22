/* ecc-internal.h

   Copyright (C) 2013, 2014 Niels Möller

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

/* Development of Nettle's ECC support was funded by the .SE Internet Fund. */

#ifndef NETTLE_ECC_INTERNAL_H_INCLUDED
#define NETTLE_ECC_INTERNAL_H_INCLUDED

#include "nettle-types.h"
#include "bignum.h"
#include "ecc-curve.h"
#include "gmp-glue.h"

/* Name mangling */
#define ecc_pp1_redc _nettle_ecc_pp1_redc
#define ecc_pm1_redc _nettle_ecc_pm1_redc
#define ecc_modp_add _nettle_ecc_modp_add
#define ecc_modp_sub _nettle_ecc_modp_sub
#define ecc_modp_mul_1 _nettle_ecc_modp_mul_1
#define ecc_modp_addmul_1 _nettle_ecc_modp_addmul_1
#define ecc_modp_submul_1 _nettle_ecc_modp_submul_1
#define ecc_modp_mul _nettle_ecc_modp_mul
#define ecc_modp_sqr _nettle_ecc_modp_sqr
#define ecc_modp_inv _nettle_ecc_modp_inv
#define ecc_modq_mul _nettle_ecc_modq_mul
#define ecc_modq_add _nettle_ecc_modq_add
#define ecc_modq_inv _nettle_ecc_modq_inv
#define ecc_modq_random _nettle_ecc_modq_random
#define ecc_mod _nettle_ecc_mod
#define ecc_hash _nettle_ecc_hash
#define cnd_copy _nettle_cnd_copy
#define sec_add_1 _nettle_sec_add_1
#define sec_sub_1 _nettle_sec_sub_1
#define sec_tabselect _nettle_sec_tabselect
#define sec_modinv _nettle_sec_modinv
#define ecc_25519_sqrt _nettle_ecc_25519_sqrt
#define curve25519_eh_to_x _nettle_curve25519_eh_to_x

#define ECC_MAX_SIZE ((521 + GMP_NUMB_BITS - 1) / GMP_NUMB_BITS)

/* Window size for ecc_mul_a. Using 4 bits seems like a good choice,
   for both Intel x86_64 and ARM Cortex A9. For the larger curves, of
   384 and 521 bits, we could improve speed by a few percent if we go
   up to 5 bits, but I don't think that's worth doubling the
   storage. */
#define ECC_MUL_A_WBITS 4
/* And for ecc_mul_a_eh */
#define ECC_MUL_A_EH_WBITS 4

struct ecc_modulo
{
  unsigned short bit_size;
  unsigned short size;
  unsigned short B_size;
  unsigned short redc_size;

  const mp_limb_t *m;
  /* B^size mod m. Expected to have at least 32 leading zeros
     (equality for secp_256r1). */
  const mp_limb_t *B;
  /* 2^{bit_size} - p, same value as above, but shifted. */
  const mp_limb_t *B_shifted;
  /* m +/- 1, for redc, excluding redc_size low limbs. */
  const mp_limb_t *redc_mpm1;
};

/* Reduces from 2*ecc->size to ecc->size. */
/* Required to return a result < 2q. This property is inherited by
   modp_mul and modp_sqr. */
typedef void ecc_mod_func (const struct ecc_modulo *m, mp_limb_t *rp);

typedef void ecc_add_func (const struct ecc_curve *ecc,
			   mp_limb_t *r,
			   const mp_limb_t *p, const mp_limb_t *q,
			   mp_limb_t *scratch);

typedef void ecc_mul_g_func (const struct ecc_curve *ecc, mp_limb_t *r,
			     const mp_limb_t *np, mp_limb_t *scratch);

typedef void ecc_mul_func (const struct ecc_curve *ecc,
			   mp_limb_t *r,
			   const mp_limb_t *np, const mp_limb_t *p,
			   mp_limb_t *scratch);

typedef void ecc_h_to_a_func (const struct ecc_curve *ecc,
			      int flags,
			      mp_limb_t *r, const mp_limb_t *p,
			      mp_limb_t *scratch);

/* Represents an elliptic curve of the form

     y^2 = x^3 - 3x + b (mod p)
*/
struct ecc_curve
{
  /* The prime p. */
  struct ecc_modulo p;
  /* Group order. FIXME: Currently, many fucntions rely on q.size ==
     p.size. This has to change for radix-51 implementation of
     curve25519 mod p arithmetic. */
  struct ecc_modulo q;

  unsigned short use_redc;
  unsigned short pippenger_k;
  unsigned short pippenger_c;

  unsigned short add_hhh_itch;
  unsigned short mul_itch;
  unsigned short mul_g_itch;
  unsigned short h_to_a_itch;

  ecc_mod_func *modp;
  ecc_mod_func *redc;
  ecc_mod_func *reduce;
  ecc_mod_func *modq;

  ecc_add_func *add_hhh;
  ecc_mul_func *mul;
  ecc_mul_g_func *mul_g;
  ecc_h_to_a_func *h_to_a;

  /* Curve constant */
  const mp_limb_t *b;
  /* Generator, x coordinate followed by y (affine coordinates).
     Currently used only by the test suite. */
  const mp_limb_t *g;
  /* If non-NULL, the constant needed for transformation to the
     equivalent Edwards curve. */
  const mp_limb_t *edwards_root;

  /* (p+1)/2 */
  const mp_limb_t *pp1h;
  /* For redc, same as Bmodp, otherwise 1. */
  const mp_limb_t *unit;

  /* (q+1)/2 */
  const mp_limb_t *qp1h;
  
  /* Tables for multiplying by the generator, size determined by k and
     c. The first 2^c entries are defined by

       T[  j_0 +   j_1 2 +     ... + j_{c-1} 2^{c-1} ]
         = j_0 g + j_1 2^k g + ... + j_{c-1} 2^{k(c-1)} g

     The following entries differ by powers of 2^{kc},

       T[i] = 2^{kc} T[i-2^c]
  */  
  const mp_limb_t *pippenger_table;
};

/* In-place reduction. */
ecc_mod_func ecc_mod;
ecc_mod_func ecc_pp1_redc;
ecc_mod_func ecc_pm1_redc;

void
ecc_modp_add (const struct ecc_curve *ecc, mp_limb_t *rp,
	      const mp_limb_t *ap, const mp_limb_t *bp);
void
ecc_modp_sub (const struct ecc_curve *ecc, mp_limb_t *rp,
	      const mp_limb_t *ap, const mp_limb_t *bp);

void
ecc_modp_mul_1 (const struct ecc_curve *ecc, mp_limb_t *rp,
		const mp_limb_t *ap, const mp_limb_t b);

void
ecc_modp_addmul_1 (const struct ecc_curve *ecc, mp_limb_t *rp,
		   const mp_limb_t *ap, mp_limb_t b);
void
ecc_modp_submul_1 (const struct ecc_curve *ecc, mp_limb_t *rp,
		   const mp_limb_t *ap, mp_limb_t b);

/* NOTE: mul and sqr needs 2*ecc->size limbs at rp */
void
ecc_modp_mul (const struct ecc_curve *ecc, mp_limb_t *rp,
	      const mp_limb_t *ap, const mp_limb_t *bp);

void
ecc_modp_sqr (const struct ecc_curve *ecc, mp_limb_t *rp,
	      const mp_limb_t *ap);

void
ecc_modp_inv (const struct ecc_curve *ecc, mp_limb_t *rp, mp_limb_t *ap,
	      mp_limb_t *scratch);

/* mod q operations. */
void
ecc_modq_mul (const struct ecc_curve *ecc, mp_limb_t *rp,
	      const mp_limb_t *ap, const mp_limb_t *bp);
void
ecc_modq_add (const struct ecc_curve *ecc, mp_limb_t *rp,
	      const mp_limb_t *ap, const mp_limb_t *bp);

void
ecc_modq_inv (const struct ecc_curve *ecc, mp_limb_t *rp, mp_limb_t *ap,
	      mp_limb_t *scratch);

void
ecc_modq_random (const struct ecc_curve *ecc, mp_limb_t *xp,
		 void *ctx, nettle_random_func *random, mp_limb_t *scratch);

void
ecc_hash (const struct ecc_curve *ecc,
	  mp_limb_t *hp,
	  size_t length, const uint8_t *digest);

void
cnd_copy (int cnd, mp_limb_t *rp, const mp_limb_t *ap, mp_size_t n);

mp_limb_t
sec_add_1 (mp_limb_t *rp, mp_limb_t *ap, mp_size_t n, mp_limb_t b);

mp_limb_t
sec_sub_1 (mp_limb_t *rp, mp_limb_t *ap, mp_size_t n, mp_limb_t b);

void
sec_tabselect (mp_limb_t *rp, mp_size_t rn,
	       const mp_limb_t *table, unsigned tn,
	       unsigned k);

void
sec_modinv (mp_limb_t *vp, mp_limb_t *ap, mp_size_t n,
	    const mp_limb_t *mp, const mp_limb_t *mp1h, mp_size_t bit_size,
	    mp_limb_t *scratch);

int
ecc_25519_sqrt(mp_limb_t *rp, const mp_limb_t *ap);

void
curve25519_eh_to_x (mp_limb_t *xp, const mp_limb_t *p,
		    mp_limb_t *scratch);

/* Current scratch needs: */
#define ECC_MODINV_ITCH(size) (3*(size))
#define ECC_J_TO_A_ITCH(size) (5*(size))
#define ECC_EH_TO_A_ITCH(size) (4*(size))
#define ECC_DUP_JJ_ITCH(size) (5*(size))
#define ECC_DUP_EH_ITCH(size) (5*(size))
#define ECC_ADD_JJA_ITCH(size) (6*(size))
#define ECC_ADD_JJJ_ITCH(size) (8*(size))
#define ECC_ADD_EH_ITCH(size) (6*(size))
#define ECC_ADD_EHH_ITCH(size) (7*(size))
#define ECC_MUL_G_ITCH(size) (9*(size))
#define ECC_MUL_G_EH_ITCH(size) (9*(size))
#if ECC_MUL_A_WBITS == 0
#define ECC_MUL_A_ITCH(size) (12*(size))
#else
#define ECC_MUL_A_ITCH(size) \
  (((3 << ECC_MUL_A_WBITS) + 11) * (size))
#endif
#if ECC_MUL_A_EH_WBITS == 0
#define ECC_MUL_A_EH_ITCH(size) (13*(size))
#else
#define ECC_MUL_A_EH_ITCH(size) \
  (((3 << ECC_MUL_A_EH_WBITS) + 10) * (size))
#endif
#define ECC_ECDSA_SIGN_ITCH(size) (12*(size))
#define ECC_MODQ_RANDOM_ITCH(size) (size)
#define ECC_HASH_ITCH(size) (1+(size))

#endif /* NETTLE_ECC_INTERNAL_H_INCLUDED */
