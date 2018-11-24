/* rsa-sec-compute-root.c

   Side-channel silent RSA root computation.

   Copyright (C) 2018 Niels Möller
   Copyright (C) 2018 Red Hat, Inc

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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>

#include "rsa.h"
#include "rsa-internal.h"
#include "gmp-glue.h"

#if !NETTLE_USE_MINI_GMP
#define MAX(a, b) ((a) > (b) ? (a) : (b))

mp_size_t
_rsa_sec_compute_root_itch (const struct rsa_private_key *key)
{
  mp_size_t nn = NETTLE_OCTET_SIZE_TO_LIMB_SIZE (key->size);
  mp_size_t pn = mpz_size (key->p);
  mp_size_t qn = mpz_size (key->q);
  mp_size_t cn = mpz_size (key->c);
  mp_size_t itch;
  mp_size_t i2;

  itch = nn;    /* Sufficient for mpn_sec_add_1 */
  i2 = mpn_sec_div_r_itch (nn, qn);
  itch = MAX (itch, i2);
  i2 = mpn_sec_div_r_itch (nn, pn);
  itch = MAX (itch, i2);
  i2 = mpn_sec_powm_itch (qn, mpz_sizeinbase (key->b, 2), qn);
  itch = MAX (itch, i2);
  i2 = mpn_sec_powm_itch (pn, mpz_sizeinbase (key->a, 2), pn);
  itch = MAX (itch, i2);
  i2 = mpn_sec_div_r_itch (qn, pn);
  itch = MAX (itch, i2);
  i2 = mpn_sec_mul_itch (pn, cn);
  itch = MAX (itch, i2);
  if (qn > pn)
    i2 = mpn_sec_mul_itch (qn, pn);
  else
    i2 = mpn_sec_mul_itch (pn, qn);
  itch = MAX (itch, i2);
  i2 = mpn_sec_div_r_itch (pn + cn, pn);
  itch = MAX (itch, i2);

  itch += MAX (nn + 1, MAX (pn +cn, qn +cn)) + pn + qn;
  return itch;
}

void
_rsa_sec_compute_root (const struct rsa_private_key *key,
                       mp_limb_t *rp, const mp_limb_t *mp,
                       mp_limb_t *scratch)
{
  mp_size_t nn = NETTLE_OCTET_SIZE_TO_LIMB_SIZE (key->size);

  /* The common case is pn = qn. This function would be simpler if we
   * could require that pn >= qn. */
  const mp_limb_t *pp = mpz_limbs_read (key->p);
  const mp_limb_t *qp = mpz_limbs_read (key->q);

  mp_size_t cn = mpz_size (key->c);
  mp_size_t pn = mpz_size (key->p);
  mp_size_t qn = mpz_size (key->q);
  mp_size_t tn = nn + 1;

  mp_limb_t *r_mod_p = scratch + MAX (tn, MAX (pn + cn, qn + cn));
  mp_limb_t *r_mod_q = r_mod_p + pn;
  mp_limb_t *sp = r_mod_q + qn;
  mp_limb_t cy;

  assert (pn + qn <= tn);
  assert (pn <= nn);
  assert (qn <= nn);
  assert (cn <= pn);

  /* Compute r_mod_q = m^d % q = (m%q)^b % q */
  mpn_copyi (scratch, mp, nn);
  mpn_sec_div_r (scratch, nn, qp, qn, sp);
  mpn_sec_powm (r_mod_q, scratch, qn, mpz_limbs_read (key->b),
                mpz_sizeinbase (key->b, 2), qp, qn, sp);

  /* Compute r_mod_p = m^d % p = (m%p)^a % p */
  mpn_copyi (scratch, mp, nn);
  mpn_sec_div_r (scratch, nn, pp, pn, sp);
  mpn_sec_powm (r_mod_p, scratch, pn, mpz_limbs_read (key->a),
                mpz_sizeinbase (key->a, 2), pp, pn, sp);

  /* Set r_mod_p' = r_mod_p * c % p - r_mod_q * c % p . */
  mpn_sec_mul (scratch, r_mod_p, pn, mpz_limbs_read (key->c), cn, sp);
  mpn_sec_div_r (scratch, pn + cn, pp, pn, sp);
  mpn_copyi (r_mod_p, scratch, pn);
  mpn_sec_mul (scratch, r_mod_q, qn, mpz_limbs_read (key->c), cn, sp);
  mpn_sec_div_r (scratch, qn + cn, pp, pn, sp);
  cy = mpn_sub_n (r_mod_p, r_mod_p, scratch, pn);
  cnd_add_n (cy, r_mod_p, pp, pn);

  /* Finally, compute x = r_mod_q + q r_mod_p' */
  if (qn > pn)
    mpn_sec_mul (scratch, qp, qn, r_mod_p, pn, sp);
  else
    mpn_sec_mul (scratch, r_mod_p, pn, qp, qn, sp);

  cy = mpn_add_n (rp, scratch, r_mod_q, qn);
  mpn_sec_add_1 (rp + qn, scratch + qn, nn - qn, cy, sp);
}
#endif
