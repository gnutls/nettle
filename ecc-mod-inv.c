/* ecc-mod-inv.c

   Copyright (C) 2013, 2014, 2022 Niels Möller

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

#include "ecc-internal.h"

#if GMP_LIMB_BITS != GMP_NUMB_BITS
#error Unsupported configuration
#endif

static mp_limb_t
cnd_neg (int cnd, mp_limb_t *rp, const mp_limb_t *ap, mp_size_t n)
{
  mp_limb_t cy = (cnd != 0);
  mp_limb_t mask = -cy;
  mp_size_t i;

  for (i = 0; i < n; i++)
    {
      mp_limb_t r = (ap[i] ^ mask) + cy;
      cy = r < cy;
      rp[i] = r;
    }
  /* Return cnd except R = A = 0. */
  return cnd & (1-cy);
}

#define BITCNT_BITS (sizeof(mp_bitcnt_t) * CHAR_BIT)

#define STEPS (GMP_NUMB_BITS - 2)

struct matrix {
  /* Matrix elements interpreted as signed two's complement. Absolute
     value of elements is at most 2^STEPS. */
  mp_limb_t a[2][2];
};

/* Conditionally set (a, b) <-- (b, -a) */
#define CND_NEG_SWAP_LIMB(cnd, a, b) do {\
    mp_limb_t __cnd_sum = (a) + (b);	 \
    mp_limb_t __cnd_diff = (a) - (b);	 \
    (a) -= __cnd_diff & -(cnd);		 \
    (b) -= __cnd_sum & -(cnd);		 \
  } while (0)

/* Perform K elementary reduction steps on (delta, f, g). Only the
   least significant K bits of f, g matter. Note that delta has an
   unsigned type, but is used as two's complement. */
static mp_bitcnt_t
steps(struct matrix *M, unsigned k, mp_bitcnt_t delta, mp_limb_t f, mp_limb_t g)
{
  mp_limb_t a00, a01, a10, a11;
  assert (f & 1);

  /* Identity matrix. */
  a00 = a11 = 1;
  a01 = a10 = 0;

  /* Preserve invariant (f ; g) = 2^{-i} M (f_orig, g_orig) */
  for (; k-- > 0; delta++)
    {
      mp_limb_t odd = g & 1;
      mp_limb_t swap = odd & ~(delta >> (BITCNT_BITS-1));

      /* Swap; (f'; g') = (g; -f) = (0,1;-1,0) (g;f) */
      CND_NEG_SWAP_LIMB(swap, f, g);
      CND_NEG_SWAP_LIMB(swap, a00, a10);
      CND_NEG_SWAP_LIMB(swap, a01, a11);

      /* Conditional negation. */
      delta = (delta ^ - (mp_bitcnt_t) swap) + swap;

      /* Cancel low bit and shift. */
      g += f & -odd;
      a10 += a00 & -odd;
      a11 += a01 & -odd;

      g >>= 1;
      a00 <<= 1;
      a01 <<= 1;
    }
  M->a[0][0] = a00; M->a[0][1] = a01;
  M->a[1][0] = a10; M->a[1][1] = a11;
  return delta;
}

/* Set R = (u * F + v * G), treating all numbers as two's complement.
   No overlap allowed. */
static mp_limb_t
add_add_mul (mp_ptr rp, const mp_limb_t *fp, const mp_limb_t *gp, mp_size_t n,
	     mp_limb_t u, mp_limb_t v) {
  mp_limb_t f_sign = fp[n-1] >> (GMP_LIMB_BITS - 1);
  mp_limb_t g_sign = gp[n-1] >> (GMP_LIMB_BITS - 1);
  mp_limb_t u_sign = u >> (GMP_LIMB_BITS - 1);
  mp_limb_t v_sign = v >> (GMP_LIMB_BITS - 1);
  mp_limb_t hi = mpn_mul_1 (rp, fp, n, u) - ((-f_sign) & u);
  hi -= ((-u_sign) & fp[n-1]) + mpn_cnd_sub_n (u_sign, rp + 1, rp + 1, fp, n-1);

  hi += mpn_addmul_1 (rp, gp, n, v) - ((-g_sign) & v);
  hi -= ((-v_sign) & gp[n-1]) + mpn_cnd_sub_n (v_sign, rp + 1, rp + 1, gp, n-1);

  return hi;
}

/* Update (f'; g') = M (f; g) / 2^{shift}, where all numbers are two's complement. */
static void
matrix_vector_mul (const struct matrix *M, unsigned shift,
		   mp_size_t n, mp_limb_t *fp, mp_limb_t *gp, mp_limb_t *tp)
{
  mp_limb_t f_hi = add_add_mul (tp, fp, gp, n, M->a[0][0], M->a[0][1]);
  mp_limb_t g_hi = add_add_mul (tp + n, fp, gp, n, M->a[1][0], M->a[1][1]);
  mp_limb_t lo = mpn_rshift (fp, tp, n, shift);
  assert (lo == 0);
  fp[n-1] += (f_hi << (GMP_LIMB_BITS - shift));
  lo = mpn_rshift (gp, tp + n, n, shift);
  assert (lo == 0);
  gp[n-1] += (g_hi << (GMP_LIMB_BITS - shift));
}

/* Set R = (u * F + v * G) (mod M), treating u, v as two's complement,
   but F, G, R unsigned. No overlap allowed. n limb inputs, n+1 limb
   output.

   Input can be allowed in the range 0 <= F, G < min (2 M, B^n),
   output always in the range 0 <= R < B M.
*/
static void
add_add_mul_mod (mp_ptr rp, const mp_limb_t *fp, const mp_limb_t *gp,
		 const mp_limb_t *mp, mp_size_t n,
		 mp_limb_t u, mp_limb_t v) {
  mp_limb_t u_sign = u >> (GMP_LIMB_BITS - 1);
  mp_limb_t v_sign = v >> (GMP_LIMB_BITS - 1);
  mp_limb_t r_sign;

  assert ((fp[n-1] >> 1) <= mp[n-1]);
  assert ((gp[n-1] >> 1) <= mp[n-1]);

  rp[n] = mpn_mul_1 (rp, fp, n, u);
  mpn_cnd_sub_n (u_sign, rp + 1, rp + 1, fp, n);

  rp[n] += mpn_addmul_1 (rp, gp, n, v);
  mpn_cnd_sub_n (v_sign, rp + 1, rp + 1, gp, n);

  /* Row sums of the matrix have absolute value <= B/4. With inputs F,
     G < 2 M, at this point we have

       |R| < B M/2.

     If R < 0, then R + B M is positive negative, adding B M makes the
     result positive.
  */
  r_sign = rp[n] >> (GMP_LIMB_BITS - 1);
  r_sign -= mpn_cnd_add_n (r_sign, rp + 1, rp + 1, mp, n);
  assert (r_sign == 0);
  assert (rp[n] <= mp[n-1]);
}

/* Input in range 0 <= T < B M, output in range 0 <= R < M. */
static void
redc_1 (mp_limb_t *rp, mp_limb_t *tp,
	const mp_limb_t *mp, mp_size_t n, mp_limb_t m_binv)
{
  mp_limb_t cy, hi;
  /* If we knew that 2M < B^n, we could allow result value in the
     range 0 <= R < 2M, and use mpn_add_mul_1 without any adjustment
     step. */
  hi = mpn_submul_1 (tp, mp, n, m_binv * tp[0]);
  assert (tp[0] == 0);
  cy = tp[n] < hi;
  tp[n] -= hi;

  cy -= mpn_cnd_add_n (cy, rp, tp + 1, mp, n);
  assert (cy == 0);
}

/* Update (u'; v') = M (u; v) B^{-1} (mod m), where u, v, m are
   unsigned n limbs, M has signed elements, and B is the bignum
   base.

   Output are canonically reduced, 0 <= U, V < M, but
   inputs are only required to be < 2 M.
*/
static void
matrix_vector_mul_mod (const struct matrix *M, const mp_limb_t *mp,
		       mp_limb_t m_binv,
		       mp_size_t n, mp_limb_t *up, mp_limb_t *vp, mp_limb_t *tp)
{
  add_add_mul_mod (tp, up, vp, mp, n, M->a[0][0], M->a[0][1]);
  add_add_mul_mod (tp + n + 1, up, vp, mp, n, M->a[1][0], M->a[1][1]);

  /* Reduce to n limbs, by multiplying with B^-1 (mod m) */
  redc_1 (up, tp, mp, n, m_binv);
  redc_1 (vp, tp + n + 1, mp, n, m_binv);
}

/* Input in range 0 <= T < 2M, output in range 0 <= R < 2M. */
static void
redc_bits (mp_limb_t *rp, mp_limb_t *tp, const mp_limb_t *mp,
	   mp_size_t n, mp_limb_t m_binv, mp_bitcnt_t k)
{
  mp_limb_t hi;

  for (; k >= GMP_NUMB_BITS; k -= GMP_NUMB_BITS)
    {
      hi = mpn_addmul_1 (tp, mp, n, -m_binv * tp[0]);
      mpn_copyi (tp, tp + 1, n - 1);
      tp[n-1] = hi;
    }
  if (k > 0)
    {
      mp_limb_t mask = ((mp_limb_t) 2 << (k-1)) - 1;
      mp_limb_t q = (-m_binv * tp[0]) & mask;
      hi = mpn_addmul_1 (tp, mp, n, q);
      mpn_rshift (rp, tp, n, k);
      rp[n-1] |= hi << (GMP_NUMB_BITS - k);
    }
}

static int
one_p (const mp_limb_t *p, mp_size_t n)
{
  mp_limb_t diff = p[0] ^ 1;
  mp_size_t i;
  for (i = 1; i < n; i++)
    diff |= p[i];

  return diff == 0;
}

/* Compute a^{-1} mod m, with running time depending only on the size.
   Returns zero if a == 0 (mod m), to be consistent with a^{phi(m)-1}.
   Based on the algorithm in https://eprint.iacr.org/2019/266.pdf */
void
ecc_mod_inv (const struct ecc_modulo *m,
	     mp_limb_t *up, const mp_limb_t *ap,
	     mp_limb_t *scratch)
{
  mp_size_t n = m->size;
  mp_bitcnt_t shift, delta, count;
  mp_limb_t cy;
  struct matrix M;

  /* Total scratch need 4*(n+1) for fp, gp, tp, n for v, total 5*n+4 */
#define fp scratch
#define gp (scratch + n + 1)
#define vp (scratch + 2*n + 2)
#define tp (scratch + 3*n + 2)

#define mp (m->m)

  /* Input should satisfy a < 2m, since that is what the iteration
     count is based on. */
  assert ((ap[n-1] >> 1) <= mp[n-1]);

  mpn_copyi (fp, mp, n); fp[n] = 0; gp[n] = 0;

  if (m->invert_power)
    /* Multiply by suitable pre-computed power to get inverse in redc
       representation. */
    ecc_mod_mul (m, gp, ap, m->invert_power, tp);
  else {
    mpn_copyi (gp, ap, n);

    shift = GMP_NUMB_BITS*((m->invert_count + STEPS - 1) / STEPS) - m->invert_count;

    /* Premultiply a by 2^{- shift} mod m */
    redc_bits (gp, gp, mp, n, m->binv, shift);
  }

  /* Maintain invariant

       a * u = 2^{-count} B^{ceil(count/STEPS)} f (mod m)
       a * v = 2^{-count} B^{ceil(count/STEPS)} g (mod m)
  */
  mpn_zero (up, n);
  mpn_zero (vp+1, n-1); vp[0] = 1;

  for (delta = 1, count = m->invert_count; count > STEPS; count -= STEPS)
    {
      delta = steps (&M, STEPS, delta, fp[0], gp[0]);
      matrix_vector_mul (&M, STEPS, n+1, fp, gp, tp);
      matrix_vector_mul_mod (&M, mp, m->binv, n, up, vp, tp);
    }
  delta = steps (&M, count, delta, fp[0], gp[0]);
  matrix_vector_mul (&M, count, n+1, fp, gp, tp);
  /* Only compute u, we don't need v. */
  add_add_mul_mod (tp, up, vp, mp, n, M.a[0][0], M.a[0][1]);
  redc_1 (up, tp, mp, n, m->binv);

  assert (sec_zero_p (gp, n+1));

  /* Now f = ±1 (if the inverse exists), and a * u = f (mod m) */
  cy = cnd_neg (fp[n] >> (GMP_LIMB_BITS - 1), up, up, n);
  /* Make u non-negative */
  cy -= mpn_cnd_add_n (cy, up, up, mp, n);

  cnd_neg (fp[n] >> (GMP_LIMB_BITS - 1), fp, fp, n + 1);
  cy = one_p (fp, n+1);
  /* Set to zero if invert doesn't exist. */
  while (n > 0)
    up[--n] &= - cy;
}
