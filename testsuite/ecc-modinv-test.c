#include "testutils.h"

#if NETTLE_USE_MINI_GMP
void
test_main (void)
{
  SKIP();
}
#else /* ! NETTLE_USE_MINI_GMP */

static int
ref_modinv (mp_limb_t *rp, const mp_limb_t *ap, const mp_limb_t *mp, mp_size_t mn)
{
  mp_limb_t tp[4*(mn+1)];
  mp_limb_t *up = tp;
  mp_limb_t *vp = tp + mn+1;
  mp_limb_t *gp = tp + 2*(mn+1);
  mp_limb_t *sp = tp + 3*(mn+1);
  mp_size_t gn, sn;

  mpn_copyi (up, ap, mn);
  mpn_copyi (vp, mp, mn);
  gn = mpn_gcdext (gp, sp, &sn, up, mn, vp, mn);
  if (gn != 1 || gp[0] != 1)
    return 0;
  
  if (sn < 0)
    mpn_sub (sp, mp, mn, sp, -sn);
  else if (sn < mn)
    /* Zero-pad. */
    mpn_zero (sp + sn, mn - sn);

  mpn_copyi (rp, sp, mn);
  return 1;
}

static int
zero_p (const struct ecc_modulo *m, const mp_limb_t *xp)
{
  return mpn_zero_p (xp, m->size)
    || mpn_cmp (xp, m->m, m->size) == 0;
}

#define MAX_ECC_SIZE (1 + 521 / GMP_NUMB_BITS)
#define COUNT 500

static void
test_modulo (gmp_randstate_t rands, const char *name,
	     const struct ecc_modulo *m)
{
  mp_limb_t *a;
  mp_limb_t *ai;
  mp_limb_t *ref;
  mp_limb_t *scratch;
  unsigned j;
  mpz_t r;

  mpz_init (r);

  a = xalloc_limbs (m->size);
  ai = xalloc_limbs (2*m->size);
  ref = xalloc_limbs (m->size);;
  scratch = xalloc_limbs (m->invert_itch);

  /* Check behaviour for zero input */
  mpn_zero (a, m->size);
  memset (ai, 17, m->size * sizeof(*ai));
  m->invert (m, ai, a, scratch);
  if (!zero_p (m, ai))
    {
      fprintf (stderr, "%s->invert failed for zero input (bit size %u):\n",
	       name, m->bit_size);
      gmp_fprintf (stderr, "p = %Nx\n"
		   "t = %Nx (bad)\n",
		   m->m, m->size,
		   ai, m->size);
      abort ();
    }
	  
  /* Check behaviour for a = m */
  memset (ai, 17, m->size * sizeof(*ai));
  m->invert (m, ai, m->m, scratch);
  if (!zero_p (m, ai))
    {
      fprintf (stderr, "%s->invert failed for a = p input (bit size %u):\n",
	       name, m->bit_size);
      gmp_fprintf (stderr, "p = %Nx\n"
		   "t = %Nx (bad)\n",
		   m->m, m->size,
		   ai, m->size);
      abort ();
    }
	
  for (j = 0; j < COUNT; j++)
    {
      if (j & 1)
	mpz_rrandomb (r, rands, m->size * GMP_NUMB_BITS);
      else
	mpz_urandomb (r, rands, m->size * GMP_NUMB_BITS);

      mpz_limbs_copy (a, r, m->size);

      if (!ref_modinv (ref, a, m->m, m->size))
	{
	  if (verbose)
	    fprintf (stderr, "Test %u (bit size %u) not invertible mod %s.\n",
		     j, m->bit_size, name);
	  continue;
	}
      m->invert (m, ai, a, scratch);
      if (mpn_cmp (ref, ai, m->size))
	{
	  fprintf (stderr, "%s->invert failed (test %u, bit size %u):\n",
		   name, j, m->bit_size);
	  gmp_fprintf (stderr, "a = %Zx\n"
		       "p = %Nx\n"
		       "t = %Nx (bad)\n"
		       "r = %Nx\n",
		       r, m->m, m->size,
		       ai, m->size,
		       ref, m->size);
	  abort ();
	}
	  
    }
  mpz_clear (r);
  free (a);
  free (ai);
  free (ref);
  free (scratch);
}

void
test_main (void)
{
  gmp_randstate_t rands;
  unsigned i;

  gmp_randinit_default (rands);

  for (i = 0; ecc_curves[i]; i++)
    {
      test_modulo (rands, "p", &ecc_curves[i]->p);
      test_modulo (rands, "q", &ecc_curves[i]->q);
    }
  gmp_randclear (rands);
}
#endif /* ! NETTLE_USE_MINI_GMP */
