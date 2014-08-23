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

#define MAX_ECC_SIZE (1 + 521 / GMP_NUMB_BITS)
#define COUNT 500

static int
mpn_zero_p (mp_srcptr ap, mp_size_t n)
{
  while (--n >= 0)
    {
      if (ap[n] != 0)
	return 0;
    }
  return 1;
}

void
test_main (void)
{
  gmp_randstate_t rands;
  mp_limb_t a[MAX_ECC_SIZE];
  mp_limb_t ai[MAX_ECC_SIZE];
  mp_limb_t ref[MAX_ECC_SIZE];
  mp_limb_t scratch[ECC_MODINV_ITCH (MAX_ECC_SIZE)];
  unsigned i;
  mpz_t r;

  gmp_randinit_default (rands);
  mpz_init (r);
  
  for (i = 0; ecc_curves[i]; i++)
    {
      const struct ecc_curve *ecc = ecc_curves[i];
      unsigned j;
      /* Check behaviour for zero input */
      mpn_zero (a, ecc->size);
      memset (ai, 17, ecc->size * sizeof(*ai));
      ecc_modp_inv (ecc, ai, a, scratch);
      if (!mpn_zero_p (ai, ecc->size))
	{
	  fprintf (stderr, "ecc_modp_inv failed for zero input (bit size %u):\n",
		       ecc->bit_size);
	  gmp_fprintf (stderr, "p = %Nx\n"
		       "t = %Nx (bad)\n",
		       ecc->p, ecc->size,
		       ai, ecc->size);
	  abort ();
	}
	  
      /* Check behaviour for a = p */
      mpn_copyi (a, ecc->p, ecc->size);
      memset (ai, 17, ecc->size * sizeof(*ai));
      ecc_modp_inv (ecc, ai, a, scratch);
      if (!mpn_zero_p (ai, ecc->size))
	{
	  fprintf (stderr, "ecc_modp_inv failed for a = p input (bit size %u):\n",
		       ecc->bit_size);
	  gmp_fprintf (stderr, "p = %Nx\n"
		       "t = %Nx (bad)\n",
		       ecc->p, ecc->size,
		       ai, ecc->size);
	  abort ();
	}
	
      for (j = 0; j < COUNT; j++)
	{
	  if (j & 1)
	    mpz_rrandomb (r, rands, ecc->size * GMP_NUMB_BITS);
	  else
	    mpz_urandomb (r, rands, ecc->size * GMP_NUMB_BITS);

	  mpz_limbs_copy (a, r, ecc->size);

	  if (!ref_modinv (ref, a, ecc->p, ecc->size))
	    {
	      if (verbose)
		fprintf (stderr, "Test %u (bit size %u) not invertible.\n",
			 j, ecc->bit_size);
	      continue;
	    }
	  ecc_modp_inv (ecc, ai, a, scratch);
	  if (mpn_cmp (ref, ai, ecc->size))
	    {
	      fprintf (stderr, "ecc_modp_inv failed (test %u, bit size %u):\n",
		       j, ecc->bit_size);
	      gmp_fprintf (stderr, "a = %Zx\n"
			   "p = %Nx\n"
			   "t = %Nx (bad)\n"
			   "r = %Nx\n",
			   r, ecc->p, ecc->size,
			   ai, ecc->size,
			   ref, ecc->size);
	      abort ();
	    }

	  mpz_limbs_copy (a, r, ecc->size);

	  if (!ref_modinv (ref, a, ecc->q, ecc->size))
	    {
	      fprintf (stderr, "Test %u (bit size %u) not invertible.\n",
		       j, ecc->bit_size);
	      continue;
	    }
	  ecc_modq_inv (ecc, ai, a, scratch);
	  if (mpn_cmp (ref, ai, ecc->size))
	    {
	      fprintf (stderr, "ecc_modq_inv failed (test %u, bit size %u):\n",
		       j, ecc->bit_size);
	      gmp_fprintf (stderr, "a = %Zx\n"
			   "p = %Nx\n"
			   "t = %Nx (bad)\n"
			   "r = %Nx\n",
			   r, ecc->p, ecc->size,
			   ai, ecc->size,
			   ref, ecc->size);
	      abort ();
	    }
	}
    }
  gmp_randclear (rands);
  mpz_clear (r);
}
#endif /* ! NETTLE_USE_MINI_GMP */
