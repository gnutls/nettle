#include "testutils.h"

/* For curve25519 (or other edwards curves) only. */
static int
point_zero_p (const struct ecc_curve *ecc, const mp_limb_t *p)
{  
  mp_limb_t *d;
  int ret;
  mp_size_t i;

  /* Zero point has Y = Z (mod p), or y = Y/Z = 1, which also implies
     x == 0. */
  d = xalloc_limbs (ecc->size);
  ecc_modp_sub (ecc, d, p + ecc->size, p + 2*ecc->size);
  while (mpn_cmp (d, ecc->p, ecc->size) >= 0)
    mpn_sub_n (d, d, ecc->p, ecc->size);

  for (i = 0, ret = 1; i < ecc->size; i++)
    if (d[i])
      {
	ret = 0;
	break;
      }
  
  free (d);
  return ret;
}

void
test_main (void)
{
  unsigned i;

  for (i = 0; ecc_curves[i]; i++)
    {
      const struct ecc_curve *ecc = ecc_curves[i];
      mp_limb_t *g = xalloc_limbs (ecc_size_j (ecc));
      mp_limb_t *p = xalloc_limbs (ecc_size_j (ecc));
      mp_limb_t *scratch = xalloc_limbs (ECC_DUP_EH_ITCH(ecc->size));;

      if (ecc->bit_size == 255)
	{
	  mp_limb_t *z = xalloc_limbs (ecc_size_j (ecc));
	  /* Zero point has x = 0, y = 1, z = 1 */
	  mpn_zero (z, 3*ecc->size);
	  z[ecc->size] = z[2*ecc->size] = 1;
	  
	  ecc_a_to_j (ecc, g, ecc->g);

	  ecc_dup_eh (ecc, p, z, scratch);
	  if (!point_zero_p (ecc, p))
	    die ("dup of zero point failed.\n");

	  ecc_dup_eh (ecc, p, g, scratch);
	  test_ecc_mul_h (i, 2, p);

	  ecc_dup_eh (ecc, p, p, scratch);
	  test_ecc_mul_h (i, 4, p);
	  free (z);
	}
      else
	{
	  ecc_a_to_j (ecc, g, ecc->g);

	  ecc_dup_jj (ecc, p, g, scratch);
	  test_ecc_mul_h (i, 2, p);

	  ecc_dup_jj (ecc, p, p, scratch);
	  test_ecc_mul_h (i, 4, p);
	}
      free (p);
      free (g);
      free (scratch);
    }
}
