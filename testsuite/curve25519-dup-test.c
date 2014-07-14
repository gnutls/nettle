#include "testutils.h"

static int
point_zero_p (const struct ecc_curve *ecc, const mp_limb_t *p)
{  
  mp_limb_t *d;
  int ret;
  mp_size_t i;
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
  const struct ecc_curve *ecc = &nettle_curve25519;
  mp_limb_t *g;
  mp_limb_t *z;
  mp_limb_t *pe;
  mp_limb_t *pa;
  mp_limb_t *scratch;
  const struct ecc_ref_point g2 =
    { /* In Edwards coordinates:
	 x = 0x1a1c31f8665368131698fecfd54233fcdc638bb46d25cc61d8bc4bcdbfbb4459,
	 y = 0x2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9
      */
      "20d342d51873f1b7d9750c687d157114"
      "8f3f5ced1e350b5c5cae469cdd684efb",
      "13b57e011700e8ae050a00945d2ba2f3"
      "77659eb28d8d391ebcd70465c72df563"
    };
  const struct ecc_ref_point g4 =    
    {
      "79ce98b7e0689d7de7d1d074a15b315f"
      "fe1805dfcd5d2a230fee85e4550013ef",
      "075af5bf4ebdc75c8fe26873427d275d"
      "73c0fb13da361077a565539f46de1c30"
    };

  g = xalloc_limbs (ecc_size_j (ecc));
  z = xalloc_limbs (ecc_size_j (ecc));
  pe = xalloc_limbs (ecc_size_j (ecc));
  pa = xalloc_limbs (ecc_size_j (ecc));
  scratch = xalloc_limbs (ECC_DUP_EH_ITCH(ecc->size));

  mpn_copyi (g, ecc->g, 2*ecc->size);
  g[2*ecc->size] = 1;
  mpn_zero (g+2*ecc->size + 1, ecc->size - 1);

  /* Zero point has x = 0, y = 1, z = 1 */
  mpn_zero (z, 3*ecc->size);
  z[ecc->size] = z[2*ecc->size] = 1;

  ecc_dup_eh (ecc, pe, z, scratch);
  if (!point_zero_p (ecc, pe))
    die ("dup of zero point failed.\n");

  ecc_dup_eh (ecc, pe, g, scratch);

  ecc_eh_to_a (ecc, 0, pa, pe, scratch);
  test_ecc_point (ecc, &g2, pa);

  ecc_dup_eh (ecc, pe, pe, scratch);

  ecc_eh_to_a (ecc, 0, pa, pe, scratch);
  test_ecc_point (ecc, &g4, pa);
}
