#include "testutils.h"

#include "knuth-lfib.h"

#if __GNUC__
# define UNUSED __attribute__ ((__unused__))
#else
# define UNUSED
#endif

static void
progress(void *ctx UNUSED, int c)
{
  fputc(c, stderr);
}

int
test_main(void)
{
#if WITH_PUBLIC_KEY

  struct dsa_public_key pub;
  struct dsa_private_key key;
  
  struct knuth_lfib_ctx lfib;
  
  dsa_private_key_init(&key);
  dsa_public_key_init(&pub);

  /* Generate a 1024 bit key with random e */
  knuth_lfib_init(&lfib, 13);

  if (!dsa_generate_keypair(&pub, &key,
			    &lfib, (nettle_random_func) knuth_lfib_random,
			    NULL, verbose ? progress : NULL,
			    1024))
    FAIL();

  test_dsa_key(&pub, &key);
  test_dsa(&pub, &key);

  dsa_public_key_clear(&pub);
  dsa_private_key_clear(&key);
  
  SUCCESS();
  
#else /* !WITH_PUBLIC_KEY */
  SKIP();
#endif /* !WITH_PUBLIC_KEY */
}
