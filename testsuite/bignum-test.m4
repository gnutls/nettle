
#if HAVE_CONFIG_H
#include "config.h"
#endif

#if HAVE_LIBGMP
#include "bignum.h"

#include <stdlib.h>
#include <string.h>

static void
test_bignum(const char *hex, unsigned length, const uint8_t *base256)
{
  mpz_t a;
  mpz_t b;
  uint8_t *buf;
  
  mpz_init_set_str(a, hex, 16);
  nettle_mpz_init_set_str_256(b, length, base256);

  if (mpz_cmp(a, b))
    FAIL;

  buf = alloca(length + 1);
  memset(buf, 17, length + 1);

  nettle_mpz_get_str_256(length, buf, a);
  if (!MEMEQ(length, buf, base256))
    FAIL;

  if (buf[length] != 17)
    FAIL;

  mpz_clear(a); mpz_clear(b);
}
#endif /* HAVE_LIBGMP */

BEGIN_TEST

#if HAVE_LIBGMP
test_bignum("0", 0, "");
test_bignum("010203040506", 7, H("00010203040506"));

#else /* !HAVE_LIBGMP */
SKIP
#endif /* !HAVE_LIBGMP */
