#include "testutils.h"
#include "sexp.h"

#include "buffer.h"
#include "bignum.h"

int
test_main(void)
{
  struct nettle_buffer buffer;
  const uint8_t e1[] = "(3:foo(3:bar17:xxxxxxxxxxxxxxxxx))";
  
  nettle_buffer_init(&buffer);
  ASSERT(sexp_format(&buffer, "(%s(%s%s))",
		     "foo", "bar", "xxxxxxxxxxxxxxxxx"));

  ASSERT(buffer.size == strlen(e1));
  ASSERT(MEMEQ(buffer.size, buffer.contents, e1));

  nettle_buffer_clear(&buffer);
  
#if HAVE_LIBGMP
  {
    mpz_t x;
    const uint8_t e2[] = "(3:foo(3:bar11:abcdefghijk))";
    
    nettle_mpz_init_set_str_256(x, 11, "abcdefghijk");
    nettle_buffer_init(&buffer);

    ASSERT(sexp_format(&buffer, "(%s(%s%b))",
		     "foo", "bar", x));

    ASSERT(buffer.size == strlen(e2));
    ASSERT(MEMEQ(buffer.size, buffer.contents, e2));

    nettle_buffer_clear(&buffer);
    mpz_clear(x);
  }
#endif /* HAVE_LIBGMP */

  SUCCESS();
}

  
