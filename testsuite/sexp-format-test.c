#include "testutils.h"
#include "sexp.h"

#include "buffer.h"
#include "bignum.h"

int
test_main(void)
{
  struct nettle_buffer buffer;

  {
    const uint8_t e[] = "(3:foo(3:bar17:xxxxxxxxxxxxxxxxx))";

    nettle_buffer_init(&buffer);
    ASSERT(sexp_format(&buffer, "(%z(%z%z))",
		       "foo", "bar", "xxxxxxxxxxxxxxxxx")
	   == strlen(e));
    
    ASSERT(sexp_format(NULL, "(%z(%z%z))",
		       "foo", "bar", "xxxxxxxxxxxxxxxxx")
	   == strlen(e));
    
    ASSERT(buffer.size == strlen(e));
    ASSERT(MEMEQ(buffer.size, buffer.contents, e));
  }
  {
    const uint8_t e[] = "{KDM6Zm9vKDM6YmFyMTc6eHh4eHh4eHh4eHh4eHh4eHgpKQ==}";

    nettle_buffer_init(&buffer);
    ASSERT(sexp_transport_format(&buffer, "(%z(%z%z))",
		       "foo", "bar", "xxxxxxxxxxxxxxxxx")
	   == strlen(e));
    
    ASSERT(sexp_transport_format(NULL, "(%z(%z%z))",
				 "foo", "bar", "xxxxxxxxxxxxxxxxx")
	   == strlen(e));
    
    ASSERT(buffer.size == strlen(e));
    ASSERT(MEMEQ(buffer.size, buffer.contents, e));
  }
  {
    const uint8_t e[] = "1:a2:bc3:def4:ghij";

    nettle_buffer_init(&buffer);  
    ASSERT(sexp_format(&buffer, "%i%i%i%i",
		       0x61, 0x6263, 0x646566, 0x6768696a)
	   == strlen(e));
    
    ASSERT(buffer.size == strlen(e));
    ASSERT(MEMEQ(buffer.size, buffer.contents, e));
  }

  {
    const uint8_t e[] = "(3:foo(4:bar))";
    
    nettle_buffer_init(&buffer);  
    ASSERT(sexp_format(&buffer, "(%z%l)",
		       "foo", 7, "(4:bar)")
	   == strlen(e));
    
    ASSERT(buffer.size == strlen(e));
    ASSERT(MEMEQ(buffer.size, buffer.contents, e));
  }
    
#if HAVE_LIBGMP
  {
    mpz_t x;
    const uint8_t e[] = "(3:foo(3:bar11:abcdefghijk))";

    nettle_buffer_clear(&buffer);
    
    nettle_mpz_init_set_str_256(x, 11, "abcdefghijk");
    nettle_buffer_init(&buffer);

    ASSERT(sexp_format(&buffer, "(%z(%z%b))",
		     "foo", "bar", x)
	   == strlen(e));

    ASSERT(sexp_format(NULL, "(%z(%z%b))",
		     "foo", "bar", x)
	   == strlen(e));
    
    ASSERT(buffer.size == strlen(e));
    ASSERT(MEMEQ(buffer.size, buffer.contents, e));

    nettle_buffer_clear(&buffer);
    mpz_clear(x);
  }
#endif /* HAVE_LIBGMP */

  SUCCESS();
}

  
