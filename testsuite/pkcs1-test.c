#include "testutils.h"

#include "pkcs1.h"

int
test_main(void)
{
#if WITH_PUBLIC_KEY
  
  uint8_t buffer[16];
  uint8_t expected[16] = {    1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			   0xff, 0xff, 0xff, 0xff, 0,    'a',  'b',  'c' };

  pkcs1_signature_prefix(sizeof(buffer), buffer,
			 3, "abc");

  ASSERT(MEMEQ(sizeof(buffer), buffer, expected));

  SUCCESS();
#else /* !WITH_PUBLIC_KEY */
  SKIP();
#endif /* !WITH_PUBLIC_KEY */
}
