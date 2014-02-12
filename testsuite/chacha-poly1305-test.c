#include "testutils.h"
#include "nettle-internal.h"

void
test_main(void)
{
  /* From draft-agl-tls-chacha20poly1305-04 */
  test_aead (&nettle_chacha_poly1305, NULL,
	     SHEX("4290bcb154173531f314af57f3be3b50"
		  "06da371ece272afa1b5dbdd1100a1007"),	/* key */
	     SHEX("87e229d4500845a079c0"),		/* auth data */
	     SHEX("86d09974840bded2a5ca"),		/* plain text */
	     SHEX("e3e446f7ede9a19b62a4"),		/* ciphertext */
	     SHEX("cd7cf67be39c794a"),			/* nonce */
	     SHEX("677dabf4e3d24b876bb284753896e1d6"));	/* tag */
}
