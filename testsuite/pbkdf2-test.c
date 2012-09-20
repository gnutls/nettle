#include "testutils.h"
#include "hmac.h"
#include "sha.h"
#include "pbkdf2.h"

/* NOTE: The salt argument is expected to expand to length, data */
#define PBKDF2_TEST(ctx, update, digest, size, c, salt, expect)	\
  do {									\
    dk[expect->length] = 17;						\
    PBKDF2 (ctx, update, digest, size, c, salt, expect->length, dk); \
    ASSERT(MEMEQ (expect->length, dk, expect->data));			\
    ASSERT(dk[expect->length] == 17);					\
  } while (0)

#define MAX_DKLEN 25

void
test_main (void)
{
  uint8_t dk[MAX_DKLEN + 1];
  struct hmac_sha1_ctx sha1ctx;
  struct hmac_sha256_ctx sha256ctx;

  /* Test vectors for PBKDF2 from RFC 6070. */

  hmac_sha1_set_key (&sha1ctx, 8, "password");

  PBKDF2_TEST (&sha1ctx, hmac_sha1_update, hmac_sha1_digest, SHA1_DIGEST_SIZE,
	       1, LDATA("salt"),
	       SHEX("0c60c80f961f0e71f3a9b524af6012062fe037a6"));

  PBKDF2_TEST (&sha1ctx, hmac_sha1_update, hmac_sha1_digest, SHA1_DIGEST_SIZE,
	       2, LDATA("salt"),
	       SHEX("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"));

  PBKDF2_TEST (&sha1ctx, hmac_sha1_update, hmac_sha1_digest, SHA1_DIGEST_SIZE,
	       4096, LDATA("salt"),
	       SHEX("4b007901b765489abead49d926f721d065a429c1"));

#if 0				/* too slow */
  PBKDF2_TEST (&sha1ctx, hmac_sha1_update, hmac_sha1_digest, SHA1_DIGEST_SIZE,
	       16777216, LDATA("salt"),
	       SHEX("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"));
#endif

  hmac_sha1_set_key (&sha1ctx, 24, "passwordPASSWORDpassword");

  PBKDF2_TEST (&sha1ctx, hmac_sha1_update, hmac_sha1_digest, SHA1_DIGEST_SIZE,
	       4096, LDATA("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
	       SHEX("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"));

  hmac_sha1_set_key (&sha1ctx, 9, "pass\0word");

  PBKDF2_TEST (&sha1ctx, hmac_sha1_update, hmac_sha1_digest, SHA1_DIGEST_SIZE,
	       4096, LDATA("sa\0lt"),
	       SHEX("56fa6aa75548099dcc37d7f03425e0c3"));

  /* PBKDF2-HMAC-SHA-256 test vectors confirmed with another
     implementation.  */

  hmac_sha256_set_key (&sha256ctx, 6, "passwd");

  PBKDF2_TEST (&sha256ctx, hmac_sha256_update, hmac_sha256_digest,
	       SHA256_DIGEST_SIZE, 1, LDATA("salt"),
	       SHEX("55ac046e56e3089fec1691c22544b605"));

  hmac_sha256_set_key (&sha256ctx, 8, "Password");

  PBKDF2_TEST (&sha256ctx, hmac_sha256_update, hmac_sha256_digest,
	       SHA256_DIGEST_SIZE, 80000, LDATA("NaCl"),
	       SHEX("4ddcd8f60b98be21830cee5ef22701f9"));
}
