#include "testutils.h"
#include "base64.h"

int
test_main(void)
{
  ASSERT(BASE64_ENCODE_LENGTH(0) == 0);   /* At most   4 bits */
  ASSERT(BASE64_ENCODE_LENGTH(1) == 2);   /* At most  12 bits */
  ASSERT(BASE64_ENCODE_LENGTH(2) == 3);   /* At most  20 bits */
  ASSERT(BASE64_ENCODE_LENGTH(3) == 4);   /* At most  28 bits */
  ASSERT(BASE64_ENCODE_LENGTH(4) == 6);   /* At most  36 bits */
  ASSERT(BASE64_ENCODE_LENGTH(5) == 7);   /* At most  44 bits */
  ASSERT(BASE64_ENCODE_LENGTH(12) == 16); /* At most 100 bits */
  ASSERT(BASE64_ENCODE_LENGTH(13) == 18); /* At most 108 bits */

  ASSERT(BASE64_DECODE_LENGTH(0) == 0); /* At most  6 bits */
  ASSERT(BASE64_DECODE_LENGTH(1) == 1); /* At most 12 bits */
  ASSERT(BASE64_DECODE_LENGTH(2) == 2); /* At most 18 bits */
  ASSERT(BASE64_DECODE_LENGTH(3) == 3); /* At most 24 bits */
  ASSERT(BASE64_DECODE_LENGTH(4) == 3); /* At most 30 bits */
  
  test_armor(&nettle_base64, 0, "", "");
  test_armor(&nettle_base64, 1, "H", "SA==");
  test_armor(&nettle_base64, 2, "He", "SGU=");
  test_armor(&nettle_base64, 3, "Hel", "SGVs");
  test_armor(&nettle_base64, 4, "Hell", "SGVsbA==");
  test_armor(&nettle_base64, 5, "Hello", "SGVsbG8=");
  test_armor(&nettle_base64, 6, "Hello", "SGVsbG8A");
  test_armor(&nettle_base64, 4, "\xff\xff\xff\xff", "/////w==");

  {
    /* Test overlapping areas */
    uint8_t buffer[] = "Helloxxxx";
    struct base64_decode_ctx ctx;
    
    ASSERT(BASE64_ENCODE_RAW_LENGTH(5) == 8);
    base64_encode_raw(buffer, 5, buffer);
    ASSERT(MEMEQ(9, buffer, "SGVsbG8=x"));
    buffer[6] = '=';

    base64_decode_init(&ctx);
    ASSERT(4 == base64_decode_update(&ctx, buffer, 8, buffer));
    ASSERT(MEMEQ(9, buffer, "HellbG==x"));
  }
    
  SUCCESS();
}
