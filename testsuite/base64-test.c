#include "testutils.h"
#include "base64.h"

int
test_main(void)
{
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
    struct base64_ctx ctx;
    
    ASSERT(BASE64_ENCODE_LENGTH(5) == 8);
    ASSERT(8 == base64_encode(buffer, 5, buffer));
    ASSERT(MEMEQ(9, buffer, "SGVsbG8=x"));
    buffer[6] = '=';

    base64_decode_init(&ctx);
    ASSERT(4 == base64_decode_update(&ctx, buffer, 8, buffer));
    ASSERT(MEMEQ(9, buffer, "HellbG==x"));
  }
    
  SUCCESS();
}
