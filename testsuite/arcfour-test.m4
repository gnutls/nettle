#include "arcfour.h"

BEGIN_TEST

struct arcfour_ctx ctx;
const uint8_t *clear = H("01234567 89ABCDEF");
uint8_t cipher[8];
arcfour_set_key(&ctx, 16, H("01234567 89ABCDEF 00000000 00000000"));
arcfour_crypt(&ctx, 8, cipher, clear);
if (!MEMEQ(8, cipher, H("69723659 1B5242B1")))
  FAIL;
