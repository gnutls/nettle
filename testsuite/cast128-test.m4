#include "cast128.h"

BEGIN_TEST

struct cast128_ctx ctx;

uint8_t msg[CAST128_BLOCK_SIZE];
uint8_t cipher[CAST128_BLOCK_SIZE];
uint8_t clear[CAST128_BLOCK_SIZE];

/* Test vectors from B.1. Single Plaintext-Key-Ciphertext Sets, RFC
 * 2144 */

/* 128 bit key */
H(msg, "01 23 45 67 89 AB CD EF");

cast128_set_key(&ctx, 16,  H("01 23 45 67 12 34 56 78"
			     "23 45 67 89 34 56 78 9A"));
cast128_encrypt(&ctx, CAST128_BLOCK_SIZE, cipher, msg);
if (!MEMEQ(CAST128_BLOCK_SIZE, cipher, H("23 8B 4F E5 84 7E 44 B2")))
  FAIL;

cast128_decrypt(&ctx, CAST128_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(CAST128_BLOCK_SIZE, msg, clear))
  FAIL;

/* 80 bit key */
H(msg, "01 23 45 67 89 AB CD EF");

cast128_set_key(&ctx, 10,  H("01 23 45 67 12 34 56 78 23 45"));
cast128_encrypt(&ctx, CAST128_BLOCK_SIZE, cipher, msg);
if (!MEMEQ(CAST128_BLOCK_SIZE, cipher, H("EB 6A 71 1A 2C 02 27 1B")))
  FAIL;

cast128_decrypt(&ctx, CAST128_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(CAST128_BLOCK_SIZE, msg, clear))
  FAIL;

/* 40 bit key */
H(msg, "01 23 45 67 89 AB CD EF");

cast128_set_key(&ctx, 5,  H("01 23 45 67 12"));
cast128_encrypt(&ctx, CAST128_BLOCK_SIZE, cipher, msg);
if (!MEMEQ(CAST128_BLOCK_SIZE, cipher, H("7A C8 16 D1 6E 9B 30 2E")))
  FAIL;

cast128_decrypt(&ctx, CAST128_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(CAST128_BLOCK_SIZE, msg, clear))
  FAIL;

