#include "serpent.h"

BEGIN_TEST

struct serpent_ctx ctx;

uint8_t msg[SERPENT_BLOCK_SIZE];
uint8_t cipher[SERPENT_BLOCK_SIZE];
uint8_t clear[SERPENT_BLOCK_SIZE];

/* The first test for each key size from the ecb_vk.txt and ecb_vt.txt
 * files in the serpent package. */

/* 128 bit key */

/* vk, 1 */
H(msg, "0000000000000000 0000000000000000");

serpent_set_key(&ctx, 16, H("8000000000000000 0000000000000000"));
serpent_encrypt(&ctx, SERPENT_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(SERPENT_BLOCK_SIZE, cipher,
	H("49AFBFAD9D5A3405 2CD8FFA5986BD2DD")))
  FAIL;

serpent_decrypt(&ctx, SERPENT_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(SERPENT_BLOCK_SIZE, msg, clear))
  FAIL;

/* vt, 1 */
H(msg, "8000000000000000 0000000000000000");

serpent_set_key(&ctx, 16, H("0000000000000000 0000000000000000"));
serpent_encrypt(&ctx, SERPENT_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(SERPENT_BLOCK_SIZE, cipher,
	H("10B5FFB720B8CB90 02A1142B0BA2E94A")))
  FAIL;

serpent_decrypt(&ctx, SERPENT_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(SERPENT_BLOCK_SIZE, msg, clear))
  FAIL;

/* 192 bit key */

/* vk, 1 */
H(msg, "0000000000000000 0000000000000000");

serpent_set_key(&ctx, 24, H("8000000000000000 0000000000000000"
			    "0000000000000000"));
serpent_encrypt(&ctx, SERPENT_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(SERPENT_BLOCK_SIZE, cipher,
	H("E78E5402C7195568 AC3678F7A3F60C66")))
  FAIL;

serpent_decrypt(&ctx, SERPENT_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(SERPENT_BLOCK_SIZE, msg, clear))
  FAIL;

/* vt, 1 */
H(msg, "8000000000000000 0000000000000000");

serpent_set_key(&ctx, 24, H("0000000000000000 0000000000000000"
			    "0000000000000000"));
serpent_encrypt(&ctx, SERPENT_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(SERPENT_BLOCK_SIZE, cipher,
	H("B10B271BA25257E1 294F2B51F076D0D9")))
  FAIL;

serpent_decrypt(&ctx, SERPENT_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(SERPENT_BLOCK_SIZE, msg, clear))
  FAIL;

/* 256 bit key */

/* vk, 1 */
H(msg, "0000000000000000 0000000000000000");

serpent_set_key(&ctx, 32, H("8000000000000000 0000000000000000"
			    "0000000000000000 0000000000000000"));
serpent_encrypt(&ctx, SERPENT_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(SERPENT_BLOCK_SIZE, cipher,
	H("ABED96E766BF28CB C0EBD21A82EF0819")))
  FAIL;

serpent_decrypt(&ctx, SERPENT_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(SERPENT_BLOCK_SIZE, msg, clear))
  FAIL;

/* vt, 1 */
H(msg, "8000000000000000 0000000000000000");

serpent_set_key(&ctx, 32, H("0000000000000000 0000000000000000"
			    "0000000000000000 0000000000000000"));
serpent_encrypt(&ctx, SERPENT_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(SERPENT_BLOCK_SIZE, cipher,
	H("DA5A7992B1B4AE6F 8C004BC8A7DE5520")))
  FAIL;

serpent_decrypt(&ctx, SERPENT_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(SERPENT_BLOCK_SIZE, msg, clear))
  FAIL;

