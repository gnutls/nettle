#include "des.h"

BEGIN_TEST

struct des3_ctx ctx;

uint8_t msg[DES3_BLOCK_SIZE] = "Now is t";
uint8_t cipher[DES3_BLOCK_SIZE];
uint8_t clear[DES3_BLOCK_SIZE];

/* Intermediate values:
 *   After first DES encryption:  "cd ea 2a 20 c2 e0 9e 48"
 *   After second DES decryption: "69 52 6e 95 8b ea 49 bd"
 */
if (!des3_set_key(&ctx, H("3e 0b 10 b0 5d 49 c2 54"
			  "6b 46 e0 75 8a 91 61 85"
			  "cb 04 07 d3 20 16 cb a2")))
  FAIL;

des3_encrypt(&ctx, DES_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(DES_BLOCK_SIZE, cipher,
	H("0a 5d b5 2d 85 74 d1 c9")))
  FAIL;

des3_decrypt(&ctx, DES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(DES_BLOCK_SIZE, msg, clear))
  FAIL;
