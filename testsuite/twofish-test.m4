#include "twofish.h"

BEGIN_TEST

struct twofish_ctx ctx;

uint8_t msg[TWOFISH_BLOCK_SIZE];
uint8_t cipher[TWOFISH_BLOCK_SIZE];
uint8_t clear[TWOFISH_BLOCK_SIZE];

/* 128 bit key */
H(msg, "0000000000000000 0000000000000000");

twofish_set_key(&ctx, 16, H("0000000000000000 0000000000000000"));
twofish_encrypt(&ctx, TWOFISH_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(TWOFISH_BLOCK_SIZE, cipher,
	H("9F589F5CF6122C32 B6BFEC2F2AE8C35A")))
  FAIL;

twofish_decrypt(&ctx, TWOFISH_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(TWOFISH_BLOCK_SIZE, msg, clear))
  FAIL;

/* 192 bit key */

twofish_set_key(&ctx, 24, H("0123456789ABCDEF FEDCBA9876543210"
			    "0011223344556677"));
twofish_encrypt(&ctx, TWOFISH_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(TWOFISH_BLOCK_SIZE, cipher,
	H("CFD1D2E5A9BE9CDF 501F13B892BD2248")))
  FAIL;

twofish_decrypt(&ctx, TWOFISH_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(TWOFISH_BLOCK_SIZE, msg, clear))
  FAIL;

/* 256 bit key */
twofish_set_key(&ctx, 32, H("0123456789ABCDEF FEDCBA9876543210"
			    "0011223344556677 8899AABBCCDDEEFF"));
twofish_encrypt(&ctx, TWOFISH_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(TWOFISH_BLOCK_SIZE, cipher,
	H("37527BE0052334B8 9F0CFCCAE87CFA20")))
  FAIL;

twofish_decrypt(&ctx, TWOFISH_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(TWOFISH_BLOCK_SIZE, msg, clear))
  FAIL;
