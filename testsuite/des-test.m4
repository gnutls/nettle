#include "des.h"

BEGIN_TEST

struct des_ctx ctx;

uint8_t msg[DES_BLOCK_SIZE];
uint8_t cipher[DES_BLOCK_SIZE];
uint8_t clear[DES_BLOCK_SIZE];

H(msg, "00 00 00 00 00 00 00 00");

if (!des_set_key(&ctx, H("01 01 01 01 01 01 01 80")))
  FAIL;

des_encrypt(&ctx, DES_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(DES_BLOCK_SIZE, cipher,
	H("9C C6 2D F4 3B 6E ED 74")))
  FAIL;

des_decrypt(&ctx, DES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(DES_BLOCK_SIZE, msg, clear))
  FAIL;

H(msg, "00 00 00 00 00 00 00 40");

if (!des_set_key(&ctx, H("80 01 01 01 01 01 01 01")))
  FAIL;

des_encrypt(&ctx, DES_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(DES_BLOCK_SIZE, cipher,
	H("A3 80 E0 2A 6B E5 46 96")))
  FAIL;

des_decrypt(&ctx, DES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(DES_BLOCK_SIZE, msg, clear))
  FAIL;

H(msg, "00 00 00 00 00 00 00 00");

if (!des_set_key(&ctx, H("08 19 2A 3B 4C 5D 6E 7F")))
  FAIL;

des_encrypt(&ctx, DES_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(DES_BLOCK_SIZE, cipher,
	H("25 DD AC 3E 96 17 64 67")))
  FAIL;

des_decrypt(&ctx, DES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(DES_BLOCK_SIZE, msg, clear))
  FAIL;

if (!des_set_key(&ctx, H("01 23 45 67 89 AB CD EF")))
  FAIL;

des_encrypt(&ctx, DES_BLOCK_SIZE, cipher, "Now is t");

if (!MEMEQ(DES_BLOCK_SIZE, cipher,
	H("3F A4 0E 8A 98 4D 48 15")))
  FAIL;

des_decrypt(&ctx, DES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(DES_BLOCK_SIZE, "Now is t", clear))
  FAIL;

/* Parity check */
if (des_set_key(&ctx, H("01 01 01 01 01 01 01 00"))
    || (ctx.status != DES_BAD_PARITY))
  FAIL;

/* Weak key check */
if (des_set_key(&ctx, H("01 01 01 01 01 01 01 01"))
    || (ctx.status != DES_WEAK_KEY))
  FAIL;

if (des_set_key(&ctx, H("01 FE 01 FE 01 FE 01 FE"))
    || (ctx.status != DES_WEAK_KEY))
  FAIL;

if (des_set_key(&ctx, H("FE E0 FE E0 FE F1 FE F1"))
    || (ctx.status != DES_WEAK_KEY))
  FAIL;

