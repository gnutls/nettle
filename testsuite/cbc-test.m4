#include "aes.h"
#include "cbc.h"

BEGIN_TEST

struct CBC_CTX(struct aes_ctx, AES_BLOCK_SIZE) ctx;

uint8_t msg[2 * AES_BLOCK_SIZE] = "Listen, I'll say this only once!";
uint8_t cipher[2 * AES_BLOCK_SIZE];
uint8_t clear[2 * AES_BLOCK_SIZE];
uint8_t iv[AES_BLOCK_SIZE];

H(iv, "e9 a7 26 a0 44 7b 8d e6  03 83 60 de ea d5 b0 4e");
aes_set_key(&ctx.ctx, 32, H("8d ae 93 ff fc 78 c9 44"
			    "2a bd 0c 1e 68 bc a6 c7"
			    "05 c7 84 e3 5a a9 11 8b"
			    "d3 16 aa 54 9b 44 08 9e"));

CBC_SET_IV(&ctx, iv);
CBC_ENCRYPT(&ctx, aes_encrypt, 2 * AES_BLOCK_SIZE, cipher, msg);

if (!MEMEQ(2 * AES_BLOCK_SIZE, cipher, H("1f 94 fc 85 f2 36 21 06"
					 "4a ea e3 c9 cc 38 01 0e"
					 "7b f6 5f c5 02 59 2e 71"
					 "af bf 34 87 c0 36 2a 16")))
  FAIL;

if (!MEMEQ(AES_BLOCK_SIZE, ctx.iv, cipher + AES_BLOCK_SIZE))
  FAIL;

CBC_SET_IV(&ctx, iv);
CBC_DECRYPT(&ctx, aes_decrypt, 2 * AES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(2 * AES_BLOCK_SIZE, msg, clear))
  FAIL;
