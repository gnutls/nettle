#include "md5.h"

BEGIN_TEST

struct md5_ctx ctx;
uint8_t digest[MD5_DIGEST_SIZE];

md5_init(&ctx);
md5_final(&ctx);
md5_digest(&ctx, MD5_DIGEST_SIZE, digest);

if (!MEMEQ(MD5_DIGEST_SIZE, digest, H("D41D8CD98F00B204 E9800998ECF8427E")))
  FAIL;

memset(digest, 0, MD5_DIGEST_SIZE);
md5_digest(&ctx, MD5_DIGEST_SIZE - 1, digest);

if (!MEMEQ(MD5_DIGEST_SIZE, digest, H("D41D8CD98F00B204 E9800998ECF84200")))
  FAIL;

md5_init(&ctx);
md5_update(&ctx, 1, "a");
md5_final(&ctx);
md5_digest(&ctx, MD5_DIGEST_SIZE, digest);

if (!MEMEQ(MD5_DIGEST_SIZE, digest, H("0CC175B9C0F1B6A8 31C399E269772661")))
  FAIL;

md5_init(&ctx);
md5_update(&ctx, 3, "abc");
md5_final(&ctx);
md5_digest(&ctx, MD5_DIGEST_SIZE, digest);

if (!MEMEQ(MD5_DIGEST_SIZE, digest, H("900150983cd24fb0 D6963F7D28E17F72")))
  FAIL;

md5_init(&ctx);
md5_update(&ctx, 14, "message digest");
md5_final(&ctx);
md5_digest(&ctx, MD5_DIGEST_SIZE, digest);

if (!MEMEQ(MD5_DIGEST_SIZE, digest, H("F96B697D7CB7938D 525A2F31AAF161D0")))
  FAIL;

md5_init(&ctx);
md5_update(&ctx, 26, "abcdefghijklmnopqrstuvwxyz");
md5_final(&ctx);
md5_digest(&ctx, MD5_DIGEST_SIZE, digest);

if (!MEMEQ(MD5_DIGEST_SIZE, digest, H("C3FCD3D76192E400 7DFB496CCA67E13B")))
  FAIL;

md5_init(&ctx);
md5_update(&ctx, 62, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
md5_final(&ctx);
md5_digest(&ctx, MD5_DIGEST_SIZE, digest);

if (!MEMEQ(MD5_DIGEST_SIZE, digest, H("D174AB98D277D9F5 A5611C2C9F419D9F")))
  FAIL;

md5_init(&ctx);
md5_update(&ctx, 80, "1234567890123456789012345678901234567890"
	            "1234567890123456789012345678901234567890");
md5_final(&ctx);
md5_digest(&ctx, MD5_DIGEST_SIZE, digest);

if (!MEMEQ(MD5_DIGEST_SIZE, digest, H("57EDF4A22BE3C955 AC49DA2E2107B67A")))
  FAIL;

