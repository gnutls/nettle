#include "sha1.h"

BEGIN_TEST

struct sha1_ctx ctx;
uint8_t digest[SHA1_DIGEST_SIZE];

sha1_init(&ctx);
sha1_final(&ctx);
sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);

if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	   H("DA39A3EE5E6B4B0D 3255BFEF95601890 AFD80709")))
  FAIL;

sha1_init(&ctx);
sha1_update(&ctx, 1, "a");
sha1_final(&ctx);
sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);

if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	   H("86F7E437FAA5A7FC E15D1DDCB9EAEAEA 377667B8")))
  FAIL;

memset(digest, 0, SHA1_DIGEST_SIZE);
sha1_digest(&ctx, SHA1_DIGEST_SIZE - 1, digest);

if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	   H("86F7E437FAA5A7FC E15D1DDCB9EAEAEA 37766700")))
  FAIL;

sha1_init(&ctx);
sha1_update(&ctx, 1, "a");
sha1_final(&ctx);
sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);

if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	   H("86F7E437FAA5A7FC E15D1DDCB9EAEAEA 377667B8")))
  FAIL;

sha1_init(&ctx);
sha1_update(&ctx, 3, "abc");
sha1_final(&ctx);
sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);

if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	   H("A9993E364706816A BA3E25717850C26C 9CD0D89D")))
  FAIL;

sha1_init(&ctx);
sha1_update(&ctx, 26, "abcdefghijklmnopqrstuvwxyz");
sha1_final(&ctx);
sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);

if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	   H("32D10C7B8CF96570 CA04CE37F2A19D84 240D3A89")))
  FAIL;

sha1_init(&ctx);
sha1_update(&ctx, 14, "message digest");
sha1_final(&ctx);
sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);

if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	   H("C12252CEDA8BE899 4D5FA0290A47231C 1D16AAE3")))
  FAIL;

sha1_init(&ctx);
sha1_update(&ctx, 62, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
sha1_final(&ctx);
sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);

if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	   H("761C457BF73B14D2 7E9E9265C46F4B4D DA11F940")))
  FAIL;

sha1_init(&ctx);
sha1_update(&ctx, 80, "1234567890123456789012345678901234567890"
	              "1234567890123456789012345678901234567890");
sha1_final(&ctx);
sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);

if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	   H("50ABF5706A150990 A08B2C5EA40FA0E5 85554732")))
  FAIL;
