#include "sha.h"

BEGIN_TEST

struct sha256_ctx ctx;
uint8_t digest[SHA256_DIGEST_SIZE];

sha256_init(&ctx);
sha256_update(&ctx, 3, "abc");
sha256_final(&ctx);
sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);

if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	   H("ba7816bf8f01cfea 414140de5dae2223 b00361a396177a9c b410ff61f20015ad")))
  FAIL;

memset(digest, 0, SHA256_DIGEST_SIZE);
sha256_digest(&ctx, SHA256_DIGEST_SIZE - 1, digest);

if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	   H("ba7816bf8f01cfea 414140de5dae2223 b00361a396177a9c b410ff61f2001500")))
  FAIL;

sha256_init(&ctx);
sha256_update(&ctx, 56, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
sha256_final(&ctx);
sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);

if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	   H("248d6a61d20638b8 e5c026930c3e6039 a33ce45964ff2167 f6ecedd419db06c1")))
  FAIL;

sha256_init(&ctx);
sha256_update(&ctx, 112, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
			 "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
sha256_final(&ctx);
sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);

if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	   H("cf5b16a778af8380 036ce59e7b049237 0b249b11e8f07a51 afac45037afee9d1")))
  FAIL;
