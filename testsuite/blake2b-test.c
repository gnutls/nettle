#include "testutils.h"

#include "blake2.h"
#include "non-nettle.h"

static void
blake2b (size_t digest_size, uint8_t *digest,
	 size_t size, const uint8_t *data)
{
  struct blake2b_ctx ctx;
  blake2b_init (&ctx, digest_size);
  blake2b_update (&ctx, size, data);
  blake2b_digest (&ctx, digest);
}

static void
blake2b_key (size_t digest_size, uint8_t *digest,
	     size_t key_size, const uint8_t *key,
	     size_t size, const uint8_t *data)
{
  struct blake2b_ctx ctx;
  blake2b_set_key (&ctx, key_size, key, digest_size);
  blake2b_update (&ctx, size, data);
  blake2b_digest (&ctx, digest);
}

static void
test_blake2b (const struct tstring *key, const struct tstring *data,
	      const struct tstring *digest)
{
  uint8_t buf [BLAKE2B_DIGEST_SIZE];
  ASSERT (digest->length <= BLAKE2B_DIGEST_SIZE);
  if (key)
    blake2b_key (digest->length, buf, key->length, key->data, data->length, data->data);
  else
    blake2b (digest->length, buf, data->length, data->data);
  if (!MEMEQ(digest->length, buf, digest->data))
    {
      fprintf (stderr, "blake2b failed:\n");
      if (key)
	{
	  fprintf (stderr, "key:");
	  tstring_print_hex (key);
	}
      fprintf (stderr, "data:");
      tstring_print_hex (data);
      fprintf (stderr, "digest:");
      print_hex (digest->length, buf);
      fprintf (stderr, "expect:");
      tstring_print_hex (digest);
      FAIL ();
    }
}

/* Self test from RFC7693 */

// Deterministic sequences (Fibonacci generator).
static void
selftest_seq(uint8_t *out, size_t len, uint32_t seed)
{
  size_t i;
  uint32_t t, a , b;

  a = 0xDEAD4BAD * seed;              // prime
  b = 1;

  for (i = 0; i < len; i++) {         // fill the buf
    t = a + b;
    a = b;
    b = t;
    out[i] = (t >> 24) & 0xFF;
  }
}

static void
blake2b_selftest (void)
{
  // grand hash of hash results
  static const uint8_t blake2b_res[32] = {
    0xC2, 0x3A, 0x78, 0x00, 0xD9, 0x81, 0x23, 0xBD,
    0x10, 0xF5, 0x06, 0xC6, 0x1E, 0x29, 0xDA, 0x56,
    0x03, 0xD7, 0x63, 0xB8, 0xBB, 0xAD, 0x2E, 0x73,
    0x7F, 0x5E, 0x76, 0x5A, 0x7B, 0xCC, 0xD4, 0x75
  };
  // parameter sets
  static const size_t b2b_md_len[4] = { 20, 32, 48, 64 };
  static const size_t b2b_in_len[6] = { 0, 3, 128, 129, 255, 1024 };

  size_t i, j, outlen, inlen;
  uint8_t in[1024], md[64], key[64];
  struct blake2b_ctx ctx;

  // 256-bit hash for testing
  blake2b_init(&ctx, 32);

  for (i = 0; i < 4; i++) {
    outlen = b2b_md_len[i];
    for (j = 0; j < 6; j++) {
      inlen = b2b_in_len[j];

      selftest_seq (in, inlen, inlen);     // unkeyed hash
      blake2b (outlen, md, inlen, in);
      blake2b_update (&ctx, outlen, md);   // hash the hash

      selftest_seq (key, outlen, outlen);  // keyed hash
      blake2b_key (outlen, md, outlen, key, inlen, in);
      blake2b_update (&ctx, outlen, md);   // hash the hash
    }
  }

  // compute and compare the hash of hashes
  blake2b_digest (&ctx, md);
  ASSERT (MEMEQ (sizeof(blake2b_res), blake2b_res, md));
}

void
test_main(void)
{
  /* RFC 7693 */
  test_hash (&nettle_blake2b_512, SDATA("abc"),
	     SHEX("BA 80 A5 3F 98 1C 4D 0D 6A 27 97 B6 9F 12 F6 E9"
		  "4C 21 2F 14 68 5A C4 B7 4B 12 BB 6F DB FF A2 D1"
		  "7D 87 C5 39 2A AB 79 2D C2 52 D5 DE 45 33 CC 95"
		  "18 D3 8A A8 DB F1 92 5A B9 23 86 ED D4 00 99 23"));
  /* Selected from
     https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt */
  test_blake2b (SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
		SHEX(""),
		SHEX("10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786"
		     "b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"));
  test_blake2b (SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
		SHEX("00"),
		SHEX("961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4"
		     "187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd"));
  test_blake2b (SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
		SHEX("0001"),
		SHEX("da2cfbe2d8409a0f38026113884f84b50156371ae304c4430173d08a99d9fb1b"
		     "983164a3770706d537f49e0c916d9f32b95cc37a95b99d857436f0232c88a965"));
  test_blake2b (SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
		SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
		SHEX("65676d800617972fbd87e4b9514e1c67402b7a331096d3bfac22f1abb95374ab"
		     "c942f16e9ab0ead33b87c91968a6e509e119ff07787b3ef483e1dcdccf6e3022"));
  test_blake2b (SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
		SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
		     "40"),
		SHEX("939fa189699c5d2c81ddd1ffc1fa207c970b6a3685bb29ce1d3e99d42f2f7442"
		     "da53e95a72907314f4588399a3ff5b0a92beb3f6be2694f9f86ecf2952d5b41c"));
  test_blake2b (SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
		SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
		     "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
		     "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
		     "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
		     "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		     "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
		     "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe"),
		SHEX("142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e9248"
		     "4be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461"));
  blake2b_selftest ();
}
