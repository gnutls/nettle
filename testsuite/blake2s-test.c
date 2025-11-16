#include "testutils.h"

#include "blake2.h"
#include "non-nettle.h"

// Convenience function for all-in-one computation.
static void
blake2s  (size_t digest_size, uint8_t *digest,
	  size_t size, const uint8_t *data)
{
  struct blake2s_ctx ctx;
  blake2s_init (&ctx, digest_size);
  blake2s_update (&ctx, size, data);
  blake2s_digest (&ctx, digest);
}

static void
blake2s_key (size_t digest_size, uint8_t *digest,
	     size_t key_size, const uint8_t *key,
	     size_t size, const uint8_t *data)
{
  struct blake2s_ctx ctx;
  blake2s_set_key (&ctx, key_size, key, digest_size);
  blake2s_update (&ctx, size, data);
  blake2s_digest (&ctx, digest);
}

static void
test_blake2s (const struct tstring *key, const struct tstring *data,
	      const struct tstring *digest)
{
  uint8_t buf [BLAKE2S_DIGEST_SIZE];
  ASSERT (digest->length <= BLAKE2S_DIGEST_SIZE);
  if (key)
    blake2s_key (digest->length, buf, key->length, key->data, data->length, data->data);
  else
    blake2s (digest->length, buf, data->length, data->data);
  if (!MEMEQ(digest->length, buf, digest->data))
    {
      fprintf (stderr, "blake2s failed:\n");
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
blake2s_selftest (void)
{
  // Grand hash of hash results.
  static const uint8_t blake2s_res[32] = {
    0x6A, 0x41, 0x1F, 0x08, 0xCE, 0x25, 0xAD, 0xCD,
    0xFB, 0x02, 0xAB, 0xA6, 0x41, 0x45, 0x1C, 0xEC,
    0x53, 0xC5, 0x98, 0xB2, 0x4F, 0x4F, 0xC7, 0x87,
    0xFB, 0xDC, 0x88, 0x79, 0x7F, 0x4C, 0x1D, 0xFE
  };
  // Parameter sets.
  static const size_t b2s_md_len[4] = { 16, 20, 28, 32 };
  static const size_t b2s_in_len[6] = { 0,  3,  64, 65, 255, 1024 };

  size_t i, j, outlen, inlen;
  uint8_t in[1024], md[32], key[32];
  struct blake2s_ctx ctx;

  // 256-bit hash for testing.
  blake2s_init(&ctx, 32);

  for (i = 0; i < 4; i++) {
    outlen = b2s_md_len[i];
    for (j = 0; j < 6; j++) {
      inlen = b2s_in_len[j];

      selftest_seq (in, inlen, inlen);     // unkeyed hash
      blake2s (outlen, md, inlen, in);
      blake2s_update (&ctx, outlen, md);   // hash the hash

      selftest_seq (key, outlen, outlen);  // keyed hash
      blake2s_key (outlen, md, outlen, key, inlen, in);
      blake2s_update (&ctx, outlen, md);   // hash the hash
    }
  }

  // Compute and compare the hash of hashes.
  blake2s_digest (&ctx, md);
  ASSERT (MEMEQ (sizeof(blake2s_res), blake2s_res, md));
}

void
test_main(void)
{
  test_hash(&nettle_blake2s_256, SDATA("abc"),
	    SHEX("50 8C 5E 8C 32 7C 14 E2 E1 A7 2B A3 4E EB 45 2F"
		 "37 45 8B 20 9E D6 3A 29 4D 99 9B 4C 86 67 59 82"));
  /* Selected from
     https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2s-kat.txt */
  test_blake2s (SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		SHEX(""),
		SHEX("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"));
  test_blake2s (SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		SHEX("00"),
		SHEX("40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"));
  test_blake2s (SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		SHEX("0001"),
		SHEX("6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803"));
  test_blake2s (SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		SHEX("c03bc642b20959cbe133a0303e0c1abff3e31ec8e1a328ec8565c36decff5265"));
  test_blake2s (SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		SHEX("2c3e08176f760c6264c3a2cd66fec6c3d78de43fc192457b2a4a660a1e0eb22b"));
  test_blake2s (SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
		     "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
		     "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
		     "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
		     "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		     "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
		     "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe"),
		SHEX("3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd"));
  blake2s_selftest ();
}
