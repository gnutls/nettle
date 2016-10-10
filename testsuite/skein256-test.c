#include "testutils.h"

#include "skein.h"

static void
print_array(const char *label, size_t n, const uint64_t *x)
{
  size_t i;
  printf("%s:", label);
  for (i = 0; i < n; i++)
    printf("%s%016llx", (i && !(i%4)) ? "\n    " : " ",
	   (unsigned long long) x[i]);
  printf("\n");
}

static void
test_skein256_block (const uint64_t keys[4],
		     const uint64_t tweak[2],
		     const uint8_t msg[SKEIN256_BLOCK_SIZE],
		     const uint64_t ref[_SKEIN256_LENGTH])
{
  uint64_t keys_expanded[_SKEIN256_NKEYS];
  uint64_t tweak_expanded[_SKEIN_NTWEAK];
  uint64_t output[_SKEIN256_LENGTH];
  uint64_t sum;
  unsigned i;
  for (i = 0, sum = _SKEIN_C240; i < _SKEIN256_LENGTH; i++)
    {
      keys_expanded[i] = keys[i];
      sum ^= keys[i];
    }
  keys_expanded[_SKEIN256_LENGTH] = sum;
  tweak_expanded[0] = tweak[0];
  tweak_expanded[1] = tweak[1];
  tweak_expanded[2] = tweak[0] ^ tweak[1];

  _skein256_block(output, keys_expanded, tweak_expanded, msg);
  if (memcmp (output, ref, sizeof(output)) != 0)
    {
      printf ("Skein 256 failed:\n");
      print_array("key", 4, keys);
      print_array("tweak", 2, tweak);
      printf ("msg: ");
      print_hex(SKEIN256_BLOCK_SIZE, msg);
      print_array("out", 4, output);
      print_array("ref", 4, ref);
      FAIL();
    }
}

void
test_main(void)
{
  /* From skein_golden_kat_short_internals.txt in
     http://www.skein-hash.info/sites/default/files/NIST_CD_102610.zip. */
  {
    static const uint64_t zeros[4] = {
      0, 0, 0, 0
    };
    static const uint64_t ref[_SKEIN256_LENGTH] = {
      0x94EEEA8B1F2ADA84ull,
      0xADF103313EAE6670ull,
      0x952419A1F4B16D53ull,
      0xD83F13E63C9F6B11ull,
    };
    test_skein256_block(zeros, zeros,
			H("0000000000000000 0000000000000000"
			  "0000000000000000 0000000000000000"),
			ref);
  }
  {
    static const uint64_t keys[4] = {
      0x1716151413121110ull,
      0x1F1E1D1C1B1A1918ull,
      0x2726252423222120ull,
      0x2F2E2D2C2B2A2928ull,
    };
    static const uint64_t tweak[2] = {
      0x0706050403020100ull,
      0x0F0E0D0C0B0A0908ull,
    };
    static const uint64_t ref[4] = {
      0x277610F5036C2E1Full,
      0x25FB2ADD1267773Eull,
      0x9E1D67B3E4B06872ull,
      0x3F76BC7651B39682ull,
    };
    test_skein256_block(keys, tweak,
			H("FFFEFDFCFBFAF9F8 F7F6F5F4F3F2F1F0"
			  "EFEEEDECEBEAE9E8 E7E6E5E4E3E2E1E0"
			  ),
			ref);
  }
  {
    /* skein256 G0 = E(zeros, tweak, config string) */
    static const uint64_t zero_keys[4] = {
      0, 0, 0, 0
    };
    static const uint64_t tweak[2] = {
      32, /* message length */
      0xc4ull << 56, /* first and final, type 4 */
    };
    static const uint64_t ref[_SKEIN256_LENGTH] = {
      0xFC9DA860D048B449ull,
      0x2FCA66479FA7D833ull,
      0xB33BC3896656840Full,
      0x6A54E920FDE8DA69ull,
    };

    test_skein256_block(zero_keys, tweak,
			H("5348413301000000 0001000000000000"
			  /* SHA3  v1       output bits (256) */
			  "0000000000000000 0000000000000000"),
			ref);
  }
  /* From the skein paper. */
  test_hash(&nettle_skein256, SHEX("ff"),
	    SHEX("0B 98 DC D1 98 EA 0E 50 A7 A2 44 C4 44 E2 5C 23"
		 "DA 30 C1 0F C9 A1 F2 70 A6 63 7F 1F 34 E6 7E D2"));
  test_hash(&nettle_skein256,
	    SHEX("FF FE FD FC FB FA F9 F8 F7 F6 F5 F4 F3 F2 F1 F0"
		 "EF EE ED EC EB EA E9 E8 E7 E6 E5 E4 E3 E2 E1 E0"),
	    SHEX("8D 0F A4 EF 77 7F D7 59 DF D4 04 4E 6F 6A 5A C3"
		 "C7 74 AE C9 43 DC FC 07 92 7B 72 3B 5D BF 40 8B"));
  test_hash(&nettle_skein256,
	    SHEX("FF FE FD FC FB FA F9 F8 F7 F6 F5 F4 F3 F2 F1 F0"
		 "EF EE ED EC EB EA E9 E8 E7 E6 E5 E4 E3 E2 E1 E0"
		 "DF DE DD DC DB DA D9 D8 D7 D6 D5 D4 D3 D2 D1 D0"
		 "CF CE CD CC CB CA C9 C8 C7 C6 C5 C4 C3 C2 C1 C0"),
	    SHEX("DF 28 E9 16 63 0D 0B 44 C4 A8 49 DC 9A 02 F0 7A"
		 "07 CB 30 F7 32 31 82 56 B1 5D 86 5A C4 AE 16 2F"));
}
