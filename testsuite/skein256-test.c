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
		     const uint64_t msg[_SKEIN256_LENGTH],
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
      print_array("msg", 4, msg);
      print_array("out", 4, output);
      print_array("ref", 4, ref);
      FAIL();
    }
}

void
test_main(void)
{
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
    test_skein256_block(zeros, zeros, zeros, ref);
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
    static const uint64_t msg[4] = {
      0xF8F9FAFBFCFDFEFFull,
      0xF0F1F2F3F4F5F6F7ull,
      0xE8E9EAEBECEDEEEFull,
      0xE0E1E2E3E4E5E6E7ull,
    };
    static const uint64_t ref[4] = {
      0x277610F5036C2E1Full,
      0x25FB2ADD1267773Eull,
      0x9E1D67B3E4B06872ull,
      0x3F76BC7651B39682ull,
    };
    test_skein256_block(keys, tweak, msg, ref);
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
    static const uint64_t config[_SKEIN256_LENGTH] = {
      0x0133414853ull, /* "SHA3", version 1 */
      256, /* Output length, in bits */
      0, 0 };
    static const uint64_t ref[_SKEIN256_LENGTH] = {
      0xFC9DA860D048B449ull,
      0x2FCA66479FA7D833ull,
      0xB33BC3896656840Full,
      0x6A54E920FDE8DA69ull,
    };

    test_skein256_block(zero_keys, tweak, config, ref);
  }
}
