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
test_skein512_block (const uint64_t keys[4],
		     const uint64_t tweak[2],
		     const uint8_t msg[SKEIN512_BLOCK_SIZE],
		     const uint64_t ref[_SKEIN512_LENGTH])
{
  uint64_t keys_expanded[_SKEIN512_NKEYS];
  uint64_t output[_SKEIN512_LENGTH];
  unsigned i;
  uint64_t sum;

  memcpy (keys_expanded, keys, _SKEIN512_LENGTH * sizeof(*keys));
  for (i = 0, sum = _SKEIN_C240; i < _SKEIN512_LENGTH; i++)
    sum ^= keys[i];
  keys_expanded[_SKEIN512_LENGTH] = sum;
  _skein512_block(output, keys_expanded, tweak, msg);
  if (memcmp (output, ref, sizeof(output)) != 0)
    {
      printf ("Skein 512 failed:\n");
      print_array("key", _SKEIN512_LENGTH, keys);
      print_array("tweak", _SKEIN_NTWEAK, tweak);
      printf ("msg: ");
      print_hex(SKEIN512_BLOCK_SIZE, msg);
      print_array("out", _SKEIN512_LENGTH, output);
      print_array("ref", _SKEIN512_LENGTH, ref);
      FAIL();
    }
}

void
test_main(void)
{
  /* From skein_golden_kat_short_internals.txt in
     http://www.skein-hash.info/sites/default/files/NIST_CD_102610.zip. */
  {
    static const uint64_t zeros[8] = {
      0, 0, 0, 0, 0, 0, 0, 0
    };
    static const uint64_t ref[_SKEIN512_LENGTH] = {
      0xBC2560EFC6BBA2B1ull,
      0xE3361F162238EB40ull,
      0xFB8631EE0ABBD175ull,
      0x7B9479D4C5479ED1ull,
      0xCFF0356E58F8C27Bull,
      0xB1B7B08430F0E7F7ull,
      0xE9A380A56139ABF1ull,
      0xBE7B6D4AA11EB47Eull,
    };
    test_skein512_block(zeros, zeros,
			H("0000000000000000 0000000000000000"
			  "0000000000000000 0000000000000000"
			  "0000000000000000 0000000000000000"
			  "0000000000000000 0000000000000000"),
			ref);
  }
  {
    static const uint64_t keys[8] = {
      0x1716151413121110ull,
      0x1F1E1D1C1B1A1918ull,
      0x2726252423222120ull,
      0x2F2E2D2C2B2A2928ull,
      0x3736353433323130ull,
      0x3F3E3D3C3B3A3938ull,
      0x4746454443424140ull,
      0x4F4E4D4C4B4A4948ull,
    };
    static const uint64_t tweak[2] = {
      0x0706050403020100ull,
      0x0F0E0D0C0B0A0908ull,
    };
    static const uint64_t ref[8] = {
      0xD4A32EDD6ABEFA1Cull,
      0x6AD5C4252C3FF743ull,
      0x35AC875BE2DED68Cull,
      0x99A6C774EA5CD06Cull,
      0xDCEC9C4251D7F4F8ull,
      0xF5761BCB3EF592AFull,
      0xFCABCB6A3212DF60ull,
      0xFD6EDE9FF9A2E14Eull,
    };
    test_skein512_block(keys, tweak,
			H("FFFEFDFCFBFAF9F8 F7F6F5F4F3F2F1F0"
			  "EFEEEDECEBEAE9E8 E7E6E5E4E3E2E1E0"
			  "DFDEDDDCDBDAD9D8 D7D6D5D4D3D2D1D0"
			  "CFCECDCCCBCAC9C8 C7C6C5C4C3C2C1C0"),
			ref);

  }
  {
    /* skein512 G0 = E(zeros, tweak, config string) */
    static const uint64_t zero_keys[_SKEIN512_LENGTH] = {
      0, 0, 0, 0, 0, 0, 0, 0,
    };
    static const uint64_t tweak[_SKEIN_NTWEAK] = {
      32, /* message length */
      0xc4ull << 56, /* first and final, type 4 */
    };
    static const uint64_t ref[_SKEIN512_LENGTH] = {
      0x4903ADFF749C51CEull, 0x0D95DE399746DF03ull,
      0x8FD1934127C79BCEull, 0x9A255629FF352CB1ull,
      0x5DB62599DF6CA7B0ull, 0xEABE394CA9D5C3F4ull,
      0x991112C71A75B523ull, 0xAE18A40B660FCC33ull,
    };
    test_skein512_block(zero_keys, tweak,
			H("5348413301000000 0002000000000000"
			  /* SHA3  v1       output bits (512) */
			  "0000000000000000 0000000000000000"
			  "0000000000000000 0000000000000000"
			  "0000000000000000 0000000000000000"),
			ref);
  }
}
