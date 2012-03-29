#include "testutils.h"
#include "salsa20.h"

static void
test_salsa20(unsigned key_length,
	     const uint8_t *key,
	     unsigned iv_length,
	     const uint8_t *iv,
	     unsigned length,
	     const uint8_t *cleartext,
	     const uint8_t *ciphertext)
{
  struct salsa20_ctx ctx;
  uint8_t *data = xalloc(length);

  salsa20_set_key(&ctx, key_length, key);
  salsa20_set_iv(&ctx, iv_length, iv);
  salsa20_crypt(&ctx, length, data, cleartext);

  if (!MEMEQ(length, data, ciphertext))
    {
      fprintf(stderr, "Encrypt failed:\nInput:");
      print_hex(length, cleartext);
      fprintf(stderr, "\nOutput: ");
      print_hex(length, data);
      fprintf(stderr, "\nExpected:");
      print_hex(length, ciphertext);
      fprintf(stderr, "\n");
      FAIL();
    }
  salsa20_set_key(&ctx, key_length, key);
  salsa20_set_iv(&ctx, iv_length, iv);
  salsa20_crypt(&ctx, length, data, data);

  if (!MEMEQ(length, data, cleartext))
    {
      fprintf(stderr, "Decrypt failed:\nInput:");
      print_hex(length, ciphertext);
      fprintf(stderr, "\nOutput: ");
      print_hex(length, data);
      fprintf(stderr, "\nExpected:");
      print_hex(length, cleartext);
      fprintf(stderr, "\n");
      FAIL();
    }

  free(data);
}
  
int
test_main(void)
{
  /* http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/salsa20/full/verified.test-vectors?logsort=rev&rev=210&view=markup */

  test_salsa20(HL("80000000 00000000 00000000 00000000"),
	       HL("00000000 00000000"),
	       HL("00000000 00000000"),
	       H("4DFA5E48 1DA23EA0"));

  test_salsa20(HL("00000000 00000000 00000000 00000000"),
	       HL("80000000 00000000"),
	       HL("00000000 00000000"),
	       H("B66C1E44 46DD9557"));

  test_salsa20(HL("0053A6F94C9FF24598EB3E91E4378ADD"),
	       HL("0D74DB42A91077DE"),
	       HL("00000000 00000000"),
	       H("05E1E7BE B697D999"));

  test_salsa20(HL("80000000 00000000 00000000 00000000"
		  "00000000 00000000 00000000 00000000"),
	       HL("00000000 00000000"),
	       HL("00000000 00000000"),
	       H("E3BE8FDD 8BECA2E3"));

  test_salsa20(HL("00000000 00000000 00000000 00000000"
		  "00000000 00000000 00000000 00000000"),
	       HL("80000000 00000000"),
	       HL("00000000 00000000"),
	       H("2ABA3DC45B494700"));

  test_salsa20(HL("0053A6F94C9FF24598EB3E91E4378ADD"
		  "3083D6297CCF2275C81B6EC11467BA0D"),
	       HL("0D74DB42A91077DE"),
	       HL("00000000 00000000"),
	       H("F5FAD53F 79F9DF58"));

  SUCCESS();
}
