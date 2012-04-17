#include "testutils.h"
#include "salsa20.h"

#include "memxor.h"

static int
memzero_p (const uint8_t *p, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++)
    if (p[i])
      return 0;
  return 1;
}

/* The ecrypt testcases encrypt 512 zero bytes (8 blocks), then give
   the xor of all blocks, and the data for block 0 (0-43), 3,4
   (192-319), 7 (448-511) */

#define STREAM_LENGTH 512
static void
test_salsa20_stream(unsigned key_length,
		    const uint8_t *key,
		    const uint8_t *iv,
		    const uint8_t *ciphertext,
		    const uint8_t *xor_ref)
{
  struct salsa20_ctx ctx;
  uint8_t data[STREAM_LENGTH + 1];
  uint8_t stream[STREAM_LENGTH + 1];
  uint8_t xor[SALSA20_BLOCK_SIZE];
  unsigned j;

  salsa20_set_key(&ctx, key_length, key);
  salsa20_set_iv(&ctx, iv);
  memset(stream, 0, STREAM_LENGTH + 1);
  salsa20_crypt(&ctx, STREAM_LENGTH, stream, stream);
  if (stream[STREAM_LENGTH])
    {
      fprintf(stderr, "Stream of %d bytes wrote too much!\n", STREAM_LENGTH);
      FAIL();
    }
  if (!MEMEQ (64, stream, ciphertext))
    {
      fprintf(stderr, "Error failed, offset 0:\n");
      fprintf(stderr, "\nOutput: ");
      print_hex(64, stream);
      fprintf(stderr, "\nExpected:");
      print_hex(64, ciphertext);
      fprintf(stderr, "\n");
      FAIL();
    }
  if (!MEMEQ (128, stream + 192, ciphertext + 64))
    {
      fprintf(stderr, "Error failed, offset 192:\n");
      fprintf(stderr, "\nOutput: ");
      print_hex(128, stream + 192);
      fprintf(stderr, "\nExpected:");
      print_hex(64, ciphertext + 64);
      fprintf(stderr, "\n");
      FAIL();
    }
  if (!MEMEQ (64, stream + 448, ciphertext + 192))
    {
      fprintf(stderr, "Error failed, offset 448:\n");
      fprintf(stderr, "\nOutput: ");
      print_hex(64, stream + 448);
      fprintf(stderr, "\nExpected:");
      print_hex(64, ciphertext + 192);
      fprintf(stderr, "\n");
      FAIL();
    }

  memxor3 (xor, stream, stream + SALSA20_BLOCK_SIZE, SALSA20_BLOCK_SIZE);
  for (j = 2*SALSA20_BLOCK_SIZE; j < STREAM_LENGTH; j += SALSA20_BLOCK_SIZE)
    memxor (xor, stream + j, SALSA20_BLOCK_SIZE);

  if (!MEMEQ (SALSA20_BLOCK_SIZE, xor, xor_ref))
    {
      fprintf(stderr, "Error failed, bad xor 448:\n");
      fprintf(stderr, "\nOutput: ");
      print_hex(SALSA20_BLOCK_SIZE, xor);
      fprintf(stderr, "\nExpected:");
      print_hex(SALSA20_BLOCK_SIZE, xor_ref);
      fprintf(stderr, "\n");
      FAIL();
    }

  for (j = 1; j <= STREAM_LENGTH; j++)
    {
      memset(data, 0, STREAM_LENGTH + 1);
      salsa20_set_iv(&ctx, iv);
      salsa20_crypt(&ctx, j, data, data);

      if (!MEMEQ(j, data, stream))
	{
	  fprintf(stderr, "Encrypt failed for length %u:\n", j);
	  fprintf(stderr, "\nOutput: ");
	  print_hex(j, data);
	  fprintf(stderr, "\nExpected:");
	  print_hex(j, stream);
	  fprintf(stderr, "\n");
	  FAIL();
	}
      if (!memzero_p (data + j, STREAM_LENGTH + 1 - j))
	{
	  fprintf(stderr, "Encrypt failed for length %u, wrote too much:\n", j);
	  fprintf(stderr, "\nOutput: ");
	  print_hex(STREAM_LENGTH + 1 - j, data + j);
	  fprintf(stderr, "\n");
	  FAIL();
	}
    }
}

static void
test_salsa20(unsigned key_length,
	     const uint8_t *key,
	     const uint8_t *iv,
	     unsigned length,
	     const uint8_t *cleartext,
	     const uint8_t *ciphertext)
{
  struct salsa20_ctx ctx;
  uint8_t *data = xalloc(length + 1);

  salsa20_set_key(&ctx, key_length, key);
  salsa20_set_iv(&ctx, iv);
  data[length] = 17;
  salsa20_crypt(&ctx, length, data, cleartext);
  if (data[length] != 17)
    {
      fprintf(stderr, "Encrypt of %u bytes wrote too much!\nInput:", length);
      print_hex(length, cleartext);
      fprintf(stderr, "\n");
      FAIL();
    }
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
  salsa20_set_iv(&ctx, iv);
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
	       H("00000000 00000000"),
	       HL("00000000 00000000"),
	       H("4DFA5E48 1DA23EA0"));

  test_salsa20(HL("00000000 00000000 00000000 00000000"),
	       H("80000000 00000000"),
	       HL("00000000 00000000"),
	       H("B66C1E44 46DD9557"));

  test_salsa20(HL("0053A6F94C9FF24598EB3E91E4378ADD"),
	       H("0D74DB42A91077DE"),
	       HL("00000000 00000000"),
	       H("05E1E7BE B697D999"));

  test_salsa20(HL("80000000 00000000 00000000 00000000"
		  "00000000 00000000 00000000 00000000"),
	       H("00000000 00000000"),
	       HL("00000000 00000000"),
	       H("E3BE8FDD 8BECA2E3"));

  test_salsa20(HL("00000000 00000000 00000000 00000000"
		  "00000000 00000000 00000000 00000000"),
	       H("80000000 00000000"),
	       HL("00000000 00000000"),
	       H("2ABA3DC45B494700"));

  test_salsa20(HL("0053A6F94C9FF24598EB3E91E4378ADD"
		  "3083D6297CCF2275C81B6EC11467BA0D"),
	       H("0D74DB42A91077DE"),
	       HL("00000000 00000000"),
	       H("F5FAD53F 79F9DF58"));

  test_salsa20_stream(HL("80000000000000000000000000000000"),
		      H("00000000 00000000"),
		      H("4DFA5E481DA23EA09A31022050859936"
			"DA52FCEE218005164F267CB65F5CFD7F"
			"2B4F97E0FF16924A52DF269515110A07"
			"F9E460BC65EF95DA58F740B7D1DBB0AA"
			"DA9C1581F429E0A00F7D67E23B730676"
			"783B262E8EB43A25F55FB90B3E753AEF"
			"8C6713EC66C51881111593CCB3E8CB8F"
			"8DE124080501EEEB389C4BCB6977CF95"
			"7D5789631EB4554400E1E025935DFA7B"
			"3E9039D61BDC58A8697D36815BF1985C"
			"EFDF7AE112E5BB81E37ECF0616CE7147"
			"FC08A93A367E08631F23C03B00A8DA2F"
			"B375703739DACED4DD4059FD71C3C47F"
			"C2F9939670FAD4A46066ADCC6A564578"
			"3308B90FFB72BE04A6B147CBE38CC0C3"
			"B9267C296A92A7C69873F9F263BE9703"),
		      H("F7A274D268316790A67EC058F45C0F2A"
			"067A99FCDE6236C0CEF8E056349FE54C"
			"5F13AC74D2539570FD34FEAB06C57205"
			"3949B59585742181A5A760223AFA22D4"));

  test_salsa20_stream(HL("48494A4B4C4D4E4F5051525354555657"
			 "58595A5B5C5D5E5F6061626364656667"),
		      H("0000000000000000"),
		      H("53AD3698A011F779AD71030F3EFBEBA0"
			"A7EE3C55789681B1591EF33A7BE521ED"
			"68FC36E58F53FFD6E1369B00E390E973"
			"F656ACB097E0D603BE59A0B8F7975B98"
			"A04698274C6AC6EC03F66ED3F94C08B7"
			"9FFDBF2A1610E6F5814905E73AD6D0D2"
			"8164EEB8450D8ED0BB4B644761B43512"
			"52DD5DDF00C31E3DABA0BC17691CCFDC"
			"B826C7F071E796D34E3BFFB3C96E76A1"
			"209388392806947C7F19B86D379FA3AE"
			"DFCD19EBF49803DACC6E577E5B97B0F6"
			"D2036B6624D8196C96FCF02C865D30C1"
			"B505D41E2C207FA1C0A0E93413DDCFFC"
			"9BECA8030AFFAC2466E56482DA0EF428"
			"E63880B5021D3051F18679505A2B9D4F"
			"9B2C5A2D271D276DE3F51DBEBA934436"),
		      H("7849651A820B1CDFE36D5D6632716534"
			"E0635EDEFD538122D80870B60FB055DB"
			"637C7CA2B78B116F83AFF46E40F8F71D"
			"4CD6D2E1B750D5E011D1DF2E80F7210A"));

  SUCCESS();
}
