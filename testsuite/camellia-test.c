#include "testutils.h"
#include "camellia.h"

int
test_main(void)
{
  /* Test vectors from RFC 3713 */
  /* 128 bit keys */
  test_cipher(&nettle_camellia128,
	      HL("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
	      HL("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
	      H("67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43"));

  /* 192 bit keys */
  test_cipher(&nettle_camellia192, 
	      HL("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
                 "00 11 22 33 44 55 66 77"),
	      HL("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
	      H("b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9"));

  /* 256 bit keys */
  test_cipher(&nettle_camellia256, 
	      HL("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
                 "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"),
	      HL("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
	      H("9a cc 23 7d ff 16 d7 6c 20 ef 7c 91 9e 3a 75 09"));

  SUCCESS();
}
