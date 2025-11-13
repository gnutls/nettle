#include "testutils.h"

#include "non-nettle.h"

void
test_main(void)
{
  test_hash(&nettle_blake2b_512, SDATA("abc"),
	    SHEX("BA 80 A5 3F 98 1C 4D 0D 6A 27 97 B6 9F 12 F6 E9"
		 "4C 21 2F 14 68 5A C4 B7 4B 12 BB 6F DB FF A2 D1"
		 "7D 87 C5 39 2A AB 79 2D C2 52 D5 DE 45 33 CC 95"
		 "18 D3 8A A8 DB F1 92 5A B9 23 86 ED D4 00 99 23"));
}
