#include "testutils.h"

#include "non-nettle.h"

void
test_main(void)
{
  test_hash(&nettle_blake2s_256, SDATA("abc"),
	    SHEX("50 8C 5E 8C 32 7C 14 E2 E1 A7 2B A3 4E EB 45 2F"
		 "37 45 8B 20 9E D6 3A 29 4D 99 9B 4C 86 67 59 82"));
}
