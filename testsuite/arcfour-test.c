#include "testutils.h"
#include "arcfour.h"

int
main(int argc, char **argv)
{
  test_cipher(&nettle_arcfour128,
	      HL("01234567 89ABCDEF 00000000 00000000"),
	      HL("01234567 89ABCDEF"),
	      H("69723659 1B5242B1"));

  SUCCESS();
}
