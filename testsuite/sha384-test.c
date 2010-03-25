#include "testutils.h"
#include "sha.h"

int
test_main(void)
{
  test_hash(&nettle_sha384, 3, "abc",
	    H("cb00753f45a35e8b b5a03d699ac65007"
	      "272c32ab0eded163 1a8b605a43ff5bed"
	      "8086072ba1e7cc23 58baeca134c825a7"));
  
  test_hash(&nettle_sha384, 112,
	    "abcdefghbcdefghicdefghijdefg"
	    "hijkefghijklfghijklmghijklmn"
	    "hijklmnoijklmnopjklmnopqklmn"
	    "opqrlmnopqrsmnopqrstnopqrstu",
	    H("09330c33f71147e8 3d192fc782cd1b47"
	      "53111b173b3b05d2 2fa08086e3b0f712"
	      "fcc7c71a557e2db9 66c3e9fa91746039"));

    SUCCESS();
}
