#include "testutils.h"
#include "sha.h"

int
test_main(void)
{
  test_hash(&nettle_sha512, 3, "abc",
	    H("ddaf35a193617aba cc417349ae204131"
	      "12e6fa4e89a97ea2 0a9eeee64b55d39a"
	      "2192992a274fc1a8 36ba3c23a3feebbd"
	      "454d4423643ce80e 2a9ac94fa54ca49f"));
  
  test_hash(&nettle_sha512, 112,
	    "abcdefghbcdefghicdefghijdefg"
	    "hijkefghijklfghijklmghijklmn"
	    "hijklmnoijklmnopjklmnopqklmn"
	    "opqrlmnopqrsmnopqrstnopqrstu",
	    H("8e959b75dae313da 8cf4f72814fc143f"
	      "8f7779c6eb9f7fa1 7299aeadb6889018"
	      "501d289e4900f7e4 331b99dec4b5433a"
	      "c7d329eeb6dd2654 5e96e55b874be909"));

    SUCCESS();
}
