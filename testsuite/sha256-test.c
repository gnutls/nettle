#include "testutils.h"
#include "sha.h"

int
main(int argc, char **argv)
{
  test_hash(&nettle_sha256, 3, "abc",
	    H("ba7816bf8f01cfea 414140de5dae2223"
	      "b00361a396177a9c b410ff61f20015ad"));

  test_hash(&nettle_sha256, 56,
	    "abcdbcdecdefdefgefghfghighij"
	    "hijkijkljklmklmnlmnomnopnopq",
	    H("248d6a61d20638b8 e5c026930c3e6039"
	      "a33ce45964ff2167 f6ecedd419db06c1"));

  test_hash(&nettle_sha256, 112,
	    "abcdefghbcdefghicdefghijdefg"
	    "hijkefghijklfghijklmghijklmn"
	    "hijklmnoijklmnopjklmnopqklmn"
	    "opqrlmnopqrsmnopqrstnopqrstu",
	    H("cf5b16a778af8380 036ce59e7b049237"
	      "0b249b11e8f07a51 afac45037afee9d1"));

    SUCCESS();
}
