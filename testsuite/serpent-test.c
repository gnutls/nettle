#include "testutils.h"
#include "serpent.h"

int
main(int argc, char **argv)
{
  /* The first test for each key size from the ecb_vk.txt and ecb_vt.txt
   * files in the serpent package. */

  /* 128 bit key */

  /* vk, 1 */
  test_cipher(&nettle_serpent128,
	      HL("8000000000000000 0000000000000000"),
	      HL("0000000000000000 0000000000000000"),
	      H("49AFBFAD9D5A3405 2CD8FFA5986BD2DD"));

  /* vt, 1 */
  test_cipher(&nettle_serpent128,
	      HL("0000000000000000 0000000000000000"),
	      HL("8000000000000000 0000000000000000"),
	      H("10B5FFB720B8CB90 02A1142B0BA2E94A"));

  /* 192 bit key */

  /* vk, 1 */
  test_cipher(&nettle_serpent192,
	      HL("8000000000000000 0000000000000000"
		 "0000000000000000"),
	      HL("0000000000000000 0000000000000000"),
	      H("E78E5402C7195568 AC3678F7A3F60C66"));

  /* vt, 1 */
  test_cipher(&nettle_serpent192,
	      HL("0000000000000000 0000000000000000"
		 "0000000000000000"),
	      HL("8000000000000000 0000000000000000"),
	      H("B10B271BA25257E1 294F2B51F076D0D9"));

  /* 256 bit key */

  /* vk, 1 */
  test_cipher(&nettle_serpent256,
	      HL("8000000000000000 0000000000000000"
		 "0000000000000000 0000000000000000"),
	      HL("0000000000000000 0000000000000000"),
	      H("ABED96E766BF28CB C0EBD21A82EF0819"));

  /* vt, 1 */
  test_cipher(&nettle_serpent256,
	      HL("0000000000000000 0000000000000000"
		 "0000000000000000 0000000000000000"),
	      HL("8000000000000000 0000000000000000"),
	      H("DA5A7992B1B4AE6F 8C004BC8A7DE5520"));

  SUCCESS();
}
