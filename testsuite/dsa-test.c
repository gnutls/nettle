#include "testutils.h"

int
test_main(void)
{
  struct dsa_public_key pub;
  struct dsa_private_key key;

  dsa_public_key_init(&pub);
  dsa_private_key_init(&key);

  mpz_set_str(pub.p,
	      "83d9a7c2ce2a9179f43cdb3bffe7de0f0eef26dd5dfae44d"
	      "531bc0de45634d2c07cb929b0dbe10da580070e6abfbb841"
	      "5c44bff570b8ad779df653aad97dc7bdeb815d7e88103e61"
	      "606ed3d8a295fbfd340d2d49e220833ebace5511e22c4f02"
	      "97ed351e9948fa848e9c8fadb7b47bcc47def4255b5e1d5e"
	      "10215b3b55a0b85f", 16);
  mpz_set_str(pub.q,
	      "8266e0deaf46020ba48d410ca580f3a978629b5d", 16);
  mpz_set_str(pub.g,
	      "30d34bb9f376bec947154afe4076bc7d359c9d32f5471ddb"
	      "be8d6a941c47fa9dc4f32573151dbb4aa59eb989b74ac36b"
	      "b6310a5e8b580501655d91f393daa193ae1303049b87febb"
	      "093dc0404b53b4c5da2463300f9c5b156d788c4ace8ecbb9"
	      "dd00c18d99537f255ac025d074d894a607cbe3023a1276ef"
	      "556916a33f7de543", 16);
  mpz_set_str(pub.y,
	      "64402048b27f39f404a546a84909c9c0e9e2dd153a849946"
	      "1062892598d30af27ae3cefc2b700fb6d077390a83bdcad7"
	      "8a1299487c9623bb62af0c85a3df9ef1ee2c0d66658e1fd3"
	      "283b5407f6cd30ee7e6154fad41a6a8b0f5c86c5accc1127"
	      "bf7c9a5d6badcb012180cb62a55c5e17d6d3528cdbe002cc"
	      "ee131c1b86867f7a", 16);
  mpz_set_str(key.x,
	      "56c6efaf878d06eef21dc070fab71da6ec1e30a6", 16);

  test_dsa_key(&pub, &key);
  
  test_dsa(&pub, &key);

  dsa_public_key_clear(&pub);
  dsa_private_key_clear(&key);

  SUCCESS();
}
