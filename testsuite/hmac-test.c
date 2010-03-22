#include "testutils.h"
#include "hmac.h"

int
test_main(void)
{
  struct hmac_md5_ctx md5;
  struct hmac_sha1_ctx sha1;
  struct hmac_sha256_ctx sha256;
  struct hmac_sha512_ctx sha512;

  /* sha512's digests are longest */
  uint8_t digest[SHA512_DIGEST_SIZE];

  memset(digest, 0, sizeof(digest));

  /* Test vectors for md5, from RFC-2202 */

  /* md5 - 1 */
  hmac_md5_set_key(&md5, HL("0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b"));
  hmac_md5_update(&md5, LDATA("Hi There"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("9294727a3638bb1c 13f48ef8158bfc9d")))
    FAIL();

  /* md5 - 2 */
  hmac_md5_set_key(&md5, LDATA("Jefe"));
  hmac_md5_update(&md5, LDATA("what do ya want for nothing?"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("750c783e6ab0b503 eaa86e310a5db738")))
    FAIL();

  /* md5 - 3 */
  hmac_md5_set_key(&md5, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_md5_update(&md5, HL("dddddddddddddddd dddddddddddddddd"
			   "dddddddddddddddd dddddddddddddddd"
			   "dddddddddddddddd dddddddddddddddd"
			   "dddd"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("56be34521d144c88 dbb8c733f0e8b3f6")))
    FAIL();

  /* md5 - 4 */
  hmac_md5_set_key(&md5, HL("0102030405060708 090a0b0c0d0e0f10" 
			    "1112131415161718 19"));
  hmac_md5_update(&md5, HL("cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			   "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			   "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			   "cdcd"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("697eaf0aca3a3aea 3a75164746ffaa79")))
    FAIL();

  /* md5 - 5 */
  memset(digest, 0, MD5_DIGEST_SIZE);
  hmac_md5_set_key(&md5, HL("0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c" ));
  hmac_md5_update(&md5, LDATA("Test With Truncation"));
  hmac_md5_digest(&md5, 12, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("56461ef2342edc00 f9bab99500000000")))
    FAIL();

  /* md5 - 6 */
  hmac_md5_set_key(&md5, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_md5_update(&md5,
		  LDATA("Test Using Larger Than Block-Size Key - Hash Key First"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("6b1ab7fe4bd7bf8f 0b62e6ce61b9d0cd")))
    FAIL();

  /* md5 - 7 */
  hmac_md5_set_key(&md5, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_md5_update(&md5,
		  LDATA("Test Using Larger Than Block-Size Key and Larger "
			"Than One Block-Size Data"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("6f630fad67cda0ee 1fb1f562db3aa53e")))
    FAIL();


  /* Test vectors for sha1, from RFC-2202 */

  /* sha1 - 1 */
  hmac_sha1_set_key(&sha1, HL("0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b 0b0b0b0b"));
  hmac_sha1_update(&sha1, LDATA("Hi There"));
  hmac_sha1_digest(&sha1, SHA1_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("b617318655057264 e28bc0b6fb378c8e f146be00")))
    FAIL();

  /* sha1 - 2 */
  hmac_sha1_set_key(&sha1, LDATA("Jefe"));
  hmac_sha1_update(&sha1, LDATA("what do ya want for nothing?"));
  hmac_sha1_digest(&sha1, SHA1_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("effcdf6ae5eb2fa2 d27416d5f184df9c 259a7c79")))
    FAIL();

  /* sha1 - 3 */
  hmac_sha1_set_key(&sha1, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaa"));
  hmac_sha1_update(&sha1, HL("dddddddddddddddd dddddddddddddddd"
			     "dddddddddddddddd dddddddddddddddd"
			     "dddddddddddddddd dddddddddddddddd"
			     "dddd"));
  hmac_sha1_digest(&sha1, SHA1_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("125d7342b9ac11cd 91a39af48aa17b4f 63f175d3")))
    FAIL();

  /* sha1 - 4 */
  hmac_sha1_set_key(&sha1, HL("0102030405060708 090a0b0c0d0e0f10" 
			      "1112131415161718 19"));
  hmac_sha1_update(&sha1, HL("cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			     "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			     "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			     "cdcd"));
  hmac_sha1_digest(&sha1, SHA1_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("4c9007f4026250c6 bc8414f9bf50c86c 2d7235da")))
    FAIL();

  /* sha1 - 5 */
  memset(digest, 0, SHA1_DIGEST_SIZE);
  hmac_sha1_set_key(&sha1, HL("0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c 0c0c0c0c"));
  hmac_sha1_update(&sha1, LDATA("Test With Truncation"));
  hmac_sha1_digest(&sha1, 12, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("4c1a03424b55e07f e7f27be100000000 00000000")))
    FAIL();

  /* sha1 - 6 */
  hmac_sha1_set_key(&sha1, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_sha1_update(&sha1,
		   LDATA("Test Using Larger Than Block-Size Key - Hash Key First"));
  hmac_sha1_digest(&sha1, SHA1_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("aa4ae5e15272d00e 95705637ce8a3b55 ed402112")))
    FAIL();

  /* sha1 - 7 */
  hmac_sha1_set_key(&sha1, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			      "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_sha1_update(&sha1,
		  LDATA("Test Using Larger Than Block-Size Key and Larger "
			"Than One Block-Size Data"));
  hmac_sha1_digest(&sha1, SHA1_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA1_DIGEST_SIZE, digest,
	     H("e8e99d0f45237d78 6d6bbaa7965c7808 bbff1a91")))
    FAIL();


  /* Test vectors for sha256, from draft-ietf-ipsec-ciph-sha-256-01.txt */

  /* Test Case #1: HMAC-SHA-256 with 3-byte input and 32-byte key */
  hmac_sha256_set_key(&sha256, HL("0102030405060708 090a0b0c0d0e0f10"
				  "1112131415161718 191a1b1c1d1e1f20"));
  hmac_sha256_update(&sha256, LDATA("abc"));
  hmac_sha256_digest(&sha256, SHA256_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	     H("a21b1f5d4cf4f73a 4dd939750f7a066a"
	       "7f98cc131cb16a66 92759021cfab8181")))
    FAIL();

  /* Test Case #2: HMAC-SHA-256 with 56-byte input and 32-byte key */
  hmac_sha256_set_key(&sha256, HL("0102030405060708 090a0b0c0d0e0f10"
				  "1112131415161718 191a1b1c1d1e1f20"));
  hmac_sha256_update(&sha256, LDATA("abcdbcdecdefdefgefghfghighijhijk"
				    "ijkljklmklmnlmnomnopnopq"));
  hmac_sha256_digest(&sha256, SHA256_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	     H("104fdc1257328f08 184ba73131c53cae"
	       "e698e36119421149 ea8c712456697d30")))
    FAIL();

  /* Test Case #3: HMAC-SHA-256 with 112-byte (multi-block) input
     and 32-byte key */
  hmac_sha256_set_key(&sha256, HL("0102030405060708 090a0b0c0d0e0f10"
				  "1112131415161718 191a1b1c1d1e1f20"));
  hmac_sha256_update(&sha256, LDATA("abcdbcdecdefdefgefghfghighijhijk"
				    "ijkljklmklmnlmnomnopnopqabcdbcde"
				    "cdefdefgefghfghighijhijkijkljklm"
				    "klmnlmnomnopnopq"));
  hmac_sha256_digest(&sha256, SHA256_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	     H("470305fc7e40fe34 d3eeb3e773d95aab"
	       "73acf0fd060447a5 eb4595bf33a9d1a3")))
    FAIL();

  /* Test Case #4:  HMAC-SHA-256 with 8-byte input and 32-byte key */
  hmac_sha256_set_key(&sha256, HL("0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b"
				  "0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b"));
  hmac_sha256_update(&sha256, LDATA("Hi There"));
  hmac_sha256_digest(&sha256, SHA256_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	     H("198a607eb44bfbc6 9903a0f1cf2bbdc5"
	       "ba0aa3f3d9ae3c1c 7a3b1696a0b68cf7")))
    FAIL();

  /* Test Case #5:  HMAC-SHA-256 with 28-byte input and 4-byte key */
  hmac_sha256_set_key(&sha256, LDATA("Jefe"));
  hmac_sha256_update(&sha256, LDATA("what do ya want for nothing?"));
  hmac_sha256_digest(&sha256, SHA256_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	     H("5bdcc146bf60754e 6a042426089575c7"
	       "5a003f089d273983 9dec58b964ec3843")))
    FAIL();

  /* Test Case #6: HMAC-SHA-256 with 50-byte input and 32-byte key */
  hmac_sha256_set_key(&sha256, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
				  "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_sha256_update(&sha256, HL("dddddddddddddddd dddddddddddddddd"
				 "dddddddddddddddd dddddddddddddddd"
				 "dddddddddddddddd dddddddddddddddd"
				 "dddd"));
  hmac_sha256_digest(&sha256, SHA256_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	     H("cdcb1220d1ecccea 91e53aba3092f962"
	       "e549fe6ce9ed7fdc 43191fbde45c30b0")))
    FAIL();

  /* Test Case #7: HMAC-SHA-256 with 50-byte input and 37-byte key */
  hmac_sha256_set_key(&sha256, HL("0102030405060708 090a0b0c0d0e0f10"
				  "1112131415161718 191a1b1c1d1e1f20"
				  "2122232425"));
  hmac_sha256_update(&sha256, HL("cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
				 "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
				 "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
				 "cdcd"));
  hmac_sha256_digest(&sha256, SHA256_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	     H("d4633c17f6fb8d74 4c66dee0f8f07455"
	       "6ec4af55ef079985 41468eb49bd2e917")))
    FAIL();

  /* Test Case #8: HMAC-SHA-256 with 20-byte input and 32-byte key */
  memset(digest, 0, SHA256_DIGEST_SIZE);
  hmac_sha256_set_key(&sha256, HL("0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c"
				  "0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c"));
  hmac_sha256_update(&sha256, LDATA("Test With Truncation"));
  hmac_sha256_digest(&sha256, 16, digest);

  if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	     H("7546af01841fc09b 1ab9c3749a5f1c17"
	       "0000000000000000 0000000000000000")))
    FAIL();

  /* Test Case #9: HMAC-SHA-256 with 54-byte input and 80-byte key */
  hmac_sha256_set_key(&sha256, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
				  "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
				  "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
				  "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
				  "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_sha256_update(&sha256, LDATA(
    "Test Using Larger Than Block-Size Key - Hash Key First"));
  hmac_sha256_digest(&sha256, SHA256_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	     H("6953025ed96f0c09 f80a96f78e6538db"
	       "e2e7b820e3dd970e 7ddd39091b32352f")))
    FAIL();

  /* Test Case #10: HMAC-SHA-256 with 73-byte (multi-block) input
     and 80-byte key */
  hmac_sha256_set_key(&sha256, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
				  "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
				  "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
				  "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
				  "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_sha256_update(&sha256, LDATA(
    "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"));
  hmac_sha256_digest(&sha256, SHA256_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA256_DIGEST_SIZE, digest,
	     H("6355ac22e890d0a3 c8481a5ca4825bc8"
	       "84d3e7a1ff98a2fc 2ac7d8e064c3b2e6")))
    FAIL();

  /* Test vectors for sha512, from draft-kelly-ipsec-ciph-sha2-01.txt */

  /* Test case AUTH512-1: */
  hmac_sha512_set_key(&sha512, HL("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
				  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
				  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
				  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));
  hmac_sha512_update(&sha512, LDATA("Hi There"));
  hmac_sha512_digest(&sha512, SHA512_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA512_DIGEST_SIZE, digest,
	     H("637edc6e01dce7e6742a99451aae82df"
	       "23da3e92439e590e43e761b33e910fb8"
	       "ac2878ebd5803f6f0b61dbce5e251ff8"
	       "789a4722c1be65aea45fd464e89f8f5b")))
    FAIL();

  /* Test case AUTH512-2: */
  hmac_sha512_set_key(&sha512, LDATA("JefeJefeJefeJefe"
				     "JefeJefeJefeJefe"
				     "JefeJefeJefeJefe"
				     "JefeJefeJefeJefe"));
  hmac_sha512_update(&sha512, LDATA("what do ya want for nothing?"));
  hmac_sha512_digest(&sha512, SHA512_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA512_DIGEST_SIZE, digest,
	     H("cb370917ae8a7ce28cfd1d8f4705d614"
	       "1c173b2a9362c15df235dfb251b15454"
	       "6aa334ae9fb9afc2184932d8695e397b"
	       "fa0ffb93466cfcceaae38c833b7dba38")))
    FAIL();

  /* Test case AUTH512-3: */
  hmac_sha512_set_key(&sha512, HL("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
  hmac_sha512_update(&sha512, HL("dddddddddddddddddddddddddddddddd"
				 "dddddddddddddddddddddddddddddddd"
				 "dddddddddddddddddddddddddddddddd"
				 "dddd"));
  hmac_sha512_digest(&sha512, SHA512_DIGEST_SIZE, digest);

  if (!MEMEQ(SHA512_DIGEST_SIZE, digest,
	     H("2ee7acd783624ca9398710f3ee05ae41"
	       "b9f9b0510c87e49e586cc9bf961733d8"
	       "623c7b55cebefccf02d5581acc1c9d5f"
	       "b1ff68a1de45509fbe4da9a433922655")))
    FAIL();

  /* Test case AUTH512-3 from same document seems broken. */

  SUCCESS();
}
