#include "testutils.h"
#include "hmac.h"

int
test_main(void)
{
  struct hmac_md5_ctx md5;
  struct hmac_sha1_ctx sha1;
  struct hmac_sha256_ctx sha256;

  /* sha256's digests are longest */
  uint8_t digest[SHA256_DIGEST_SIZE];

  memset(digest, 0, sizeof(digest));
  
  /* Test vectors for md5, from RFC-2202 */
  hmac_md5_set_key(&md5, HL("0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b"));
  hmac_md5_update(&md5, LDATA("Hi There"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("9294727a3638bb1c 13f48ef8158bfc9d")))
    FAIL();

  hmac_md5_set_key(&md5, LDATA("Jefe"));
  hmac_md5_update(&md5, LDATA("what do ya want for nothing?"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("750c783e6ab0b503 eaa86e310a5db738")))
    FAIL();

  hmac_md5_set_key(&md5, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_md5_update(&md5, HL("dddddddddddddddd dddddddddddddddd"
			   "dddddddddddddddd dddddddddddddddd"
			   "dddddddddddddddd dddddddddddddddd"
			   "dddd"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("56BE34521D144C88 DBB8C733F0E8B3F6")))
    FAIL();
  
  hmac_md5_set_key(&md5, HL("0102030405060708 090a0b0c0d0e0f10" 
			    "1112131415161718 19"));
  hmac_md5_update(&md5, HL("cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			   "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			   "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd"
			   "cdcd"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("697eaf0aca3a3aea3a75164746ffaa79")))
    FAIL();

  memset(digest, 0, MD5_DIGEST_SIZE);
  hmac_md5_set_key(&md5, HL("0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c" ));
  hmac_md5_update(&md5, LDATA("Test With Truncation"));
  hmac_md5_digest(&md5, 12, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("56461ef2342edc00f9bab99500000000")))
    FAIL();

  hmac_md5_set_key(&md5, HL("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
			    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"));
  hmac_md5_update(&md5,
		  LDATA("Test Using Larger Than Block-Size Key - Hash Key First"));
  hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);

  if (!MEMEQ(MD5_DIGEST_SIZE, digest,
	     H("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd")))
    FAIL();

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
	     H("6f630fad67cda0ee1fb1f562db3aa53e")))
    FAIL();

  SUCCESS();
}
