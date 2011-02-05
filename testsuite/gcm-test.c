#include "testutils.h"
#include "aes.h"
#include "gcm.h"

int
test_main(void)
{
  /* 
   * GCM-AES Test Vectors from
   * htt://www.cryptobarn.com/papers/gcm-spec.pdf
   */

  /* Test case 1 */
  test_cipher_gcm(&nettle_aes128,
		  /* key */HL("00000000000000000000000000000000"),
		  /* auth data */ HL(""),
		  /* plaintext */HL(""),
		  /* ciphertext*/H(""),
		  /* IV */HL("000000000000000000000000"),
		  /* tag */H("58e2fccefa7e3061367f1d57a4e7455a"));

  /* Test case 2 */
  test_cipher_gcm(&nettle_aes128,
		  HL("00000000000000000000000000000000"),
		  HL(""),
		  HL("00000000000000000000000000000000"),
		  H("0388dace60b6a392f328c2b971b2fe78"),
		  HL("000000000000000000000000"),
		  H("ab6e47d42cec13bdf53a67b21257bddf"));

  /* Test case 3 */
  test_cipher_gcm(&nettle_aes128,
		  HL("feffe9928665731c6d6a8f9467308308"),
		  HL(""),
		  HL("d9313225f88406e5a55909c5aff5269a"
		     "86a7a9531534f7da2e4c303d8a318a72"
		     "1c3c0c95956809532fcf0e2449a6b525"
		     "b16aedf5aa0de657ba637b391aafd255"),
		  H("42831ec2217774244b7221b784d0d49c"
		    "e3aa212f2c02a4e035c17e2329aca12e"
		    "21d514b25466931c7d8f6a5aac84aa05"
		    "1ba30b396a0aac973d58e091473f5985"),
		  HL("cafebabefacedbaddecaf888"),
		  H("4d5c2af327cd64a62cf35abd2ba6fab4"));

  /* Test case 4 */
  test_cipher_gcm(&nettle_aes128,
		  HL("feffe9928665731c6d6a8f9467308308"),
		  HL("feedfacedeadbeeffeedfacedeadbeef"
		     "abaddad2"),
		  HL("d9313225f88406e5a55909c5aff5269a"
		     "86a7a9531534f7da2e4c303d8a318a72"
		     "1c3c0c95956809532fcf0e2449a6b525"
		     "b16aedf5aa0de657ba637b39"),
		  H("42831ec2217774244b7221b784d0d49c"
		    "e3aa212f2c02a4e035c17e2329aca12e"
		    "21d514b25466931c7d8f6a5aac84aa05"
		    "1ba30b396a0aac973d58e091"),
		  HL("cafebabefacedbaddecaf888"),
		  H("5bc94fbc3221a5db94fae95ae7121a47"));

#if 0
  /* Unsupported IV size. */
  /* Test case 5 */
  test_cipher_gcm(&nettle_aes128,
		  HL("feffe9928665731c6d6a8f9467308308"),
		  HL("feedfacedeadbeeffeedfacedeadbeef"
		     "abaddad2"),
		  HL("d9313225f88406e5a55909c5aff5269a"
		     "86a7a9531534f7da2e4c303d8a318a72"
		     "1c3c0c95956809532fcf0e2449a6b525"
		     "b16aedf5aa0de657ba637b39"),
		  HL("cafebabefacedbad"),
		  H("61353b4c2806934a777ff51fa22a4755"
		    "699b2a714fcdc6f83766e5f97b6c7423"
		    "73806900e49f24b22b097544d4896b42"
		    "4989b5e1ebac0f07c23f4598"),
		  H("3612d2e79e3b0785561be14aaca2fccb"));

  /* Test case 6 */
  test_cipher_gcm(&nettle_aes128,
		  HL("feffe9928665731c6d6a8f9467308308"),
		  HL("feedfacedeadbeeffeedfacedeadbeef"
		     "abaddad2"),
                  HL("d9313225f88406e5a55909c5aff5269a"
		     "86a7a9531534f7da2e4c303d8a318a72"
		     "1c3c0c95956809532fcf0e2449a6b525"
		     "b16aedf5aa0de657ba637b39"),
		  H("8ce24998625615b603a033aca13fb894"
		    "be9112a5c3a211a8ba262a3cca7e2ca7"
		    "01e4a9a4fba43c90ccdcb281d48c7c6f"
		    "d62875d2aca417034c34aee5"),
		  HL("9313225df88406e555909c5aff5269aa"
		     "6a7a9538534f7da1e4c303d2a318a728"
		     "c3c0c95156809539fcf0e2429a6b5254"
		     "16aedbf5a0de6a57a637b39b"),
		  H("619cc5aefffe0bfa462af43c1699d050"));
  

#endif
  SUCCESS();
}

