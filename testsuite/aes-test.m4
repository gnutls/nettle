#include "aes.h"

BEGIN_TEST

struct aes_ctx ctx;

uint8_t msg[AES_BLOCK_SIZE];
uint8_t cipher[AES_BLOCK_SIZE];
uint8_t clear[AES_BLOCK_SIZE];

/* 128 bit keys */
H(msg, "506812A45F08C889 B97F5980038B8359");

aes_set_key(&ctx, 16,  H("0001020305060708 0A0B0C0D0F101112"));
aes_encrypt(&ctx, AES_BLOCK_SIZE, cipher, msg);
if (!MEMEQ(16, cipher, H("D8F532538289EF7D 06B506A4FD5BE9C9")))
  FAIL;

aes_decrypt(&ctx, AES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(16, msg, clear))
  FAIL;

H(msg, "5C6D71CA30DE8B8B 00549984D2EC7D4B");

aes_set_key(&ctx, 16,  H("14151617191A1B1C 1E1F202123242526"));
aes_encrypt(&ctx, AES_BLOCK_SIZE, cipher, msg);
if (!MEMEQ(16, cipher, H("59AB30F4D4EE6E4F F9907EF65B1FB68C")))
  FAIL;

aes_decrypt(&ctx, AES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(16, msg, clear))
  FAIL;

H(msg, "53F3F4C64F8616E4 E7C56199F48F21F6");

aes_set_key(&ctx, 16,  H("28292A2B2D2E2F30 323334353738393A"));
aes_encrypt(&ctx, AES_BLOCK_SIZE, cipher, msg);
if (!MEMEQ(16, cipher, H("BF1ED2FCB2AF3FD4 1443B56D85025CB1")))
  FAIL;

aes_decrypt(&ctx, AES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(16, msg, clear))
  FAIL;

H(msg, "F5F4F7F684878689 A6A7A0A1D2CDCCCF");

aes_set_key(&ctx, 16,  H("A0A1A2A3A5A6A7A8 AAABACADAFB0B1B2"));
aes_encrypt(&ctx, AES_BLOCK_SIZE, cipher, msg);
if (!MEMEQ(16, cipher, H("CE52AF650D088CA5 59425223F4D32694")))
  FAIL;

aes_decrypt(&ctx, AES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(16, msg, clear))
  FAIL;

/* 192 bit keys */
H(msg, "2D33EEF2C0430A8A 9EBF45E809C40BB6");

aes_set_key(&ctx, 24,  H("0001020305060708 0A0B0C0D0F101112"
			 "14151617191A1B1C"));
aes_encrypt(&ctx, AES_BLOCK_SIZE, cipher, msg);
if (!MEMEQ(16, cipher, H("DFF4945E0336DF4C 1C56BC700EFF837F")))
  FAIL;

aes_decrypt(&ctx, AES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(16, msg, clear))
  FAIL;

/* 256 bit keys */
H(msg, "834EADFCCAC7E1B30664B1ABA44815AB");

aes_set_key(&ctx, 32,  H("0001020305060708 0A0B0C0D0F101112"
			 "14151617191A1B1C 1E1F202123242526"));
aes_encrypt(&ctx, AES_BLOCK_SIZE, cipher, msg);
if (!MEMEQ(16, cipher, H("1946DABF6A03A2A2 C3D0B05080AED6FC")))
  FAIL;

aes_decrypt(&ctx, AES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(16, msg, clear))
  FAIL;

/* This test case has been problematic with the CBC test case */
H(msg, "a5 ce 55 d4 21 15 a1 c6 4a a4 0c b2 ca a6 d1 37");

aes_set_key(&ctx, 32, H("8d ae 93 ff fc 78 c9 44"
			"2a bd 0c 1e 68 bc a6 c7"
			"05 c7 84 e3 5a a9 11 8b"
			"d3 16 aa 54 9b 44 08 9e"));

aes_encrypt(&ctx, AES_BLOCK_SIZE, cipher, msg);
/* In the cbc test, I once got the bad value
 *   "b2 a0 6c d2 2f df 7d 2c  26 d2 42 88 8f 20 74 a2" */
if (!MEMEQ(16, cipher, H("1f 94 fc 85 f2 36 21 06"
			 "4a ea e3 c9 cc 38 01 0e")))
  FAIL;

aes_decrypt(&ctx, AES_BLOCK_SIZE, clear, cipher);
if (!MEMEQ(16, msg, clear))
  FAIL;

/* From draft NIST spec on AES modes.

F.1 ECB Example Vectors
F.1.1 ECB-AES128-Encrypt

Key	2b7e151628aed2a6abf7158809cf4f3c
Block #1
Plaintext	6bc1bee22e409f96e93d7e117393172a
Input Block	6bc1bee22e409f96e93d7e117393172a
Output Block	3ad77bb40d7a3660a89ecaf32466ef97
Ciphertext	3ad77bb40d7a3660a89ecaf32466ef97
Block #2
Plaintext	ae2d8a571e03ac9c9eb76fac45af8e51
Input Block	ae2d8a571e03ac9c9eb76fac45af8e51
Output Block	f5d3d58503b9699de785895a96fdbaaf
Ciphertext	f5d3d58503b9699de785895a96fdbaaf
Block #3
Plaintext	30c81c46a35ce411e5fbc1191a0a52ef
Input Block	30c81c46a35ce411e5fbc1191a0a52ef
Output Block	43b1cd7f598ece23881b00e3ed030688
Ciphertext	43b1cd7f598ece23881b00e3ed030688
Block #4
Plaintext	f69f2445df4f9b17ad2b417be66c3710
Input Block	f69f2445df4f9b17ad2b417be66c3710
Output Block	7b0c785e27e8ad3f8223207104725dd4
Ciphertext	7b0c785e27e8ad3f8223207104725dd4

F.1.2 ECB-AES128-Decrypt
Key	2b7e151628aed2a6abf7158809cf4f3c
Block #1
Ciphertext	3ad77bb40d7a3660a89ecaf32466ef97
Input Block	3ad77bb40d7a3660a89ecaf32466ef97
Output Block	6bc1bee22e409f96e93d7e117393172a
Plaintext	6bc1bee22e409f96e93d7e117393172a
Block #2
Ciphertext	f5d3d58503b9699de785895a96fdbaaf
Input Block	f5d3d58503b9699de785895a96fdbaaf
Output Block	ae2d8a571e03ac9c9eb76fac45af8e51
Plaintext	ae2d8a571e03ac9c9eb76fac45af8e51
Block #3
Ciphertext	43b1cd7f598ece23881b00e3ed030688
Input Block	43b1cd7f598ece23881b00e3ed030688
Output Block	30c81c46a35ce411e5fbc1191a0a52ef
Plaintext	30c81c46a35ce411e5fbc1191a0a52ef
Block #4
Ciphertext	7b0c785e27e8ad3f8223207104725dd4
Input Block	7b0c785e27e8ad3f8223207104725dd4
Output Block	f69f2445df4f9b17ad2b417be66c3710
Plaintext	f69f2445df4f9b17ad2b417be66c3710

F.1.3 ECB-AES192-Encrypt
Key	8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
Block #1
Plaintext	6bc1bee22e409f96e93d7e117393172a
Input Block	6bc1bee22e409f96e93d7e117393172a
Output Block	bd334f1d6e45f25ff712a214571fa5cc
Ciphertext	bd334f1d6e45f25ff712a214571fa5cc
Block #2
Plaintext	ae2d8a571e03ac9c9eb76fac45af8e51
Input Block	ae2d8a571e03ac9c9eb76fac45af8e51
Output Block	974104846d0ad3ad7734ecb3ecee4eef
Ciphertext	974104846d0ad3ad7734ecb3ecee4eef
Block #3
Plaintext	30c81c46a35ce411e5fbc1191a0a52ef
Input Block	30c81c46a35ce411e5fbc1191a0a52ef
Output Block	ef7afd2270e2e60adce0ba2face6444e
Ciphertext	ef7afd2270e2e60adce0ba2face6444e
Block #4
Plaintext	f69f2445df4f9b17ad2b417be66c3710
Input Block	f69f2445df4f9b17ad2b417be66c3710
Output Block	9a4b41ba738d6c72fb16691603c18e0e
Ciphertext	9a4b41ba738d6c72fb16691603c18e0e

F.1.4 ECB-AES192-Decrypt
Key	8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
Block #1
Ciphertext	bd334f1d6e45f25ff712a214571fa5cc
Input Block	bd334f1d6e45f25ff712a214571fa5cc
Output Block	6bc1bee22e409f96e93d7e117393172a
Plaintext	6bc1bee22e409f96e93d7e117393172a
Block #2
Ciphertext	974104846d0ad3ad7734ecb3ecee4eef
Input Block	974104846d0ad3ad7734ecb3ecee4eef
Output Block	ae2d8a571e03ac9c9eb76fac45af8e51
Plaintext	ae2d8a571e03ac9c9eb76fac45af8e51
Block #3
Ciphertext	ef7afd2270e2e60adce0ba2face6444e
Input Block	ef7afd2270e2e60adce0ba2face6444e
Output Block	30c81c46a35ce411e5fbc1191a0a52ef
Plaintext	30c81c46a35ce411e5fbc1191a0a52ef
Block #4
Ciphertext	9a4b41ba738d6c72fb16691603c18e0e
Input Block	9a4b41ba738d6c72fb16691603c18e0e
Output Block	f69f2445df4f9b17ad2b417be66c3710
Plaintext	f69f2445df4f9b17ad2b417be66c3710

F.1.5 ECB-AES256-Encrypt
Key	603deb1015ca71be2b73aef0857d7781
	1f352c073b6108d72d9810a30914dff4
Block #1
Plaintext	6bc1bee22e409f96e93d7e117393172a
Input Block	6bc1bee22e409f96e93d7e117393172a
Output Block	f3eed1bdb5d2a03c064b5a7e3db181f8
Ciphertext	f3eed1bdb5d2a03c064b5a7e3db181f8
Block #2
Plaintext	ae2d8a571e03ac9c9eb76fac45af8e51
Input Block	ae2d8a571e03ac9c9eb76fac45af8e51
Output Block	591ccb10d410ed26dc5ba74a31362870
Ciphertext	591ccb10d410ed26dc5ba74a31362870
Block #3
Plaintext	30c81c46a35ce411e5fbc1191a0a52ef
Input Block	30c81c46a35ce411e5fbc1191a0a52ef
Output Block	b6ed21b99ca6f4f9f153e7b1beafed1d
Ciphertext	b6ed21b99ca6f4f9f153e7b1beafed1d
Block #4
Plaintext	f69f2445df4f9b17ad2b417be66c3710
Input Block	f69f2445df4f9b17ad2b417be66c3710
Output Block	23304b7a39f9f3ff067d8d8f9e24ecc7
Ciphertext	23304b7a39f9f3ff067d8d8f9e24ecc7

F.1.6 ECB-AES256-Decrypt
Key	603deb1015ca71be2b73aef0857d7781
	1f352c073b6108d72d9810a30914dff4
Block #1
Ciphertext	f3eed1bdb5d2a03c064b5a7e3db181f8
Input Block	f3eed1bdb5d2a03c064b5a7e3db181f8
Output Block	6bc1bee22e409f96e93d7e117393172a
Plaintext	6bc1bee22e409f96e93d7e117393172a
Block #2
Ciphertext	591ccb10d410ed26dc5ba74a31362870
Input Block	591ccb10d410ed26dc5ba74a31362870
Output Block	ae2d8a571e03ac9c9eb76fac45af8e51
Plaintext	ae2d8a571e03ac9c9eb76fac45af8e51
Block #3
Ciphertext	b6ed21b99ca6f4f9f153e7b1beafed1d
Input Block	b6ed21b99ca6f4f9f153e7b1beafed1d
Output Block	30c81c46a35ce411e5fbc1191a0a52ef
Plaintext	30c81c46a35ce411e5fbc1191a0a52ef
Block #4
Ciphertext	23304b7a39f9f3ff067d8d8f9e24ecc7
Input Block	23304b7a39f9f3ff067d8d8f9e24ecc7
Output Block	f69f2445df4f9b17ad2b417be66c3710
Plaintext	f69f2445df4f9b17ad2b417be66c3710
*/
