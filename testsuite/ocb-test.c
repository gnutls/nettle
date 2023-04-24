#include "testutils.h"
#include "nettle-internal.h"

struct ocb_aes128_message_key
{
  struct ocb_aes128_encrypt_key encrypt_key;
  struct aes128_ctx decrypt_key;
};

static void
ocb_aes128_set_encrypt_key_wrapper (struct ocb_aes128_message_key *key,
				    const uint8_t *aes_key)
{
  ocb_aes128_set_encrypt_key (&key->encrypt_key, aes_key);
}
static void
ocb_aes128_set_decrypt_key_wrapper (struct ocb_aes128_message_key *key,
				    const uint8_t *aes_key)
{
  ocb_aes128_set_decrypt_key (&key->encrypt_key, &key->decrypt_key, aes_key);
}
static void
ocb_aes128_encrypt_message_wrapper (const struct ocb_aes128_message_key *key,
				    size_t nlength, const uint8_t *nonce,
				    size_t alength, const uint8_t *adata,
				    size_t clength, uint8_t *dst, const uint8_t *src)
{
  ocb_aes128_encrypt_message (&key->encrypt_key, nlength, nonce, alength, adata,
			      OCB_DIGEST_SIZE, clength, dst, src);
}
static int
ocb_aes128_decrypt_message_wrapper (const struct ocb_aes128_message_key *key,
				    size_t nlength, const uint8_t *nonce,
				    size_t alength, const uint8_t *adata,
				    size_t mlength, uint8_t *dst, const uint8_t *src)
{
  return ocb_aes128_decrypt_message (&key->encrypt_key, &key->decrypt_key,
				     nlength, nonce, alength, adata,
				     OCB_DIGEST_SIZE, mlength, dst, src);
}

static const struct nettle_aead_message
ocb_aes128_message = {
  "ocb_aes128",
  sizeof(struct ocb_aes128_message_key),
  AES128_KEY_SIZE,
  OCB_DIGEST_SIZE,
  1, /* Supports in-place operation. */
  (nettle_set_key_func*) ocb_aes128_set_encrypt_key_wrapper,
  (nettle_set_key_func*) ocb_aes128_set_decrypt_key_wrapper,
  (nettle_encrypt_message_func*) ocb_aes128_encrypt_message_wrapper,
  (nettle_decrypt_message_func*) ocb_aes128_decrypt_message_wrapper,
};

/* For 96-bit tag */
static void
set_nonce_tag96 (struct ocb_aes128_ctx *ctx, size_t length, const uint8_t *nonce)
{
  assert (length == OCB_NONCE_SIZE);
  ocb_aes128_set_nonce (&ctx->ocb, &ctx->key,
			12, OCB_NONCE_SIZE, nonce);
}

void
test_main(void)
{
  /* From RFC 7253 */
  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX(""), /* auth data */
	    SHEX(""), /* plaintext */
	    SHEX(""), /* ciphertext */
	    SHEX("BBAA99887766554433221100"), /* nonce */
	    SHEX("785407BFFFC8AD9EDCC5520AC9111EE6")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX("0001020304050607"), /* auth data */
	    SHEX("0001020304050607"), /* plaintext */
	    SHEX("6820B3657B6F615A"), /* ciphertext */
	    SHEX("BBAA99887766554433221101"), /* nonce */
	    SHEX("5725BDA0D3B4EB3A257C9AF1F8F03009")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX("0001020304050607"), /* auth data */
	    SHEX(""), /* plaintext */
	    SHEX(""), /* ciphertext */
	    SHEX("BBAA99887766554433221102"), /* nonce */
	    SHEX("81017F8203F081277152FADE694A0A00")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX(""), /* auth data */
	    SHEX("0001020304050607"), /* plaintext */
	    SHEX("45DD69F8F5AAE724"), /* ciphertext */
	    SHEX("BBAA99887766554433221103"), /* nonce */
	    SHEX("14054CD1F35D82760B2CD00D2F99BFA9")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* auth data */
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* plaintext */
	    SHEX("571D535B60B277188BE5147170A9A22C"), /* ciphertext */
	    SHEX("BBAA99887766554433221104"), /* nonce */
	    SHEX("3AD7A4FF3835B8C5701C1CCEC8FC3358")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* auth data */
	    SHEX(""), /* plaintext */
	    SHEX(""), /* ciphertext */
	    SHEX("BBAA99887766554433221105"), /* nonce */
	    SHEX("8CF761B6902EF764462AD86498CA6B97")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX(""), /* auth data */
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* plaintext */
	    SHEX("5CE88EC2E0692706A915C00AEB8B2396"), /* ciphertext */
	    SHEX("BBAA99887766554433221106"), /* nonce */
	    SHEX("F40E1C743F52436BDF06D8FA1ECA343D")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"), /* auth data */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"), /* plaintext */
	    SHEX("1CA2207308C87C010756104D8840CE1952F09673A448A122"), /* ciphertext */
	    SHEX("BBAA99887766554433221107"), /* nonce */
	    SHEX("C92C62241051F57356D7F3C90BB0E07F")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"), /* auth data */
	    SHEX(""), /* plaintext */
	    SHEX(""), /* ciphertext */
	    SHEX("BBAA99887766554433221108"), /* nonce */
	    SHEX("6DC225A071FC1B9F7C69F93B0F1E10DE")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX(""), /* auth data */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"), /* plaintext */
	    SHEX("221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3C"), /* ciphertext */
	    SHEX("BBAA99887766554433221109"), /* nonce */
	    SHEX("E725F32494B9F914D85C0B1EB38357FF")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"
		 "18191A1B1C1D1E1F"), /* auth data */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"
		 "18191A1B1C1D1E1F"), /* plaintext */
	    SHEX("BD6F6C496201C69296C11EFD138A467ABD3C707924B964DE"
		 "AFFC40319AF5A485"), /* ciphertext */
	    SHEX("BBAA9988776655443322110A"), /* nonce */
	    SHEX("40FBBA186C5553C68AD9F592A79A4240")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"
		 "18191A1B1C1D1E1F"), /* auth data */
	    SHEX(""), /* plaintext */
	    SHEX(""), /* ciphertext */
	    SHEX("BBAA9988776655443322110B"), /* nonce */
	    SHEX("FE80690BEE8A485D11F32965BC9D2A32")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX(""), /* auth data */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"
		 "18191A1B1C1D1E1F"), /* plaintext */
	    SHEX("2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF4"
		 "6040C53F1432BCDF"), /* ciphertext */
	    SHEX("BBAA9988776655443322110C"), /* nonce */
	    SHEX("B5E1DDE3BC18A5F840B52E653444D5DF")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"
		 "18191A1B1C1D1E1F2021222324252627"), /* auth data */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"
		 "18191A1B1C1D1E1F2021222324252627"), /* plaintext */
	    SHEX("D5CA91748410C1751FF8A2F618255B68A0A12E093FF45460"
		 "6E59F9C1D0DDC54B65E8628E568BAD7A"), /* ciphertext */
	    SHEX("BBAA9988776655443322110D"), /* nonce */
	    SHEX("ED07BA06A4A69483A7035490C5769E60")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"
		 "18191A1B1C1D1E1F2021222324252627"), /* auth data */
	    SHEX(""), /* plaintext */
	    SHEX(""), /* ciphertext */
	    SHEX("BBAA9988776655443322110E"), /* nonce */
	    SHEX("C5CD9D1850C141E358649994EE701B68")); /* tag */

  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX(""), /* auth data */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"
		 "18191A1B1C1D1E1F2021222324252627"), /* plaintext */
	    SHEX("4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15"
		 "A5DDBFC5787E50B5CC55EE507BCB084E"), /* ciphertext */
	    SHEX("BBAA9988776655443322110F"), /* nonce */
	    SHEX("479AD363AC366B95 A98CA5F3000B1479")); /* tag */

  /* Test with 96-bit tag. */
  test_aead(&nettle_ocb_aes128, (nettle_hash_update_func *) set_nonce_tag96,
	    SHEX("0F0E0D0C0B0A09080706050403020100"), /* key */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"
		 "18191A1B1C1D1E1F2021222324252627"), /* auth data */
	    SHEX("000102030405060708090A0B0C0D0E0F1011121314151617"
		 "18191A1B1C1D1E1F2021222324252627"), /* plaintext */
	    SHEX("1792A4E31E0755FB03E31B22116E6C2DDF9EFD6E33D536F1"
		 "A0124B0A55BAE884ED93481529C76B6A"), /* ciphertext */
	    SHEX("BBAA9988776655443322110D"), /* nonce */
	    SHEX("D0C515F4D1CDD4FDAC4F02AA")); /* tag */

  /* 16 blocks, not verified with other implementations or any
     authoritative test vector.not an authoritative test vector. */
  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX(""), /* auth data */
	    SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		 "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
		 "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
		 "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
		 "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
		 "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		 "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
		 "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
	    SHEX("4412923493c57d5d e0d700f753cce0d1"
		 "d2d95060122e9f15 a5ddbfc5787e50b5"
		 "11dfb888da244711 f051dbce82b0b9a7"
		 "cb14869b164e55eb 578e41fa435ff220"
		 "25ed114f6ec18cd6 7b743ab299e596f6"
		 "6100fba539db164d 765eaff0bf489ace"
		 "90ff6af96d1c395b 8dd586b154a0ecea"
		 "504395c5592cf2f0 03a3878585a0bfd3"
		 "b4039d15bc47a6d6 4a51f7302a976bb0"
		 "175167bcb5d8f071 a3faff70544ab2ba"
		 "52947d35d6e545e9 bda57b3972ecad10"
		 "f0e85aec389f4276 2e58978918d4c285"
		 "c2088ca8ac48095c 976065aa47766756"
		 "7a507bab08315b2e 36327e8103a6a70d"
		 "7f9f5318684697b2 bf95d65fa5458e6e"
		 "f40a974cb940e8fd 63baf0ce96773279"),
	    SHEX("BBAA9988776655443322110F"), /* nonce */
	    SHEX("3aa4f4e4b4ff142c 9357291589fa25d8")); /* tag */

  /* 16 complete blocks + left-over bytes, not verified with other
     implementations or any authoritative test vector. */
  test_aead(&nettle_ocb_aes128, NULL,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX(""), /* auth data */
	    SHEX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		 "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
		 "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
		 "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
		 "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
		 "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		 "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
		 "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
		 "deadbeaf"),
	    SHEX("4412923493c57d5d e0d700f753cce0d1"
		 "d2d95060122e9f15 a5ddbfc5787e50b5"
		 "11dfb888da244711 f051dbce82b0b9a7"
		 "cb14869b164e55eb 578e41fa435ff220"
		 "25ed114f6ec18cd6 7b743ab299e596f6"
		 "6100fba539db164d 765eaff0bf489ace"
		 "90ff6af96d1c395b 8dd586b154a0ecea"
		 "504395c5592cf2f0 03a3878585a0bfd3"
		 "b4039d15bc47a6d6 4a51f7302a976bb0"
		 "175167bcb5d8f071 a3faff70544ab2ba"
		 "52947d35d6e545e9 bda57b3972ecad10"
		 "f0e85aec389f4276 2e58978918d4c285"
		 "c2088ca8ac48095c 976065aa47766756"
		 "7a507bab08315b2e 36327e8103a6a70d"
		 "7f9f5318684697b2 bf95d65fa5458e6e"
		 "f40a974cb940e8fd 63baf0ce96773279"
		 "1dd97611"),
	    SHEX("BBAA9988776655443322110F"), /* nonce */
	    SHEX("8a24edb596b59425 43ec197d5369979b")); /* tag */

  /* Test the all-in-one message functions. */
  test_aead_message(&ocb_aes128_message,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX("BBAA99887766554433221100"), /* nonce */
	    SHEX(""), /* auth data */
	    SHEX(""), /* plaintext */
	    SHEX("785407BFFFC8AD9EDCC5520AC9111EE6"));

  test_aead_message(&ocb_aes128_message,
	    SHEX("000102030405060708090A0B0C0D0E0F"), /* key */
	    SHEX("BBAA99887766554433221101"), /* nonce */
	    SHEX("0001020304050607"), /* auth data */
	    SHEX("0001020304050607"), /* plaintext */
	    SHEX("6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009")); /* ciphertext */
}
