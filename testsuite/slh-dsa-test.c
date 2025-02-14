/* slh-dsa-test.c

   Copyright (C) 2025 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#include "testutils.h"

#include "sha3.h"
#include "slh-dsa.h"
#include "slh-dsa-internal.h"
#include "bswap-internal.h"

static void
test_wots_gen (const struct tstring *public_seed, const struct tstring *secret_seed,
	       unsigned layer, uint64_t tree_idx, uint32_t keypair,
	       const struct tstring *exp_pub)
{
  struct slh_address_tree at = {0};
  uint8_t pub[_SLH_DSA_128_SIZE];
  ASSERT (public_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (secret_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (exp_pub->length == _SLH_DSA_128_SIZE);

  at.layer = bswap32_if_le (layer);
  at.tree_idx = bswap64_if_le (tree_idx);
  _wots_gen (public_seed->data, secret_seed->data, &at, keypair, pub);
  ASSERT (MEMEQ (sizeof (pub), pub, exp_pub->data));
}

static void
test_wots_sign (const struct tstring *public_seed, const struct tstring *secret_seed,
		unsigned layer, uint64_t tree_idx, uint32_t keypair, const struct tstring *msg,
		const struct tstring *exp_pub, const struct tstring *exp_sig)
{
  struct slh_address_tree at = {0};
  uint8_t sig[WOTS_SIGNATURE_SIZE];
  uint8_t pub[_SLH_DSA_128_SIZE];
  ASSERT (public_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (secret_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (msg->length == _SLH_DSA_128_SIZE);
  ASSERT (exp_pub->length == _SLH_DSA_128_SIZE);
  ASSERT (exp_sig->length == WOTS_SIGNATURE_SIZE);

  at.layer = bswap32_if_le (layer);
  at.tree_idx = bswap64_if_le (tree_idx);

  _wots_sign (public_seed->data, secret_seed->data, &at, keypair,
	      msg->data, sig, pub);
  ASSERT (MEMEQ(sizeof(sig), sig, exp_sig->data));
  ASSERT (MEMEQ(sizeof(pub), pub, exp_pub->data));

  memset (pub, 0, sizeof(pub));
  _wots_verify (public_seed->data, &at, keypair, msg->data, sig, pub);
  ASSERT (MEMEQ(sizeof(pub), pub, exp_pub->data));
}

/* The xmss_leaf and xmss_node functions copied from slh-xmss.c */
static void
xmss_leaf (const struct slh_merkle_ctx_secret *ctx, unsigned idx, uint8_t *leaf)
{
  _wots_gen (ctx->pub.seed, ctx->secret_seed, &ctx->pub.at, idx, leaf);
}

static void
xmss_node (const struct slh_merkle_ctx_public *ctx, unsigned height, unsigned index,
	   const uint8_t *left, const uint8_t *right, uint8_t *out)
{
  struct sha3_256_ctx sha3;
  struct slh_address_hash ah =
    {
      bswap32_if_le (SLH_XMSS_TREE),
      0,
      bswap32_if_le (height),
      bswap32_if_le (index),
    };

  _slh_shake_init (&sha3, ctx->seed, &ctx->at, &ah);
  sha3_256_update (&sha3, _SLH_DSA_128_SIZE, left);
  sha3_256_update (&sha3, _SLH_DSA_128_SIZE, right);
  sha3_256_shake (&sha3, _SLH_DSA_128_SIZE, out);
}

static void
test_merkle (const struct tstring *public_seed, const struct tstring *secret_seed,
	     unsigned layer, uint64_t tree_idx, uint32_t idx, const struct tstring *msg,
	     const struct tstring *exp_pub, const struct tstring *exp_sig)
{
  struct slh_merkle_ctx_secret ctx =
    {
      {
	public_seed->data,
	{ bswap32_if_le(layer), 0, bswap64_if_le(tree_idx) },
	0,
      },
      secret_seed->data,
    };

  uint8_t sig[XMSS_AUTH_SIZE];
  uint8_t pub[_SLH_DSA_128_SIZE];
  ASSERT (public_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (secret_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (msg->length == _SLH_DSA_128_SIZE);
  ASSERT (exp_pub->length == _SLH_DSA_128_SIZE);
  ASSERT (exp_sig->length == XMSS_AUTH_SIZE);

  _merkle_sign (&ctx, xmss_leaf, xmss_node, XMSS_H, idx, sig);
  ASSERT (MEMEQ(sizeof(sig), sig, exp_sig->data));

  memcpy (pub, msg->data, sizeof(pub));
  _merkle_verify (&ctx.pub, xmss_node, XMSS_H, idx, sig, pub);
  ASSERT (MEMEQ(sizeof(pub), pub, exp_pub->data));
}

static void
test_fors_gen(const struct tstring *public_seed, const struct tstring *secret_seed,
	      unsigned layer, uint64_t tree_idx, unsigned keypair, unsigned idx,
	      const struct tstring *exp_sk, const struct tstring *exp_leaf)
{
  struct slh_merkle_ctx_secret ctx =
    {
      {
	public_seed->data,
	{ bswap32_if_le(layer), 0, bswap64_if_le(tree_idx) },
	keypair,
      },
      secret_seed->data,
    };
  uint8_t sk[_SLH_DSA_128_SIZE];
  uint8_t leaf[_SLH_DSA_128_SIZE];
  ASSERT (public_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (secret_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (exp_sk->length == _SLH_DSA_128_SIZE);
  ASSERT (exp_leaf->length == _SLH_DSA_128_SIZE);

  _fors_gen (&ctx, idx, sk, leaf);
  ASSERT (MEMEQ(sizeof(sk), sk, exp_sk->data));
  ASSERT (MEMEQ(sizeof(leaf), leaf, exp_leaf->data));
}

static void
test_fors_sign (const struct tstring *public_seed, const struct tstring *secret_seed,
		unsigned layer, uint64_t tree_idx, unsigned keypair, const struct tstring *msg,
		const struct tstring *exp_pub, const struct tstring *exp_sig)
{
  struct slh_merkle_ctx_secret ctx =
    {
      {
	public_seed->data,
	{ bswap32_if_le(layer), 0, bswap64_if_le(tree_idx) },
	keypair,
      },
      secret_seed->data,
    };
  uint8_t pub[_SLH_DSA_128_SIZE];
  uint8_t sig[FORS_SIGNATURE_SIZE];
  ASSERT (public_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (secret_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (msg->length == FORS_MSG_SIZE);
  ASSERT (exp_pub->length == _SLH_DSA_128_SIZE);
  ASSERT (exp_sig->length == FORS_SIGNATURE_SIZE);

  _fors_sign (&ctx, msg->data, sig, pub);
  ASSERT (MEMEQ(sizeof(sig), sig, exp_sig->data));
  ASSERT (MEMEQ(sizeof(pub), pub, exp_pub->data));

  memset (pub, 0, sizeof(pub));
  _fors_verify (&ctx.pub, msg->data, sig, pub);
  ASSERT (MEMEQ(sizeof(pub), pub, exp_pub->data));
}

static void
test_xmss_gen(const struct tstring *public_seed, const struct tstring *secret_seed,
	      const struct tstring *exp_pub)
{
  uint8_t pub[_SLH_DSA_128_SIZE];
  ASSERT (public_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (secret_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (exp_pub->length == _SLH_DSA_128_SIZE);

  _xmss_gen (public_seed->data, secret_seed->data, pub);
  ASSERT (MEMEQ(sizeof(pub), pub, exp_pub->data));
}

static void
test_xmss_sign (const struct tstring *public_seed, const struct tstring *secret_seed,
		unsigned layer, uint64_t tree_idx, uint32_t idx, const struct tstring *msg,
		const struct tstring *exp_pub, const struct tstring *exp_sig)
{
  struct slh_merkle_ctx_secret ctx =
    {
      {
	public_seed->data,
	{ bswap32_if_le(layer), 0, bswap64_if_le(tree_idx) },
	0,
      },
      secret_seed->data,
    };

  uint8_t sig[XMSS_SIGNATURE_SIZE];
  uint8_t pub[_SLH_DSA_128_SIZE];
  ASSERT (public_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (secret_seed->length == _SLH_DSA_128_SIZE);
  ASSERT (msg->length == _SLH_DSA_128_SIZE);
  ASSERT (exp_pub->length == _SLH_DSA_128_SIZE);
  ASSERT (exp_sig->length == XMSS_SIGNATURE_SIZE);

  _xmss_sign (&ctx, idx, msg->data, sig, pub);
  ASSERT (MEMEQ(sizeof(sig), sig, exp_sig->data));
  ASSERT (MEMEQ(sizeof(pub), pub, exp_pub->data));

  memset (pub, 0, sizeof(pub));
  _xmss_verify (&ctx.pub, idx, msg->data, sig, pub);
  ASSERT (MEMEQ(sizeof(pub), pub, exp_pub->data));
}

static void
test_slh_dsa_shake_128s(const struct tstring *pub, const struct tstring *priv,
			const struct tstring *msg, const struct tstring *exp_sig)
{
  uint8_t sig[SLH_DSA_SHAKE_128S_SIGNATURE_SIZE];
  ASSERT (pub->length == SLH_DSA_SHAKE_128S_KEY_SIZE);
  ASSERT (priv->length == SLH_DSA_SHAKE_128S_KEY_SIZE);
  ASSERT (exp_sig->length == SLH_DSA_SHAKE_128S_SIGNATURE_SIZE);

  slh_dsa_shake_128s_sign (pub->data, priv->data, msg->length, msg->data, sig);
  if (! MEMEQ(sizeof(sig), sig, exp_sig->data))
    {
      size_t i;
      for (i = 0; i < sizeof(sig); i++)
	if (sig[i] != exp_sig->data[i])
	  break;

      fprintf (stderr, "failed slh_dsa_shake_128s_sign, first diff at %zd\n", i);
      abort ();
    }
  ASSERT (slh_dsa_shake_128s_verify (pub->data, msg->length, msg->data, sig));

  if (msg->length > 0)
    ASSERT (!slh_dsa_shake_128s_verify (pub->data, msg->length-1, msg->data, sig));
  sig[SLH_DSA_SHAKE_128S_SIGNATURE_SIZE-1] ^= 1;
  ASSERT (!slh_dsa_shake_128s_verify (pub->data, msg->length, msg->data, sig));
}

void
test_main(void)
{
  const struct tstring *public_seed =
    SHEX("b505d7cfad1b497499323c8686325e47");

  const struct tstring *secret_seed =
    SHEX("7c9935a0b07694aa0c6d10e4db6b1add");

  test_wots_gen (public_seed, secret_seed, 6, 0, 0,
		 SHEX("38c9077d76d1e32933fb58a53e769ed7"));
  test_wots_gen (public_seed, secret_seed, 6, 0, 1,
		 SHEX("a026afacc77c7d97eebe6f88c70fec2d"));
  test_wots_gen (public_seed, secret_seed, 0, UINT64_C(0x29877722d7c079), 0x156,
		 SHEX("99747c3547770fa288a628ed15122d3e"));

  test_wots_sign (public_seed, secret_seed, 0, UINT64_C(0x29877722d7c079), 0x156,
		  SHEX("3961b2cab15e08c633be827744a07f01"),
		  SHEX("99747c3547770fa288a628ed15122d3e"),
		  SHEX("e1933de10e3fface 5fb8f8707c35ac13 74dc14ee8518481c 7e63d936ecc62f50"
		       "c7f951b87bc716dc 45e9bcfec6f6d97e 7fafdacb6db05ed3 778f21851f325e25"
		       "470da8dd81c41223 6d66cbee9ffa9c50 b86aa40baf213494 dfacca22aa0fb479"
		       "53928735ca4212cf 53a09ab0335d20a8 e62ede797c8e7493 54d636f15f3150c5"
		       "52797b76c091a41f 949f7fb57b42f744 1cca410264d6421f 4aa2c7e2ff4834a8"
		       "db0e6e7750b2e11f f1c89a42d1fbc271 8358e38325886ad1 2346cd694f9eab73"
		       "46c9a23b5ebe7637 bfd834a412318b01 188b0f29e3bd979f 8ae734acf1563af3"
		       "03d3c095e9eaeba3 5207b9df3acf9ee4 7da5c1e2652f3b86 41698f3d2260591b"
		       "07d00565e5d6be18 36033d2b7ef2c33b dc5cf3bba95b42df 6f73345b835341b2"
		       "50e2862c9f2f9cef 77cfa74cfb04c560 d8a0038c4e96cb0d a2b3e9b2cd3cecf5"
		       "22fda0d67e5f62b2 ee23bd42a61c7da4 8f0ea30b81af7ccb 6bb02cde272d2574"
		       "1325e9d91535615c 0184f2d7f226141d 79b42412721fd345 61d93663650b3c1b"
		       "6901872bc4c0bb15 bcd9038950b7717f 7f448b6126592076 a2bad2d63c55399c"
		       "243fdbdb0c8d676b 2ae455e7f0a9b18d 3fc889c43387f2cb c4dc73d7c85bfab6"
		       "b4b04463a3dd359c 3a8f61bfa6c4b042 4aeba4dd8a95ec12 43b2e36c29f82e1d"
		       "711281599b3e05e7 5492ae3425eaa7f1 4ff8c6a9630bba6e bd236f195269a481"
		       "e87eb3d444825ba4 424ee5b2d9efb595 d5a338f4c253f79d e9d04535206ca6db"
		       "c2d4c9a1ec20849b 0db3fbe10c1446d5"));

  test_merkle (public_seed, secret_seed, 0, UINT64_C(0x29877722d7c079), 0x156,
	       /* The message signed is the wots public key. */
	       SHEX("99747c3547770fa288a628ed15122d3e"),
	       SHEX("1be9523f2c90cd553ef5be5aa1c5c4fa"),
	       SHEX("612d5bac915a3996 2cdbcacee0969dcf 8ecfb830cea2206c 37749c65b8f673db"
		    "090b1e2ade6c2a2f 349b5915103a3ac7 8482c39e99ffc462 6fb4cf4a116804ab"
		    "9d93d7104660fefa 0753cf875cb22fd6 0e55dc2f303de036 47712b12067a55f7"
		    "a467897bbed0d3a0 9d50e9deaadff78d e9ac65c1fd05d076 10a79c8c465141ad"
		    "65e60340531fab08 f1f433ef823283fe"));

  test_fors_gen (public_seed, secret_seed, 0, UINT64_C(0x29877722d7c079), 0x156, 0x203,
		 SHEX("1ba66d6f782bdd2485589ea15d2b8ff0"),
		 SHEX("4d9783fd544a53ee7a485ef229b35965"));
  test_fors_gen (public_seed, secret_seed, 0, UINT64_C(0x29877722d7c079), 0x156, 0,
		 SHEX("be19da5abd01818bbcae2fc2d728c83b"),
		 SHEX("40b0edc79104214adda356341b3950ab"));
  test_fors_gen (public_seed, secret_seed, 0, UINT64_C(0x29877722d7c079), 0x156, 1,
		 SHEX("ed98099d2fd9d94ac48cae4c142a4c78"),
		 SHEX("64fccb8a3cf088faeb39353aad5f624c"));
  test_fors_gen (public_seed, secret_seed, 0, UINT64_C(0x29877722d7c079), 0x156, 0x4e1e,
		 SHEX("17f55905e41a6dc6e5bab2c9f0c1d5d3"),
		 SHEX("15325ef3d2914cbd401327244cdb633d"));
  test_fors_sign (public_seed, secret_seed, 0, UINT64_C(0x29877722d7c079), 0x156,
		  SHEX("2033c1a4df6fc230c699522a21bed913"
		       "0dda231526"),
		  SHEX("3961b2cab15e08c633be827744a07f01"),
		  SHEX("1ba66d6f782bdd24 85589ea15d2b8ff0 a00c06eaedc8c22d cb86f3df8b52a3bd"
		       "144d4ed6f1167431 a95dc6018879b6b0 f9813797204ec2b0 558bad17b32e6dd9"
		       "88086a032c0acbcf 2c1349ffc16c4af7 59365ff74afe4b8d c3fac5b2cda7ba65"
		       "6c36c086e58468c0 1eddfc959fbdc853 2d75e79cf3374756 cc0491cfef555921"
		       "ec8567bff0b6f216 ac4a4f200da63b5c 6d3a5c3273aa7a42 66adf083d3126103"
		       "c73fe63a6e05e47e 8b9a520f00f32a69 7d0ff3a5ee840931 3773188f300b39e5"
		       "b4967febf77c0f23 226785ee9dce335c efb1ce84b0673058 1bcef4d45f24aee4"
		       "96a60bd4759b7b20 692241850eae1de7 0c7c4287b9f3b962 a66e0f23d1301b84"
		       "48bb3dc545be0ef8 d0ec0be045d33ae4 b2dc0c5d002c2699 e8f49bf3bcb13676"
		       "beefe11186a20a95 7027ac48ee6dd33b c0895df9847fd1c6 7a753777d21ac464"
		       "2751139061cca836 99822c13567833b9 41fe5954bff0969a 4b20e0829d77e24e"
		       "d0e02a00a2ce9f7e 64923fa61f0da1af dc5978dc063afeac b7108ee08aaa55b7"
		       "11df00bbf1c71d69 8b389e6ad0ee2af4 fad1d8f8c87d53ee ac1f82a162a95cd5"
		       "cce6dfc9908a1de3 3a2b26b41bbc4ffd a8e136879f10341a 713d62c107f3238c"
		       "38693aff2e1fe15a dd8380671b2fac8f db3a4ffacd143f5a 00e21caccbe7d95d"
		       "4c31c4daf7110529 de599fb6e8aa4f71 8c6172f4f10c4c1d d7310f8e44d18fb9"
		       "bb6b906ae7ce973d eadfc82d6704762e d61165f6ca118313 4b6c834bf6b4e4ce"
		       "19700bb54fb2d0f2 82b11ee5b7f68c72 cf32ff9e7d1356bd 53fdcce0d03c43d0"
		       "ebf6f7d8841a16dd b49944d01374ecb9 45e6c5f0659d5f51 de0b27a834e2e7be"
		       "a78a609da75d7f2c 6a40ba9110a2c331 9db7775bf6226b9a 8e324dc4411824a8"
		       "8db95cc2fd96e4bc 24f1ecb6ce2b9293 020c28deacec1eb3 313d4e3dfd24b403"
		       "686f16272cac3aca 95080257071a54f7 45ffb4708ff2d02d e94d7e9bf8d45f64"
		       "5917c7135d6bc0a1 ca0a99bc4e33a689 07aa65a58b586c56 e1d81af6cb57fa5d"
		       "56b3567687ecef53 2bb5aaaf2041b510 1538294296ae4c11 89a5100eb19b5531"
		       "2016c575cbbb688f 20ba186dd48e4161 64c29b2eb7b59979 814b5a8e76553997"
		       "99bf79eeab3ee76d 4c97df282265564f 2fa8971a1ecca0c4 6b59cc6ba253531c"
		       "17ab7125cf2aad60 a120c7d4b631b1ba f187182c7d7582da 3232251215ffd6a2"
		       "a55c627ba8d5cafe 761504d8341f293e 713987d6e0ca2eab 373c5131c2d38051"
		       "c35b17918937b9fe e98382c277640de0 ccec45ba22d9d189 eea505a21c8594dd"
		       "9b12e69a7faf58ed 269b718abeea4621 391d7fb4c6e0037b daf4a9ac73191674"
		       "9e2a17d704cf5616 8d97c17b257e2483 16aa9da15d822ee3 c325bc0519173641"
		       "7007ea82088618d7 531ffcef255b2de2 bf9fcaeb29d83e56 7a08dd3d3c229209"
		       "af96ba71d8274fda e324702878d99ac0 5e990e0d6f34c879 d19279f57541f294"
		       "96645cad4a636793 385b0a5dc21d5659 37fc36384dea4beb b5746c10748efcbd"
		       "6b1925a74e3ac467 d7af456e0ba1e47a 2fab24e8311c14d8 40b499c9140e99a4"
		       "993379b9b762b3ad c9499d5c86d07bc6 a159876a9962d8a4 43514e812f75c60d"
		       "c50028388c627329 6e7208a3fa618256 2d10d7142a99da06 86ef8f05e564446c"
		       "6bb32ffdee9edd13 aee58027d29e7195 48b67d75efe9581a 3374c66f65a1cd9e"
		       "f9e98e6b57c40321 2739df6fd2de6c8a 39decc7cd33e37db 3a0f43296cb987e8"
		       "756d4b29dc227733 bdee1d2f01679dab 92ce506e2fc77a70 798787b2e95be8e9"
		       "bf80d0b64af8eaa6 ceda80fe85a0ceaf 81f335b99a1899a3 d9d609e7ba606eb2"
		       "ababf2bbce1bc8f9 9eaf6074cf1c7e07 9896eb09827c16d0 cd4833377c46a337"
		       "a7950b31b6566624 02e8ba838668a315 ac531315a9a56af1 8729ee25f53711c0"
		       "9d25c173aa0e4d2b ec72db4b9cb4210d 52a8fb2f8b2671b1 ec711a4da8a357df"
		       "bb0d2ec9734a50e1 db92352ace0f26f5 0cfb76fd17a08dec bb19c2417a9dc719"
		       "f2ecac4a8e7c4827 5533def5c08788dc 4b47ec81960b25a5 7dba2762f5a07003"
		       "7c50a4883fe902eb cb1574998dd5e8b1 e34ea5aea20bbbef fdb5d6163688e4e1"
		       "bdc9619f12b78d20 e8c073f81da8bbe4 8bde8934bc7186da 9d29d1f670a322bf"
		       "9febca92915e393c 1878895c04b8c365 e4d399ac551a55c5 4264e3fc6176cbcd"
		       "101790863cdab395 74a4dd5c9edd69a0 1df20a10e5abff31 b4e204f5cf7e1dc9"
		       "a27626ec3bf06d28 fad08c10674830d7 abc54772d95ace66 765757340007a353"
		       "63d270f410a6bcf2 0f2ca54dfdb00d9b e8fa7ea5b79bf818 2f16b95f9850ce4c"
		       "acff1e66bec202b5 7b85b37cdd2c3900 1d2950666368afa2 1de5ce68f54833a8"
		       "8da17b49c4e66243 560ec61a6efd5d3a 2966a76df2dc08c4 e5f02f8b8cd71b90"
		       "4ddd4bfd73a5c848 9b7eb813ca3da6b8 dbea536354e01428 dd6dc42db23257a2"
		       "0e322f685bb82b20 f0edc48351c22b75 e0aa8adc567f172e 654360e094c19754"
		       "2f39965bd9004621 c9ee3297870ed818 f980a71ec4a8f818 1e9be5be1ef6a660"
		       "cbf68637e54b5afa bbc5f9dc61933014 cb52b4d2624a24ac a3c6f5ca80dd5aee"
		       "93d0155af703c0ac a4a9266cd9b56f3f 152fc4fca8e7dce3 21a188682fb36e6f"
		       "7a736fd4e9972a9f 71f11d50c351551e 3c455f1b051befcb c1fd83239b748951"
		       "f7e18c2027627339 712df2772dcd57de 9a15f218e25a4493 ce20d039e2880881"
		       "69445f244f14d56e 6efe9ed005094333 1a4ef297119cf5c0 e21e2bbc535daebf"
		       "3fce3caf9d86b62c 37a4c9bd8991b8ff 01e992f26a77e987 ca8ddf6cf47d47d5"
		       "439eb6622b241172 a8d5a251dcb5d4d2 26a68bef9d2e77df e4db3ebd4342f49b"
		       "ee82b28fc35063e9 36589f86f8ff2db0 f2a7fcbf0d461484 184f64bf18e5bff6"
		       "84545e6112f87662 60987bcfe76bed5a 17dfb88a9b7d7cac cb4283afb4ee21ef"
		       "b43d698c413de813 48309bc1ec10cdb3 3a7e2e4aaed41cfe bf808b08e7f64f8f"
		       "6f250960375c3a3e d0617000ac6e54a6 12727861daf4d893 7ae133a5e99c607e"
		       "09e8097f876ef8cd 75e244b78eaabf83 1db9efd0ba405b52 715825974579a627"
		       "9f7775ab87de6e26 9979530e3fff6d8f f6421ab3ba1ec61b 9ebc1a2a7aa59002"
		       "ac916c26f55bc369 b2e11030f3346548 28285930228ad081 2500c822bd41ead4"
		       "80b530331f8642f2 6d5454fe75cc3870 d807ef92496b27e0 45b3317f10e98533"
		       "59875ec041117f3b b37d88c526ef1a34 2b6ea289fa69bc91 4d8fef84a27329f3"
		       "0a7326c84710f972 5432a525f3bf9af3 d93f9faded5766f9 067a5b1b7a0dac92"
		       "75207b6776c404b1 7801a7372666f153 78cdf91bb4c29d6a cf79eed16918947c"
		       "769283e829ec1e97 cb90630473224d88 95f2a0219d309507 173f42594372696f"
		       "6ef8468b843d4ad5 81ad78c221bbb877 0ca2323858016dc6 f9c311bd451a5b68"
		       "ce23c6feb8c1f543 82a8512d286e6bd5 62ada1c6c8c7c46d 7a9722d7a909b7cc"
		       "fce3258bb37b78c0 d076e4bb587bfe05 95257c988543edeb d2f24f9e124dd0e3"
		       "35ea2add17201df7 f2e68fbcc02da7d4 3b7a9a8f83de7375 be2c61b4c2b872bb"
		       "de25ea659a59b1a6 3cbc9c5efb6c449d 9818245291c6c232 17ae6cb018cdf7a9"
		       "a49240f37a484361 b450ba8fccedd4f4 556ca8423fd1e907 6a876306958ee264"
		       "4646633c2777280a c7a82e441d79b556 c629d7c97b4c7895 4bae0e76cb4ab1b2"
		       "0b51126ac8f125e2 f01c266df31b2ae6 d50eb02f96b39044 81a32254799bc233"
		       "88f7d86b6b60876d 20cf9e8a4468fb3e be4883fb90765a50 5d6ae99827a0ff96"
		       "d5eb284ac7df815c 0fd5aa2bdffa560b dc37beb9a7a6a4e3 fc074a9f812132a8"
		       "6be3a1f73433a198 0a168bbe54910ff5 95a47b6747f43a67 8fe5a7c96e636b4b"
		       "874f348d24b79337 db4315cb10fd0e56 2431511c323353cf 1e59fd5a55357e5f"
		       "6b7cce60f1f8211f d1f5be68f7c8bd70 c29f03c0a6613c64 dd10a65db5e0c546"
		       "f5382403ff8ba36b ad49879231912a4b 219a08a19858b12c 2744fd65603775b5"
		       "6bf4459512e79188 92da55f87d7cc02c 6885c0ec02550b60 9e3fa7d9fb0d13ab"));
  test_xmss_gen (public_seed, secret_seed,
		 SHEX("ac524902fc81f503 2bc27b17d9261ebd"));

  test_xmss_sign(public_seed, secret_seed, 0, UINT64_C(0x29877722d7c079), 0x156,
		 /* The message signed is a fors public key. */
		 SHEX("3961b2cab15e08c633be827744a07f01"),
		 SHEX("1be9523f2c90cd553ef5be5aa1c5c4fa"),
		 SHEX(/* Embedded wots signature. */
		      "e1933de10e3fface 5fb8f8707c35ac13 74dc14ee8518481c 7e63d936ecc62f50"
		      "c7f951b87bc716dc 45e9bcfec6f6d97e 7fafdacb6db05ed3 778f21851f325e25"
		      "470da8dd81c41223 6d66cbee9ffa9c50 b86aa40baf213494 dfacca22aa0fb479"
		      "53928735ca4212cf 53a09ab0335d20a8 e62ede797c8e7493 54d636f15f3150c5"
		      "52797b76c091a41f 949f7fb57b42f744 1cca410264d6421f 4aa2c7e2ff4834a8"
		      "db0e6e7750b2e11f f1c89a42d1fbc271 8358e38325886ad1 2346cd694f9eab73"
		      "46c9a23b5ebe7637 bfd834a412318b01 188b0f29e3bd979f 8ae734acf1563af3"
		      "03d3c095e9eaeba3 5207b9df3acf9ee4 7da5c1e2652f3b86 41698f3d2260591b"
		      "07d00565e5d6be18 36033d2b7ef2c33b dc5cf3bba95b42df 6f73345b835341b2"
		      "50e2862c9f2f9cef 77cfa74cfb04c560 d8a0038c4e96cb0d a2b3e9b2cd3cecf5"
		      "22fda0d67e5f62b2 ee23bd42a61c7da4 8f0ea30b81af7ccb 6bb02cde272d2574"
		      "1325e9d91535615c 0184f2d7f226141d 79b42412721fd345 61d93663650b3c1b"
		      "6901872bc4c0bb15 bcd9038950b7717f 7f448b6126592076 a2bad2d63c55399c"
		      "243fdbdb0c8d676b 2ae455e7f0a9b18d 3fc889c43387f2cb c4dc73d7c85bfab6"
		      "b4b04463a3dd359c 3a8f61bfa6c4b042 4aeba4dd8a95ec12 43b2e36c29f82e1d"
		      "711281599b3e05e7 5492ae3425eaa7f1 4ff8c6a9630bba6e bd236f195269a481"
		      "e87eb3d444825ba4 424ee5b2d9efb595 d5a338f4c253f79d e9d04535206ca6db"
		      "c2d4c9a1ec20849b 0db3fbe10c1446d5"
		      /* Auth path aka inclusion proof. */
		      "612d5bac915a3996 2cdbcacee0969dcf 8ecfb830cea2206c 37749c65b8f673db"
		      "090b1e2ade6c2a2f 349b5915103a3ac7 8482c39e99ffc462 6fb4cf4a116804ab"
		      "9d93d7104660fefa 0753cf875cb22fd6 0e55dc2f303de036 47712b12067a55f7"
		      "a467897bbed0d3a0 9d50e9deaadff78d e9ac65c1fd05d076 10a79c8c465141ad"
		      "65e60340531fab08 f1f433ef823283fe"));

  /* Test vector from
     https://github.com/smuellerDD/leancrypto/raw/refs/heads/master/slh-dsa/tests/sphincs_tester_vectors_shake_128s.h */
  test_slh_dsa_shake_128s(SHEX("B505D7CFAD1B4974 99323C8686325E47"
			       "AC524902FC81F503 2BC27B17D9261EBD"),
			  SHEX("7C9935A0B07694AA 0C6D10E4DB6B1ADD"
			       "2FD81A25CCB14803 2DCD739936737F2D"),
			  SHEX("D81C4D8D734FCBFB EADE3D3F8A039FAA"
			       "2A2C9957E835AD55 B22E75BF57BB556A"
			       "C8"),
			  SHEX("373c73945bffbe75 0f03acb9e5c6bfc4 6a18de32418675a0 b92e0309a54f6cd4"
			       "671db880b257ac96 f4af40eb80575aa2 f4fbcbaa9578a6f2 60882cf0ad94f907"
			       "310bfc029afeba08 10dd859c275b5b28 ed08b97031cce361 ce4888fede45215f"
			       "c2b59b75bfb82df7 0b21fe09f2a21ccc 2bfce1ceef91ff77 da219eedefc16f3a"
			       "4b94fb931062b24c c1c7517d29756e81 148f9071a81b1980 5694fcc93edf05f4"
			       "c804d3d99c5b9d3e d25e9999003d36db 32153553a81f9d0c 80b78cb4a0003998"
			       "5e5e2ee71bf4b8e9 e4abd07a9c49d0b5 310ac46f2a4af89f c52d4eb41cfff58d"
			       "5369c6517fa11745 1eb4439a874fbb96 daffd185ef27cc65 d3d67f06e7a5eed2"
			       "32913e61ecce42b5 623a156cbf16ed9f 7a280403a247b098 380567ab9309b0fa"
			       "8d4c3ed2d646344f c6a4bf1bdc68d161 9f29737a4d2597e2 b421f611b7bf464a"
			       "6824045f9c058b5e 39a591a40af4da11 75874e7ee287fd4b 1cf29d35a2652c42"
			       "663be06b06df5b22 c484989916feb133 3ccaa2e20d389baa f62de05537cb4f63"
			       "e1bc00e1d827d01b 6358c19f677126b5 1a7e5e6be0180009 deec05f4d66ebdd7"
			       "8e576912c869b592 0ffbcf25e37f8eb6 dbcae3e8a2c97e73 1860190a2f7ef9a7"
			       "8bbd5a36d7516882 7b299ef7580eac6f 90c6cc1ea68f27c3 d2835622d7677618"
			       "75d9f385c4d6fd43 48436cbea77f39b8 0f16196dab3030e9 cb61e15511b65016"
			       "f4115fa3921385fe 203ec3127531e2ca 26616e278e4f5f70 e621fe5a18353fac"
			       "ce683794004557d5 732391afc53cce77 44ca92811baeb824 e5e46dea2720d68b"
			       "1910307b967059be 7583adc9ac8d425f 998861e765cd8ec1 c474fb3f631cafc0"
			       "90b202f9b9c1596c 5ef21a2985642bcb 36056aea784226a8 a490a4e4ef9783a8"
			       "fb77eb2f4e10e3f6 d0a62a6a6062f6a8 991d5ecbddb74f86 a02c54258e29d10a"
			       "86b756885721175d ecf0077a66f4b3fc 592ba9fa5e3a0fa7 1eb808e5e944ffa2"
			       "5e377cfb8782b2fb f93c5abc88fe8b83 1148088836aad27c ccb8aff0bb9e4308"
			       "f485c3473824ffb0 30e51cf613671dec 7bcb4dbb62c7224f 2dc63fc2157bc59a"
			       "b1242f460f8ad6a2 3c20fd27e280776f a180b31baf6e204a bad44cf1a645ab8a"
			       "cb811c0f08a0b019 45116e05a5bda4e2 de18d7047157d2b4 b76805ac222a8e75"
			       "745dc2443d14a43e 21dfb39ebb6c14fe 42b002b62cfe4808 ce0a6c3ff2401fd4"
			       "8c047e654ac98dba a5e0f621620c34af 63cdfeed579b7c04 dc2e3288ca684081"
			       "4ed30399c25c840a 0dd471d46760e40e 8448529112e68c54 65084b1be7eb3818"
			       "c00c3fb3365b094d f1b03d4f11887868 6bd49fa6618a0a42 bace7865caafa963"
			       "34afbd686ae8e957 ec206aa03de1b2ab e0ef1e933eb8cf15 7a64c52b285e97af"
			       "9722ef435dc8f982 b44194937d6826f0 a1ade35632e03bdf eb1bfad881a34fbc"
			       "809354630edc6437 e947c965b128893c 7fb7e2e2e2db7ce2 7b8a54fb95b56ccf"
			       "96f901544d056960 ec9c8bab5ffac52c b6f98b9431a3770f 7053457993351c19"
			       "cce355ab749e32d2 a2c56910e9475811 8835465f31eae203 4d3728e376f193ab"
			       "b567ed28dfea4cd7 efdb1f35847473db 9483c8344904fe50 95154c9f56446440"
			       "815e6669c7fb8ac3 87af71803ef5a616 74112b8d4ea8137b aba080b98956dcf1"
			       "9d19558acd69c715 04bbd291410ea1cc 5a8b62f025bbdef1 39f8cb7f65594cd7"
			       "80f6ba44c839bda6 755fc4a2ba3c925d 7fa1f05b954171b1 6d5ffb607c643081"
			       "0be371dd52f3d888 aba9038f2320732f 7403bd541a7eb7af 93703dea45e02946"
			       "8f57ee3bfd74a67c 4feaecae0c1786b9 266e52674de811f5 6f657b1bdcd5aefb"
			       "30f924c2495357bb 70037725e821a5f7 7690d21eecc5b77a 1777123cff4c0b15"
			       "52f1dbe08260bbed 0d5ac3cfa1450030 6b9564de6135d1d4 1c52866d0acabb22"
			       "157c712a37972b47 15a5459c4f30fef5 5a2a396a9d78dbfc c06ad406f4cfe1b1"
			       "120537abc51241b4 59153167bea44afc 9d7efd91341c7fd5 5017effa7c687f67"
			       "ef4ad278c1829b7c 073784ddd0d64fbd 90869a3724ba1d1c a05bde1c669fca54"
			       "8b85d8bd574d0703 c42fc2c1180aa171 93faf9e55482558f 54905b9c9b98d99c"
			       "001842df9c942d4c 36bbd4e60d571b19 84421b90931b916e 6f57a17781b30db7"
			       "f09a6105fab7f1f0 d6dfc72eebc30a1c 26d7387f404e0c12 9168e7e246a73940"
			       "8c0eb2ceaa07c48a 0a3cef36ee60535d 2ad119dc24285323 00ff025fd956e621"
			       "9ca1e2df05bb00f2 75477db356190d84 b14f3e77e9c669df 825885acee76ab11"
			       "518bea9753fa0504 7f1828cc1ebc207a 796d40490ebb4934 06acb8a8f90081dc"
			       "d28c5bcf4f7d0a22 38eb1f6ebbbe02ec 17808173042fd209 bd81ce50cc245c25"
			       "e7ae1990db628667 c02599acf12085d8 484dbc84ed0f8908 13e4e9232db6cc1d"
			       "6d028881abc8ccae 1a7216a5e97cd4fd 848ea80984e0bd4a 8e5ad4e23e37b61b"
			       "626dad1d36ba7cb1 79b17b1f417f1b04 a16e315f2405526b 04b40c9375acbd27"
			       "1ce0a02dcb480adb 1fdbfa1accc079c2 51dbdd354e0b405e daaa87d0a2bb6902"
			       "d12f3ade5f8588e2 02218b859ad5eadc 5f186f15a87cff3a 461692ffe0921073"
			       "6ee053b200fadf4e d6c5d2ec302a86e8 935afb31780b035c e49154dd9decc7e1"
			       "55b8b27a8046caf9 3cda59190128fd74 d5cc56046682b4dd 3824ed44c91accb9"
			       "67ac2304b682c477 0d8bfa0cce4b791a 04b7b53c3369e463 636d6908bacc2e40"
			       "3a0422e3cde7374d 1c5a6afe599b341a 7db6bd2dbddbfb5c f9c85ab10637f32d"
			       "26620bbee639fc57 6819baa7a0552436 99a9294917af1a5f cc14ac5d04229b6b"
			       "0b115d1f9dd983a4 a5117f9549ecd7e4 2db3b8cc33d767c0 9283f258fa845c43"
			       "419bf7b437cb0ac0 3d0b255dce3ac86f 495b2e1c8deb916c 9afe1564181a201f"
			       "dfc5495585ab00f3 f344cf5e1e510a53 b183d1100b347a15 e6df9a57d9702de8"
			       "46c5a5cb55410139 433ef287786cb596 d6738995f23b6332 1b07e8f7848f5315"
			       "8e5f2b260e797dc6 cff9812e5b8d39ae 2233d87bf240dbeb 54c137b21ab8f51a"
			       "859dd2f8187e04d7 6612f743a1a8d3a2 409e6375e30e8a28 7a07f65415b82588"
			       "10f27f7c2bb5cf65 1860fb1b26a4f35c e4870226d3dbcd5f 54f603e7c927c73c"
			       "2604fab51c6c2272 0315f70c4cd14f74 44a1a4c9be0511e6 8c2247f22e0051bc"
			       "132f0dcb0cc387e4 966bdc386cc7623e 8a384b82c7e6406d 61e4bf3532c7a755"
			       "cb58a80d8ef30412 f8691a8ac779ae54 81daafc0e26b4bfc 7eee57c75c52b8f3"
			       "8ca6d97bdcdbb366 3a80a5ecb4e5f5a1 4b5aff54897f09c7 0e926c264bd72851"
			       "826c3772c2a24206 4a0a0b4b38792890 62efdc6fbb20984e 7297e779298c7dff"
			       "91898d646083325e 9cb981eba5a3515c 4aa26069979e3cfd d5da15be8e8615dd"
			       "0410d914312a6b1f 6844d42c43b9f65b a93746903f52cd27 c0d4482c920a0bd1"
			       "942189359c6cc639 b9e899084962fd78 f219ab8dc39a226e 4701ceee6a689343"
			       "836a7a4b2b72a874 2cbc7a10e34860c5 aa8b5936db7ec269 b57208cf47f02f2e"
			       "5d06b978b3445ae0 71d9fd313375199c 618efcdd1f66dc29 9c781efee5caf209"
			       "89f3ae515824f77d edc21edfaf4cafef 79e83523cdbd118b 04ee628dd0eedff0"
			       "f771c09ea8930dc4 d4abfa4748a568ba 5d9ba5ec63991e9a 5cd0fdd560a2c99e"
			       "cf5d44fe62aef6c7 1c07ce5e8dc72caf 653817bc4819ba54 4d713e2be7028fea"
			       "afc3455fab2bde23 52b8ae6417a3b131 b1fc0922d5751498 48b62a4a1a9b26f5"
			       "c12d7c68e004e445 73ef48ab562d0072 e04202ea1f56eb1a 0cb8e2306b87fbed"
			       "bd5ac23cf212c620 68afa2fd30358774 99309658594e947f 26d81a8edad1413b"
			       "792a5c35d5680ccd 6f2eb81e412dbba1 c750ad2ff6ab3f93 5c8d18e8759c0594"
			       "39d9efb1a6f1d011 6ec5e35e83c4f4e7 7d3cf696ffc74e0d 07e8d6347369b63c"
			       "81cdbed36dcb07ef 77f737657e278a73 39e55cb7274a019d 39d92b651e09c0d5"
			       "d654d4ad44291a36 b42e0908505c4de8 7d640a00c56d5abc 2a994701b2f0d2e9"
			       "a4b1a030476e3506 8850326022e5edc4 d621de04dee0eac6 de4e51e2b2f6fe7e"
			       "07b464baad97a19b ceaf083ec5152e9f a0da7ecfb82caaf2 f163c3709f6c86e7"
			       "cbd5d338b56a284d c8c8497e5b5d9206 beb8664c88f84280 8f19f6425c86d32f"
			       "1af3277e9783c5e9 ca0ba31e0efa3017 5ee4422efb4acc82 0998a4e19e0f124d"
			       "04529a95a7c4c880 a1b468e5ee8541d9 9d07cb2a46c5f21e f67dcfa5858d41e1"
			       "b140749b04db5433 4e95a4c3a9385d2b fd53685c859e31a1 904f4b3fbbc5a74a"
			       "d0d5e222d4a5224c 4f5605851603911d 2f908d20d40d8b37 106ae45c381f6aa2"
			       "d5c89c7148d80943 1fd29e6a85ce6be9 eee6602372e504aa 4487d1c6023d6b3d"
			       "2f79718dd86ffb8a d2edff96f28b4a95 d5107430372d59e1 afdf7b32bcab8648"
			       "ea8c2f4addb40d95 91cf58fd95d04c01 557e6d8b526efed0 cb5607f5b334529f"
			       "acc4c52bc7e4f238 c9a0461ca9580df2 a46c91a74bdb2149 aa207f60d28abab0"
			       "d18970af2fb6b3c1 64af229faa6884a2 1f645eae16091f48 f859f96ffb169886"
			       "ab7c3b8f73543dbd b09ed00db65dd6ad c06c242a5d8373cd f0a93be9bbbd63e2"
			       "99084a5cd3ad6a77 f7bfa5b09136abe6 934420b5fa5f7bbb 165ed99c472c136c"
			       "1d679150a9623626 1a3b9bb8e581724a ea2208ac72a8160e 672510b73d9b386c"
			       "ec83dc2cba9c29f7 fa997748de75bd9d 0c21e2256175381a 45b03b3dacbc29b7"
			       "d5494fdb921ae780 4d18dd023b78e8f7 df965b1fe3f36033 e8d20f3a436adc1c"
			       "5860951da02481f9 c8fa05bebd131b3a 4207be917e217660 ba91ae83a35d7741"
			       "0b1c0a3cc8652329 4929924b95e8021a 0d8bb5af959a54c6 63b9b6d5149ccb6b"
			       "b0e5280adecdce1b 7229e817ad6ba08c 467bd3f9ed6537f5 e7e8c949d2d4bb7e"
			       "3f0d4b42adf32c67 42b7666bf0876e18 51dbf5dae1eb4210 f115e6a5afb2e5b0"
			       "5db56aa0fd56f752 4f1da655a7851734 2d55900dae39c326 1e400de0abd76eb3"
			       "c173406514da6fa5 4d81838a0e1761cc db1a7d02416dde89 10492551d64fc331"
			       "0f89627657b88159 2a3a26b466f6dcc6 6ceed88dddb3ba60 3ebb4055f6743887"
			       "7c0bb6b011975c6d b15a896b13d91f53 d2fad4eb9eea5c21 2e2784fc30992d45"
			       "d9e43e2201814159 c87058d35d76137e 3ab78d93be20e655 d6061d504f9670f4"
			       "2da359d408f7b791 bbe6bd509cfd7b53 9b382ce7a356e8f0 fe54a907560f75d2"
			       "ad1f59b83fbda0db 4a1cc4d18ea6cfeb ae7bd14fb6c7f8a7 72125032f9c3eaa1"
			       "ba175042ca35ea0b d483992479450e37 b52454e44a85af85 3907c50f1ebbd69f"
			       "2caacf912fecd431 7ce04b5a28664721 6686c9318c2278fa 45343eeef2cf4dfb"
			       "5eaecb0aa20422b9 715960b9c7ea0b13 3330c62ef1f615d9 2d283c95102a79ef"
			       "09d152924ce15c5b 1aa893b9be2d8427 89b1b29e2d05fb4d d5a2b486d0be0696"
			       "d73b6925107ea8ab d2a71d0dad3d7a76 71579004a46afdda eb08a357271405d4"
			       "e183e790d5d2f854 8d8da51e28243c25 4e0e460079dea68f d4410d50cbf0e9bb"
			       "f96d3532baab2bad 5e81f359c5839526 71e90601e0bdc325 740a42f666c6ee86"
			       "8b68e1298e625f68 6ef0eeee17c45a81 59ab13c794cf224f 4a2cd0efc5ea1a3a"
			       "368a4e6cc80ad464 6cb3f6dcf45ecd23 7a6ba15df7193b91 41d2520d77bae9d7"
			       "d8507c3694463456 8005bb5df947096e 548f88ce8515a0d5 f3070a9ad32dd656"
			       "36e1a4e91caffc00 8bed45094e6f664c 3b14461277653538 ece57b5705d66437"
			       "67bb2b0c49530cf7 d142d0d14f00c6de e3e134292dc0ab81 a4d675a041fd9d0d"
			       "41dbcfd9d234a145 7a7fe343a6bdefb4 cb1a48fc1aaad3bb adf0661b6f15a291"
			       "ff11666a95be8b7e c55a5be147dfd7ea 639e95353097ad58 df3611890367b580"
			       "96a2ffa5bc5a2bab da709fbf59f110e1 1573c6ebb9c68359 5ea71f53901ded68"
			       "1517d7acd58db8d1 417d615313a32daf 4dda30f5f0257b37 29afb59c8f95e3a9"
			       "7c8d35b09d212bbd 94b49abdf6e50b6a 57d6a488e4f9446b 96a67b0357764b01"
			       "ff38be4744f692ab 9fba6f8bb24c5318 75d7f146fb46b46e 0d6021a0f9ee1940"
			       "928d05dccdb48f79 26ed0d0b01749ddd 301958d08524f924 5f7951665627ee19"
			       "fe9ef4a1f884a311 fa7d3b398a0d0faa c9e18caf850f20f9 3a1f1c6288477192"
			       "1ef22596705aa9e3 b86df8e0b1ce071a 79cb80f8674fd162 bbf128d897892820"
			       "9d02c68998669edb 100131822dd455fc ff708ace30e3dc80 4efbd9d2a001da20"
			       "e4d17cfe3206b92d 25edda5fcaa37395 a4dbb15383bccba1 0ba80f8fd66c14da"
			       "2fbfd1850ccca1c6 617b0553634a6e9e 7094d18f385bcce2 16fee3e2f4d827e4"
			       "563393018fa1b350 341016e7ba78a6b1 5ae5b0685417af24 22a5efe51d46dccb"
			       "236dbab0dd0e13d6 21231632396abae7 b737106146a00d50 965db987fa75371b"
			       "e865134504c7f64d af9b188eb4ac894f 29c4e5568688913f 362aefe8fbcf2dd2"
			       "ea12f3ea4e1de149 55d2dacc6ad5b4e5 d00f78161a67898f 96b64cf5f21a1713"
			       "38a94284a2b180cc 5e2b2b03ee6e6d58 bf3a49558aa87a9b af0696bb28c96fca"
			       "9e4a4321e13b1ecd 7b172d27d2e1007f 3aefc189d51b23e7 573ec280c5131542"
			       "071c27aa22f57034 5f3292be4dab04b1 a9c5dab11bee3e65 78768b6f1fadd532"
			       "7cc09cbb4cd36063 aecb4fe42f3b4a84 de7ad0d2b1d72ee6 245e82ab60cefab2"
			       "0e779148280502df bf6748d72adb725e 4836c68f08cd83ec 0573078320c936d5"
			       "6b0edf049dfa8d2d 684078a41e80a3ba 5246293063c86a2e 4c32963199c056b4"
			       "f7780079208306e3 7c6b4dbb70b1e186 be3517a797869e09 577c1449412d87fc"
			       "31f901ff65ea3400 99d7a8bbfdc8c441 78a113177a135c10 6dc898a7b0a88335"
			       "dcd1019360095b8e 9239bea63ca9b9e4 f097200e23d86064 99f7748eebb4b598"
			       "4a3a872f154ad47b 04c480c14d46e5fe 01e75a53329cb6a0 2b973fbd5b0dfb92"
			       "fd3572825cb170ce ab96955a7df816b8 fbe549572a5ef399 26c207d78deb6ab7"
			       "2a5ca66e77ccbb5f 758f29b038ab1909 5ca572dc1a13101e 633819b29f8b6a4b"
			       "bafffcd390fb8ef2 351522e72c9f09b8 2df20d11435996df dcf2f3a5595217b5"
			       "f02721c9d515bdd4 d71abadca7428f12 cccaa766255da4df 18c9dcbaa4dc4150"
			       "cf6c45a41664a642 74fc66929bd1ce07 058520c295ad5db1 1ebe965aea245b56"
			       "74fa1390a4acdca4 507f4f509c0899f1 bd46fc3aa1f7f43e 882385437c2d92e6"
			       "43b222f1de3733d2 ff5b246aa379cb7b 2309ff16d53aea18 435accd18c86c740"
			       "9ab1fa1d20a62bc0 73e47aa944f63175 5deac3cd3fc3f552 a7d043e07a337e21"
			       "ac1343a0100d8e74 386927b6335125ba c5809e09fc25810d 949d5bf4e6ef4af0"
			       "08a33c4aa136f700 bbc39b7e7130e73b 4aab82f0f8e2cd4a 4160882684ddec0e"
			       "1d2697bb8bd999ec 04bf7eede896d4a0 89179356adaee823 398aa1af27c65e61"
			       "dd5a47c1aa7778c3 3ed0726710eb053e 583988d8c1347b30 358f7df216c692fb"
			       "e67ec05087840869 7d37e0ed298f357b 33f0dae67e665bcd a85fc71cf91e155e"
			       "f412378d81fc6a77 2a382318af8964c3 2a3337de70b4ae7e 8fa50f2246f79de3"
			       "4401e734750ca311 091a621abc1f7819 f74e16dcfb5aa398 248f2f4b5795eee8"
			       "8fd6757314d79b76 b85685448e6ac531 2a321752ddbaa0d6 e33b7bd9c6190df2"
			       "c0495a632a364655 5faeaa9d2bd04d66 bee9a700af0b75fd 3b7fa4944ad43d9d"
			       "cc291e493297cb01 6ab1ee25e1613165 1106f954f576d47b a14d6239d8699882"
			       "e222956a2b53f470 4d38de97acaa75c9 2c6097384d8a70d0 b17dc04659ed206c"
			       "604d60f0463f4714 a43a53f0b5a02685 f1751faf492a48a7 e07e6b9946ad28b4"
			       "15502949ac793aab ba8f41e060390732 63878d212a262d49 ec51ff8536aa1c02"
			       "16c54ce2c4f1f7b5 c88bafe62874e4d7 e54b0bf068b714a4 453a509d8909a338"
			       "24425567871a6328 9a418b6f12a7db7a b11d3f98fc4eb2b3 a4b7cb059f8c5140"
			       "d3169fef3f4a8591 398a46db9a246ab8 73ca741436ec0bf7 e84940c594c15c12"
			       "f048e9e22289ab82 808a4d4ab459254c ee928e01502b1f30 872ef8bcc0d28f35"
			       "c62460fb2cf5840b a160dcf1dcc87282 292cf70f662f9682 2efe7794181d67c1"
			       "86fc38145c7e8170 eebdfa9856483b73 417c6ae5e035972f 6aee1dcad230d14f"
			       "d311e68a931d9202 f52ea2bcf2d85f61 8ee90e1bad0df934 b4ee13faef044493"
			       "8684f7ecca17c19b b17787e88f7db0f9 bc00bc22f4aa8a02 358d46ead5ae4f5c"
			       "06d1815662f7adf2 dd598acd1d52d83e e995d6273fae0c34 3388199eefe80fb6"
			       "9689f4ccea58044c a02702fa6c188e6f 572f699a067d1ef8 2e41386f54d90b9c"
			       "94a6586fde4df772 2e04de90c10c2dd1 09d5f2583c42eaaa 123e8b47b9513845"
			       "48407df213b95965 6bb00b50b71cf2f7 eecfa6a00d3e364f f3e08a765024b54b"
			       "c12491bbc6bc825f 8530528a11209560 e5bd3edb5499009d 869d086123c2f05f"
			       "40eac28946d0dfb7 68f5e01cbf42dca4 cccad733c444f533 902019c33af6d535"
			       "6690c6bbb4116db5 d25576cb2ff56289 f5b238b5ba738b38 498b5cd67c5394f7"
			       "4fc9fdb77b71b0ae 322bed1fc8687d1d f7e987e2154615e2 c26c2d94d337bb9f"
			       "77cc9772343f480a 07f13b455392dc26 436efe56ac1ad226 a98ec9b4fd2f5e37"
			       "e42c93c0da8c6911 7b67627c0fef6fe4 131186e7a517289e 2b46e7b2405e9c9f"
			       "d47cb9f4d6772722 5206a133aa154762 918618dbc8016c5f 89d723800c01c5d9"
			       "98b7fb5779a687ba 0511432eae24d16a f333e88f7f18b173 af80567847a609d8"
			       "68967df6b1e68f64 9fdde21a141235ea e6905787c0ee5c79 ff52bd6259f055a5"
			       "cc457b5624094d20 4b3240a56040b9b6 14145f43d467d26e 5f74b85d8986b169"
			       "4dc8e20d2ddd600e 60e576d148af560a 4a72ce4b968672e7 1373abf6c0f47569"
			       "0c3446f9109b3109 501b5776e4df13a2 48b344fb9f416d4c b5e38cd44315011b"
			       "fa0a96eb86537a4f 0634dbbe42050cd7 430f630f87bbb958 beffe476ad2dda10"
			       "5856c24befa48154 36d46395faa2797c c3ed908dbd2c9dd1 053d2f7926d26d67"
			       "a09e0147e261e2b0 3864350945652e0d 960631d360916e6a b61a5c9d3459dbb3"
			       "820212e5ef3241ab 5de63ea4150e4d7c bdfdf071addda34a 4bc53a7fcd169821"
			       "0f9c18c4fa4a36b0 e6b61cb3720d3fab b913c337f9294afd 2bf279322f15344b"
			       "2365893fdc31cc4e a8b87fa582d5a074 34f7fb57df95c706 f508826d90fa3bcd"
			       "af75ff59a7fff497 432c32f16225319a abdcf1f6d174fe58 4ad2697a8d070423"
			       "adaa1f5662b97a08 001cd48c33e34e8d 48a2779df70902cd ad2ecfa26d94d3f4"
			       "1f9e937f71f6f2ce ab1fa5aefe5813b1 1a81df48971c7e0f 23e68437008ba0c4"
			       "eec536d4a090e3a2 2cc15a726299b01c 236a1293084a3ccd 22bc2f2f46f45817"
			       "29e55d822b34b7c9 b7a0d4714ad72209 f1f81af845683a04 2c6e977e45e9cf5f"
			       "1030262aebfb7c76 04d3eae79300fc18 eb9bae0c1db704e8 736c225c03a4db78"
			       "b346a1d016d658a6 98291dc838142838 6cb4e164a4ad7493 b2a76b436cf48e07"
			       "1c637107300e294f c61b660791a6ce2e 99fedde9cfa1ac62 91c9bcb9f14e8aba"
			       "85e898b532a3593e 555395011e8876d2 38caa1848e232ff5 74e50c7c55f6a643"
			       "3a0f9eac55f3f93f 4ac293109f3c1691 faad822a2ad13c4c 8d4817280df581d7"
			       "7b75ff33a8157c8f 6804c3156bf2898e 881a4733a695f622 24865f354a3cb960"
			       "e27cbe33b355c770 650df31567e58fc5 f2fdcca4dd6baba1 1b9fce458156cefc"
			       "bbfe83192484a292 7a41835cb120d779 fb9ddd676a6f3071 0ae18443b759c8ed"
			       "4977675b90e465b3 3eb76d9db8d5dc1f fd1e6f1ea0474e25 13be36a5bf36b4c4"
			       "690e16fea2a89981 68e3b6473fc5d078 700d3dcfea0612ea 8802d6d214f03d69"
			       "ecad474084721d08 96008adb378d9a4f 09a895e4e2062ef4 571c8f88b6b0167a"
			       "3577652a9c5117c9 0dbbb81512ae7586 c660034831dacc7e 6d807af3a397a442"
			       "e2d61faafd2eda60 61b9506cf0252fa4 36f1eb5d35e96f4e ae80376a42073e1d"
			       "1a85dfdf086a4bf7 62b74d3d4e667402 ee5f59d36c7ac624 87a65de64502751c"
			       "f6fe941e20ac694d 70a853f9869b41cf b46b2869878fd260 498f6a3ff2156144"
			       "c63585772e402fde 2eef7466931514ac 22d707bf6b4f118e 7bd9fe13e8b90363"
			       "96ecc3127623e13f b612f9c4d60700c2 9b802fd741bb99c6 357f15f760826fb8"
			       "226f51a3f2278147 2def7d6f707e753b 171a496e6ce99c64 da1ee01ae949394d"
			       "eda4f3dbe8980338 bcf150c839ffb4df 3043d1392f53f9d5 e9d571774b0efbc6"
			       "09ea772fd481dfa3 93b73e1035532801 455da7d830901a1d 2502885cd6d74b9a"
			       "2c2dedaf9a9edd43 a021def1aa51333a 02e837c01da65f6b fa45dc2abcd2c0bd"
			       "84db2d91b6d6e6c5 673f09175050cf70 60b505a03db18f49 29c1d4eba35e9694"
			       "641cbcf58050709f 13272565113f1e8c d904aa967f0f7855 0dde0cf6db44fcf6"
			       "87bbac7b39a4e21f 36513c12d761bb7c e663362b60f4bb4a 5e9a1ebb5d057224"
			       "5c563f7528aa5d86 f6eadbf5f62ef61a 349125587bb444fb 98dcfeb5e54981ce"
			       "4bf11f1b55be0bbd b609e57f0a5b1a78 2ac830f31db648c0 d632d20daaf84fb7"
			       "1a02467612630d26 3dc0dfd65943f7ce 95c3f781c959485a 0ff28a4810ba87d0"
			       "b85be2499ca35f7c 099f23f2300b0f26 eaa0894510d28bd6 7beb619086cb61b6"
			       "ef0eea3cc71e6ed0 743b7ac3f9d219de 6886f209d134355d d1f7125e88c25972"
			       "9d0a0b3f633707bc 02843a8e259fa9c4 e6ab58d9c9bc8e8c 0504010d5e2ac224"
			       "0bc4c1e5eb15ecb4 2875fff48bbf182e a8ff1041cdc59c8a 506471f66ca8a713"
			       "a27a8aff707361b7 632b4250ca3b32e0 69def84ada576a1b cea10c1398a66361"
			       "cb4f96de45be2454 db7ee6975e47ae95 222dba6a40683225 4e1f05a4d3db0a7e"
			       "17061b18213d6bbd c66bd61b29d1ea53"));
}
