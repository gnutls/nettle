/* chacha-test.c
 *
 * Test program for the ChaCha stream cipher implementation.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2013 Joachim Strömbergson
 * Copyright (C) 2012, 2014 Niels Möller
 *
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#include "testutils.h"

#include "chacha.h"

static void
test_chacha(const struct tstring *key, const struct tstring *iv,
	    const struct tstring *expected, unsigned rounds)
{
  /* Uses the _chacha_core function to be able to test different
     numbers of rounds. */
  /* FIXME: For rounds == 20, use crypt function, support more than
     one block, and test various short lengths. */
  uint32_t out[_CHACHA_STATE_LENGTH];

  struct chacha_ctx ctx;

  ASSERT (expected->length == CHACHA_BLOCK_SIZE);

  chacha_set_key (&ctx, key->length, key->data);
  ASSERT (iv->length == CHACHA_IV_SIZE);
  chacha_set_iv(&ctx, iv->data);

  _chacha_core (out, ctx.state, rounds);

  if (!MEMEQ(CHACHA_BLOCK_SIZE, out, expected->data))
    {
      printf("Error, expected:\n");
      tstring_print_hex (expected);
      printf("Got:\n");
      print_hex(CHACHA_BLOCK_SIZE, (uint8_t *) out);
      FAIL ();
    }

  if (verbose)
    {
      printf("Result after encryption:\n");
      print_hex(CHACHA_BLOCK_SIZE, (uint8_t *) out);
    }
}

void
test_main(void)
{
  /* Test vectors from draft-strombergson-chacha-test-vectors */

  /* TC1: All zero key and IV. 128 bit key and 8 rounds. */
  test_chacha (SHEX("0000000000000000 0000000000000000"),
	       SHEX("0000000000000000"),
	       SHEX("e28a5fa4a67f8c5d efed3e6fb7303486"
		    "aa8427d31419a729 572d777953491120"
		    "b64ab8e72b8deb85 cd6aea7cb6089a10"
		    "1824beeb08814a42 8aab1fa2c816081b"),
	       8);

  test_chacha (SHEX("0000000000000000 0000000000000000"),
	       SHEX("0000000000000000"),
	       SHEX("e1047ba9476bf8ff 312c01b4345a7d8c"
		    "a5792b0ad467313f 1dc412b5fdce3241"
		    "0dea8b68bd774c36 a920f092a04d3f95"
		    "274fbeff97bc8491 fcef37f85970b450"),
	       12);

  test_chacha (SHEX("0000000000000000 0000000000000000"),
	       SHEX("0000000000000000"),
	       SHEX("89670952608364fd 00b2f90936f031c8"
		    "e756e15dba04b849 3d00429259b20f46"
		    "cc04f111246b6c2c e066be3bfb32d9aa"
		    "0fddfbc12123d4b9 e44f34dca05a103f"),
	       20);

  test_chacha (SHEX("0000000000000000 0000000000000000"
		    "0000000000000000 0000000000000000"),
	       SHEX("0000000000000000"),
	       SHEX("76b8e0ada0f13d90 405d6ae55386bd28"
		    "bdd219b8a08ded1a a836efcc8b770dc7"
		    "da41597c5157488d 7724e03fb8d84a37"
		    "6a43b8f41518a11c c387b669b2ee6586"),
	       20);


  /* TC2: Single bit in key set. All zero IV */
  test_chacha (SHEX("0100000000000000 0000000000000000"),
	       SHEX("0000000000000000"),
	       SHEX("03a7669888605a07 65e8357475e58673"
		    "f94fc8161da76c2a 3aa2f3caf9fe5449"
		    "e0fcf38eb882656a f83d430d410927d5"
		    "5c972ac4c92ab9da 3713e19f761eaa14"),
	       8);

  test_chacha (SHEX("0100000000000000 0000000000000000"),
	       SHEX("0000000000000000"),
	       SHEX("2a865a3b8999fa83 ae8aacf33fc6be4f"
		    "32c8aa9762738d26 963270052f4eef8b"
		    "86af758f7867560a f6d0eeb973b5542b"
		    "b24c8abceac8b1f3 6d026963d6c8a9b2"),
	       12);

  test_chacha (SHEX("0100000000000000 0000000000000000"),
	       SHEX("0000000000000000"),
	       SHEX("ae56060d04f5b597 897ff2af1388dbce"
		    "ff5a2a4920335dc1 7a3cb1b1b10fbe70"
		    "ece8f4864d8c7cdf 0076453a8291c7db"
		    "eb3aa9c9d10e8ca3 6be4449376ed7c42"),
	       20);

  test_chacha (SHEX("0100000000000000 0000000000000000"
		    "0000000000000000 0000000000000000"),
	       SHEX("0000000000000000"),
	       SHEX("c5d30a7ce1ec1193 78c84f487d775a85"
		    "42f13ece238a9455 e8229e888de85bbd"
		    "29eb63d0a17a5b99 9b52da22be4023eb"
		    "07620a54f6fa6ad8 737b71eb0464dac0"),
	       20);

  /* TC3: Single bit in IV set. All zero key */
  test_chacha (SHEX("0000000000000000 0000000000000000"),
	       SHEX("0100000000000000"),
	       SHEX("25f5bec6683916ff 44bccd12d102e692"
		    "176663f4cac53e71 9509ca74b6b2eec8"
		    "5da4236fb2990201 2adc8f0d86c8187d"
		    "25cd1c486966930d 0204c4ee88a6ab35"),
	       8);

  test_chacha (SHEX("0000000000000000 0000000000000000"),
	       SHEX("0100000000000000"),
	       SHEX("91cdb2f180bc89cf e86b8b6871cd6b3a"
		    "f61abf6eba01635d b619c40a0b2e19ed"
		    "fa8ce5a9bd7f53cc 2c9bcfea181e9754"
		    "a9e245731f658cc2 82c2ae1cab1ae02c"),
	       12);

  test_chacha (SHEX("0000000000000000 0000000000000000"),
	       SHEX("0100000000000000"),
	       SHEX("1663879eb3f2c994 9e2388caa343d361"
		    "bb132771245ae6d0 27ca9cb010dc1fa7"
		    "178dc41f8278bc1f 64b3f12769a24097"
		    "f40d63a86366bdb3 6ac08abe60c07fe8"),
	       20);

  test_chacha (SHEX("0000000000000000 0000000000000000"
		    "0000000000000000 0000000000000000"),
	       SHEX("0100000000000000"),
	       SHEX("ef3fdfd6c61578fb f5cf35bd3dd33b80"
		    "09631634d21e42ac 33960bd138e50d32"
		    "111e4caf237ee53c a8ad6426194a8854"
		    "5ddc497a0b466e7d 6bbdb0041b2f586b"),
	       20);

  /* TC4: All bits in key and IV are set. */
  test_chacha (SHEX("ffffffffffffffff ffffffffffffffff"),
	       SHEX("ffffffffffffffff"),
	       SHEX("2204d5b81ce66219 3e00966034f91302"
		    "f14a3fb047f58b6e 6ef0d72113230416"
		    "3e0fb640d76ff9c3 b9cd99996e6e38fa"
		    "d13f0e31c82244d3 3abbc1b11e8bf12d"),
	       8);

  test_chacha (SHEX("ffffffffffffffff ffffffffffffffff"),
	       SHEX("ffffffffffffffff"),
	       SHEX("60e349e60c38b328 c4baab90d44a7c72"
		    "7662770d36350d65 a1433bd92b00ecf4"
		    "83d5597d7a616258 ec3c5d5b30e1c5c8"
		    "5c5dfe2f92423b8e 36870f3185b6add9"),
	       12);

  test_chacha (SHEX("ffffffffffffffff ffffffffffffffff"),
	       SHEX("ffffffffffffffff"),
	       SHEX("992947c3966126a0 e660a3e95db048de"
		    "091fb9e0185b1e41 e41015bb7ee50150"
		    "399e4760b262f9d5 3f26d8dd19e56f5c"
		    "506ae0c3619fa67f b0c408106d0203ee"),
	       20);

  test_chacha (SHEX("ffffffffffffffff ffffffffffffffff"
		    "ffffffffffffffff ffffffffffffffff"),
	       SHEX("ffffffffffffffff"),
	       SHEX("d9bf3f6bce6ed0b5 4254557767fb5744"
		    "3dd4778911b60605 5c39cc25e674b836"
		    "3feabc57fde54f79 0c52c8ae43240b79"
		    "d49042b777bfd6cb 80e931270b7f50eb"),
	       20);

  /* TC5: Every even bit set in key and IV. */
  test_chacha (SHEX("5555555555555555 5555555555555555"),
	       SHEX("5555555555555555"),
	       SHEX("f0a23bc36270e18e d0691dc384374b9b"
		    "2c5cb60110a03f56 fa48a9fbbad961aa"
		    "6bab4d892e96261b 6f1a0919514ae56f"
		    "86e066e17c71a417 6ac684af1c931996"),
	       8);

  test_chacha (SHEX("5555555555555555 5555555555555555"),
	       SHEX("5555555555555555"),
	       SHEX("90ec7a49ee0b20a8 08af3d463c1fac6c"
		    "2a7c897ce8f6e60d 793b62ddbebcf980"
		    "ac917f091e52952d b063b1d2b947de04"
		    "aac087190ca99a35 b5ea501eb535d570"),
	       12);

  test_chacha (SHEX("5555555555555555 5555555555555555"),
	       SHEX("5555555555555555"),
	       SHEX("357d7d94f966778f 5815a2051dcb0413"
		    "3b26b0ead9f57dd0 9927837bc3067e4b"
		    "6bf299ad81f7f50c 8da83c7810bfc17b"
		    "b6f4813ab6c32695 7045fd3fd5e19915"
		    ),
	       20);

  test_chacha (SHEX("5555555555555555 5555555555555555"
		    "5555555555555555 5555555555555555"),
	       SHEX("5555555555555555"),
	       SHEX("bea9411aa453c543 4a5ae8c92862f564"
		    "396855a9ea6e22d6 d3b50ae1b3663311"
		    "a4a3606c671d605c e16c3aece8e61ea1"
		    "45c59775017bee2f a6f88afc758069f7"),
	       20);

  /* TC6: Every odd bit set in key and IV. */
  test_chacha (SHEX("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"),
	       SHEX("aaaaaaaaaaaaaaaa"),
	       SHEX("312d95c0bc38eff4 942db2d50bdc500a"
		    "30641ef7132db1a8 ae838b3bea3a7ab0"
		    "3815d7a4cc09dbf5 882a3433d743aced"
		    "48136ebab7329950 6855c0f5437a36c6"),
	       8);

  test_chacha (SHEX("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"),
	       SHEX("aaaaaaaaaaaaaaaa"),
	       SHEX("057fe84fead13c24 b76bb2a6fdde66f2"
		    "688e8eb6268275c2 2c6bcb90b85616d7"
		    "fe4d3193a1036b70 d7fb864f01453641"
		    "851029ecdb60ac38 79f56496f16213f4"),
	       12);

  test_chacha (SHEX("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"),
	       SHEX("aaaaaaaaaaaaaaaa"),
	       SHEX("fc79acbd58526103 862776aab20f3b7d"
		    "8d3149b2fab65766 299316b6e5b16684"
		    "de5de548c1b7d083 efd9e3052319e0c6"
		    "254141da04a6586d f800f64d46b01c87"),
	       20);

  test_chacha (SHEX("aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"
		    "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa"),
	       SHEX("aaaaaaaaaaaaaaaa"),
	       SHEX("9aa2a9f656efde5a a7591c5fed4b35ae"
		    "a2895dec7cb4543b 9e9f21f5e7bcbcf3"
		    "c43c748a970888f8 248393a09d43e0b7"
		    "e164bc4d0b0fb240 a2d72115c4808906"),
	       20);

  /* TC7: Sequence patterns in key and IV. */
  test_chacha (SHEX("0011223344556677 8899aabbccddeeff"),
	       SHEX("0f1e2d3c4b5a6978"),
	       SHEX("29560d280b452840 0a8f4b795369fb3a"
		    "01105599e9f1ed58 279cfc9ece2dc5f9"
		    "9f1c2e52c98238f5 42a5c0a881d850b6"
		    "15d3acd9fbdb026e 9368565da50e0d49"),
	       8);

  test_chacha (SHEX("0011223344556677 8899aabbccddeeff"),
	       SHEX("0f1e2d3c4b5a6978"),
	       SHEX("5eddc2d9428fceee c50a52a964eae0ff"
		    "b04b2de006a9b04c ff368ffa921116b2"
		    "e8e264babd2efa0d e43ef2e3b6d065e8"
		    "f7c0a17837b0a40e b0e2c7a3742c8753"),
	       12);

  test_chacha (SHEX("0011223344556677 8899aabbccddeeff"),
	       SHEX("0f1e2d3c4b5a6978"),
	       SHEX("d1abf630467eb4f6 7f1cfb47cd626aae"
		    "8afedbbe4ff8fc5f e9cfae307e74ed45"
		    "1f1404425ad2b545 69d5f18148939971"
		    "abb8fafc88ce4ac7 fe1c3d1f7a1eb7ca"),
	       20);

  test_chacha (SHEX("0011223344556677 8899aabbccddeeff"
		    "ffeeddccbbaa9988 7766554433221100"),
	       SHEX("0f1e2d3c4b5a6978"),
	       SHEX("db43ad9d1e842d12 72e4530e276b3f56"
		    "8f8859b3f7cf6d9d 2c74fa53808cb515"
		    "7a8ebf46ad3dcc4b 6c7dadde131784b0"
		    "120e0e22f6d5f9ff a7407d4a21b695d9"),
	       8);

  /* TC8: hashed string patterns */
  test_chacha(SHEX("c46ec1b18ce8a878 725a37e780dfb735"),
	      SHEX("1ada31d5cf688221"),
	      SHEX("6a870108859f6791 18f3e205e2a56a68"
		   "26ef5a60a4102ac8 d4770059fcb7c7ba"
		   "e02f5ce004a6bfbb ea53014dd82107c0"
		   "aa1c7ce11b7d78f2 d50bd3602bbd2594"),
	      8);

  test_chacha(SHEX("c46ec1b18ce8a878 725a37e780dfb735"),
	      SHEX("1ada31d5cf688221"),
	      SHEX("b02bd81eb55c8f68 b5e9ca4e307079bc"
		   "225bd22007eddc67 02801820709ce098"
		   "07046a0d2aa552bf dbb49466176d56e3"
		   "2d519e10f5ad5f27 46e241e09bdf9959"),
	      12);

  test_chacha(SHEX("c46ec1b18ce8a878 725a37e780dfb735"),
	      SHEX("1ada31d5cf688221"),
	      SHEX("826abdd84460e2e9 349f0ef4af5b179b"
		   "426e4b2d109a9c5b b44000ae51bea90a"
		   "496beeef62a76850 ff3f0402c4ddc99f"
		   "6db07f151c1c0dfa c2e56565d6289625"),
	      20);

  test_chacha(SHEX("c46ec1b18ce8a878 725a37e780dfb735"
		   "1f68ed2e194c79fb c6aebee1a667975d"),
	      SHEX("1ada31d5cf688221"),
	      SHEX("f63a89b75c2271f9 368816542ba52f06"
		   "ed49241792302b00 b5e8f80ae9a473af"
		   "c25b218f519af0fd d406362e8d69de7f"
		   "54c604a6e00f353f 110f771bdca8ab92"),
	      20);
}
