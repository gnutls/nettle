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
}
