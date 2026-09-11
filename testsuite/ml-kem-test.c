/* ml-kem-test.c

   Copyright (C) 2025 Red Hat, Inc.
   Copyright (C) 2026 Niels Möller

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

#include "knuth-lfib.h"
#include "ml-kem-internal.h"

struct ml_kem_alg {
  size_t public_key_size;
  size_t private_key_size;
  size_t ciphertext_size;
  size_t inner_private_key_size;

  size_t (*generate_itch)(void);
  void (*generate)(uint8_t *pub, uint8_t *key,
		   const uint8_t *seed,
		   uint16_t *scratch);
  size_t (*encap_itch)(void);
  void (*encap)(const uint8_t *pub,
		uint8_t *secret, uint8_t *ciphertext,
		void *random_ctx, nettle_random_func *random,
		uint16_t *scratch);
  size_t (*decap_itch)(void);
  void (*decap)(const uint8_t *key,
		uint8_t *secret,
		const uint8_t *ciphertext,
		uint16_t *scratch);
};

static const struct ml_kem_alg
ml_kem_768 = {
  ML_KEM_768_PUBLIC_KEY_SIZE,
  ML_KEM_768_PRIVATE_KEY_SIZE,
  ML_KEM_768_CIPHERTEXT_SIZE,
  ML_KEM_768_INNER_PRIVATE_KEY_SIZE,
  ml_kem_768_generate_keypair_itch,
  ml_kem_768_generate_keypair,
  ml_kem_768_encap_itch,
  ml_kem_768_encap,
  ml_kem_768_decap_itch,
  ml_kem_768_decap,
};

static const struct ml_kem_alg
ml_kem_1024 = {
  ML_KEM_1024_PUBLIC_KEY_SIZE,
  ML_KEM_1024_PRIVATE_KEY_SIZE,
  ML_KEM_1024_CIPHERTEXT_SIZE,
  ML_KEM_1024_INNER_PRIVATE_KEY_SIZE,
  ml_kem_1024_generate_keypair_itch,
  ml_kem_1024_generate_keypair,
  ml_kem_1024_encap_itch,
  ml_kem_1024_encap,
  ml_kem_1024_decap_itch,
  ml_kem_1024_decap,
};

static void
random_from_seed (struct tstring *seed, size_t n, uint8_t *dst)
{
  ASSERT (n <= seed->length);
  memcpy (dst, seed->data, n);
}

static void
test_ml_kem_generate_keypair (const struct ml_kem_alg *alg,
			      const struct tstring *seed,
			      const struct tstring *pk,
			      const struct tstring *sk)
{
  uint8_t *pub;
  uint8_t *key;
  uint16_t *scratch;

  ASSERT (seed->length == ML_KEM_SEED_SIZE);
  ASSERT (pk->length == alg->public_key_size);
  ASSERT (sk->length == alg->private_key_size);

  pub = xalloc (alg->public_key_size);
  key = xalloc (alg->private_key_size);
  scratch = xalloc (alg->generate_itch () * sizeof(uint16_t));

  alg->generate (pub, key, seed->data, scratch);

  ASSERT (MEMEQ (pk->length, pk->data, pub));
  ASSERT (MEMEQ (sk->length, sk->data, key));
  free (pub);
  free (key);
  free (scratch);
}

static void
test_ml_kem_encap (const struct ml_kem_alg *alg,
		   const struct tstring *pk,
		   const struct tstring *seed,
		   const struct tstring *ciphertext,
		   const struct tstring *secret)
{
  uint8_t *ciphertext2;
  uint8_t secret2[32];
  uint16_t *scratch;

  ASSERT (pk->length == alg->public_key_size);
  ASSERT (seed->length == 32);
  ASSERT (ciphertext->length == alg->ciphertext_size);
  ASSERT (secret->length == ML_KEM_SESSION_KEY_SIZE);

  ciphertext2 = xalloc (alg->ciphertext_size);
  scratch = xalloc (alg->encap_itch () * sizeof(uint16_t));

  mark_bytes_undefined (seed->length, seed->data);

  alg->encap (pk->data, secret2, ciphertext2,
	      (void *)seed, (nettle_random_func *)random_from_seed,
	      scratch);

  mark_bytes_defined (alg->ciphertext_size, ciphertext2);
  mark_bytes_defined (sizeof(secret2), secret2);

  ASSERT (MEMEQ (ciphertext->length, ciphertext->data, ciphertext2));
  ASSERT (MEMEQ (secret->length, secret->data, secret2));

  free (ciphertext2);
  free (scratch);
}

static void
test_ml_kem_decap (const struct ml_kem_alg *alg,
		   const struct tstring *sk,
		   const struct tstring *ciphertext,
		   const struct tstring *secret)
{
  uint8_t secret2[32];
  uint16_t *scratch;

  ASSERT (sk->length == alg->private_key_size);
  ASSERT (ciphertext->length == alg->ciphertext_size);
  ASSERT (secret->length == ML_KEM_SESSION_KEY_SIZE);

  scratch = xalloc (alg->decap_itch () * sizeof(uint16_t));

  mark_bytes_undefined (alg->inner_private_key_size, sk->data);

  alg->decap (sk->data, secret2, ciphertext->data, scratch);

  mark_bytes_defined (sizeof(secret2), secret2);

  ASSERT (MEMEQ (secret->length, secret->data, secret2));

  free (scratch);
}

static void
test_ml_kem_encap_decap (const struct ml_kem_alg *alg,
			 const struct tstring *pk,
			 const struct tstring *sk,
			 const struct tstring *seed,
			 const struct tstring *ciphertext,
			 const struct tstring *secret)
{
  test_ml_kem_encap (alg, pk, seed, ciphertext, secret);
  test_ml_kem_decap (alg, sk, ciphertext, secret);
}

static void
test_ml_kem_pairwise (const struct ml_kem_alg *alg,
		      void *random_ctx, nettle_random_func *random)
{
  uint8_t *pub;
  uint8_t *key;
  uint8_t *ciphertext;
  uint8_t seed[ML_KEM_SEED_SIZE];
  uint8_t secret[ML_KEM_SESSION_KEY_SIZE];
  uint8_t secret2[ML_KEM_SESSION_KEY_SIZE];
  uint16_t *scratch;

  pub = xalloc (alg->public_key_size);
  key = xalloc (alg->private_key_size);
  ciphertext = xalloc (alg->ciphertext_size);

  scratch = xalloc (alg->generate_itch () * sizeof(uint16_t));
  random (random_ctx, sizeof (seed), seed);
  alg->generate (pub, key, seed, scratch);
  free (scratch);

  scratch = xalloc (alg->encap_itch () * sizeof(uint16_t));
  alg->encap (pub, secret, ciphertext,
	      random_ctx, random, scratch);
  free (scratch);

  scratch = xalloc (alg->decap_itch () * sizeof(uint16_t));
  alg->decap (key, secret2, ciphertext, scratch);
  free (scratch);

  ASSERT (MEMEQ (ML_KEM_SESSION_KEY_SIZE, secret2, secret));

  free (pub);
  free (key);
  free (ciphertext);
}

static void
test_randomized (void)
{
  struct knuth_lfib_ctx lfib;
  unsigned count;
  unsigned end_count = test_side_channel ? 10 : 1000;
  /* FIXME: Use a stronger randomness generator with 64-bit seed. */
  knuth_lfib_init (&lfib, test_get_seed ());
  end_count = test_side_channel ? 10 : 1000;
  for (count = 0; count < end_count; count++)
    {
      test_ml_kem_pairwise (&ml_kem_768,
			    &lfib, (nettle_random_func *) knuth_lfib_random);
      test_ml_kem_pairwise (&ml_kem_1024,
			    &lfib, (nettle_random_func *) knuth_lfib_random);
    }
}

void
test_main (void)
{
#if WITH_EXTRA_ASSERTS
  if (test_side_channel)
    SKIP();
#endif

  /* Test vectors from: https://github.com/usnistgov/ACVP-Server/tree/d98cad66639bf9d0822129c4bcae7a169fcf9ca6/gen-val/json-files/ML-KEM-keyGen-FIPS203 */

  /* tcId: 26 */
  test_ml_kem_generate_keypair (&ml_kem_768,
				SHEX ("A2B4BCA315A6EA4600B4A316E09A2578AA1E8BCE919C8DF3A96C71C843F5B38B"
				      "D6BF055CB7B375E3271ED131F1BA31F83FEF533A239878A71074578B891265D1"),
				read_hex_file ("ml-kem-768-keygen-tc26.pk", ML_KEM_768_PUBLIC_KEY_SIZE),
				read_hex_file ("ml-kem-768-keygen-tc26.sk", ML_KEM_768_PRIVATE_KEY_SIZE));

  /* tcId: 51 */
  test_ml_kem_generate_keypair (&ml_kem_1024,
				SHEX ("2B5330C4F23BFDFD5C31F050BA3B38235324BF032372FC12D04DD08920F0BD59"
				      "0A064D6C06CEAB73E59CFCA9FF6402255A326AEF1E9CB678BF36929DAFE29A58"),
				read_hex_file ("ml-kem-1024-keygen-tc51.pk", ML_KEM_1024_PUBLIC_KEY_SIZE),
				read_hex_file ("ml-kem-1024-keygen-tc51.sk", ML_KEM_1024_PRIVATE_KEY_SIZE));

  /* Test vectors from: https://github.com/usnistgov/ACVP-Server/tree/d98cad66639bf9d0822129c4bcae7a169fcf9ca6/gen-val/json-files/ML-KEM-encapDecap-FIPS203 */

  /* tcId: 26 */
  test_ml_kem_encap_decap (&ml_kem_768,
			   read_hex_file ("ml-kem-768-encapdecap-tc26.pk", ML_KEM_768_PUBLIC_KEY_SIZE),
			   read_hex_file ("ml-kem-768-encapdecap-tc26.sk", ML_KEM_768_PRIVATE_KEY_SIZE),
			   SHEX ("5BD922AF345AB90F297D0A82EA39527A648E4977AB56242E2AC0ED9A2CC66F10"),
			   read_hex_file ("ml-kem-768-encapdecap-tc26.ct", ML_KEM_768_CIPHERTEXT_SIZE),
			   SHEX ("B2425299020BCF563B8EBE0512F0479941335A75A32B8D10BFF60E5548B64672"));

  /* tcId: 51 */
  test_ml_kem_encap_decap (&ml_kem_1024,
			   read_hex_file ("ml-kem-1024-encapdecap-tc51.pk", ML_KEM_1024_PUBLIC_KEY_SIZE),
			   read_hex_file ("ml-kem-1024-encapdecap-tc51.sk", ML_KEM_1024_PRIVATE_KEY_SIZE),
			   SHEX ("8199CF923CE12126920108569C11CBF97CF03F44AF5CFA7D550E9B2AC7431982"),
			   read_hex_file ("ml-kem-1024-encapdecap-tc51.ct", ML_KEM_1024_CIPHERTEXT_SIZE),
			   SHEX ("5D537CD0EF7B58F0FE95370473B96878F138ECC259ADFBF77EBD7328B822D9D9"));

  test_randomized ();
}
