#include "testutils.h"
#include "poly1305.h"
#include "poly1305-internal.h"
#include "knuth-lfib.h"

static void
check_digest (const char *name, void *ctx, nettle_hash_digest_func *f,
	      const struct tstring *msg,
	      const struct tstring *ref)
{
  uint8_t tag[16];
  ASSERT (ref->length == POLY1305_AES_DIGEST_SIZE);
  f(ctx, tag);
  if (!MEMEQ(ref->length, ref->data, tag))
    {
      printf ("%s failed\n", name);
      printf ("msg: "); print_hex (msg->length, msg->data);
      printf ("length: %u\n", (unsigned) msg->length);
      printf ("tag: "); print_hex (ref->length, tag);
      printf ("ref: "); print_hex (ref->length, ref->data);
      abort ();
    }

}

static void
test_poly1305 (const struct tstring *key,
	       const struct tstring *nonce,
	       const struct tstring *msg,
	       const struct tstring *ref)
{
  struct poly1305_aes_ctx ctx;

  ASSERT (key->length == POLY1305_AES_KEY_SIZE);
  ASSERT (ref->length == POLY1305_AES_DIGEST_SIZE);

  poly1305_aes_set_key (&ctx, key->data);
  poly1305_aes_set_nonce (&ctx, nonce->data);
  poly1305_aes_update(&ctx, msg->length, msg->data);

  check_digest ("poly1305-aes", &ctx, (nettle_hash_digest_func *) poly1305_aes_digest,
		msg, ref);
}

static void
poly1305_internal (const uint8_t key[16],
		   size_t length, const uint8_t *message,
		   union nettle_block16 *nonce)
{
  struct poly1305_ctx ctx;
  _nettle_poly1305_set_key (&ctx, key);

  for ( ; length >= 16; length -= 16, message += 16)
    _nettle_poly1305_block (&ctx, message, 1);
  if (length > 0)
    {
      uint8_t block[16];
      memcpy (block, message, length);
      block[length] = 1;
      memset (block + length + 1, 0, sizeof(block) - 1 - length);
      _nettle_poly1305_block (&ctx, block, 0);
    }
  _nettle_poly1305_digest (&ctx, nonce);
}

static void
ref_poly1305_internal (const uint8_t key[16],
		       size_t length, const uint8_t *message,
		       union nettle_block16 *nonce)
{
  uint8_t block[16];
  mpz_t p;
  mpz_t h;
  mpz_t r;
  mpz_t m;

  mpz_init_set_ui (p, 1);
  mpz_init (r);
  mpz_init_set_ui (h, 0);
  mpz_init (m);

  mpz_mul_2exp (p, p, 130);
  mpz_sub_ui (p, p, 5);

  memcpy (block, key, sizeof(block));
  block[3] &= 0x0f;
  block[4] &= 0xfc;
  block[7] &= 0x0f;
  block[8] &= 0xfc;
  block[11] &= 0x0f;
  block[12] &= 0xfc;
  block[15] &= 0x0f;

  /* Little-endian load */
  mpz_import (r, 16, -1, 1, 0, 0, block);

  for ( ; length >= 16; length -= 16, message += 16)
    {
      mpz_import (m, 16, -1, 1, 0, 0, message);
      mpz_setbit (m, 128);
      mpz_add (h, h, m);
      mpz_mul (h, h, r);
      mpz_mod (h, h, p);
    }
  if (length > 0)
    {
      mpz_import (m, length, -1, 1, 0, 0, message);
      mpz_setbit (m, length * 8);
      mpz_add (h, h, m);
      mpz_mul (h, h, r);
      mpz_mod (h, h, p);
    }
  mpz_import (m, 16, -1, 1, 0, 0, nonce->b);
  mpz_add (h, h, m);
  mpz_fdiv_r_2exp (h, h, 128);

  memset (nonce->b, 0, 16);
  mpz_export (nonce->b, NULL, -1, 1, 0, 0, h);

  mpz_clear (p);
  mpz_clear (r);
  mpz_clear (h);
  mpz_clear (m);
}

static void
test_poly1305_internal (const uint8_t key[16],
			size_t length, const uint8_t *message,
			const uint8_t nonce[16],
			const uint8_t ref[16])
{
  union nettle_block16 digest;

  memcpy (digest.b, nonce, sizeof(digest.b));
  poly1305_internal (key, length, message, &digest);

  if (!MEMEQ (sizeof(digest.b), digest.b, ref))
    {
      printf ("poly1305_internal failed\n");
      printf ("key: "); print_hex (16, key);
      printf ("nonce: "); print_hex (16, nonce);
      printf ("msg: "); print_hex (length, message);
      printf ("length: %u\n", (unsigned) length);
      printf ("tag: "); print_hex (16, digest.b);
      printf ("ref: "); print_hex (16, ref);
      abort();
    }
}

static void
test_fixed (void)
{
  static uint8_t nonce[16] = {0};
  static const struct {
    char *key;
    char *message;
    char *digest;
  } test_cases[] = {
    {"9959780624f5670ccc9e530738ddd70a",
     "82785d0bbe75181ea188c1a0d8dd81cf90d1c0f1cfa97912e92ab91bd3357368",
     "00000000000000000000000000000000"},
    {"6c72ea0dc487510934252a01544e9307",
     "0b6a6a734cb67fe9a548a81f21ec3db398c1ed1a62715e993e67f0a682b75990",
     "01000000000000000000000000000000"},
    {"64447e0bdca48e0a30c5af06ec830008",
     "1fd9b81b8310bdf6007549d6d06df6d07e37c8a8500edd91874a5657cff1c1ba",
     "faffffffffffffffffffffffffffffff"},
    {"054a840700390c092c422e037825c709",
     "3faabe212f024da30f8f7064d3dab6f426c5a408de0bec35624b6793a0d4a353",
     "05000000000000000000000000000000",}
  };
  size_t i;

  for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++)
    {
      struct tstring *key = tstring_hex(test_cases[i].key);
      struct tstring *message = tstring_hex(test_cases[i].message);
      struct tstring *digest = tstring_hex(test_cases[i].digest);
      union nettle_block16 out;
      ASSERT (key->length == 16);
      ASSERT (digest->length == 16);

      memset (out.b, 0, sizeof(out.b));
      test_poly1305_internal (key->data, message->length, message->data, nonce, digest->data);
    }
}

#define COUNT 10000
#define MAX_MESSAGE_SIZE 300

static void
test_random(void)
{
  struct knuth_lfib_ctx rand_ctx;
  unsigned j;

  knuth_lfib_init (&rand_ctx, 17);
  for (j = 0; j < COUNT; j++)
    {
      uint8_t key[16];
      uint8_t nonce[16];
      uint8_t message[MAX_MESSAGE_SIZE];
      size_t length;
      union nettle_block16 ref;

      knuth_lfib_random (&rand_ctx, sizeof(key), key);
      knuth_lfib_random (&rand_ctx, sizeof(nonce), nonce);

      knuth_lfib_random (&rand_ctx, sizeof(length), (uint8_t *) &length);
      length %= MAX_MESSAGE_SIZE + 1;

      knuth_lfib_random (&rand_ctx, length, message);

      memcpy (ref.b, nonce, sizeof(ref.b));
      ref_poly1305_internal (key, length, message, &ref);

      test_poly1305_internal (key, length, message, nonce, ref.b);
    }
}

static void
test_poly1305_mac(const struct tstring *r,
                  const struct tstring *s,
                  const struct tstring *msg,
                  const struct tstring *ref)
{
  struct poly1305_mac_ctx ctx;
  uint8_t tag[POLY1305_MAC_DIGEST_SIZE];
  unsigned i;

  ASSERT (r->length == POLY1305_MAC_R_SIZE);
  ASSERT (s->length == POLY1305_MAC_S_SIZE);
  ASSERT (ref->length == POLY1305_MAC_DIGEST_SIZE);

  poly1305_mac_set_key(&ctx, r->data);

  poly1305_mac_update(&ctx, msg->length, msg->data);
  poly1305_mac_digest(&ctx, s->data, tag);

  if (!MEMEQ(ref->length, ref->data, tag))
  {
    printf ("test_poly1305_mac failed\n");
    printf ("msg: "); print_hex (msg->length, msg->data);
    printf ("length: %u\n", (unsigned) msg->length);
    printf ("tag: "); print_hex (ref->length, tag);
    printf ("ref: "); print_hex (ref->length, ref->data);
    abort ();
  }

  /* attempt to re-use the structure */
  poly1305_mac_update(&ctx, msg->length, msg->data);
  poly1305_mac_digest(&ctx, s->data, tag);
  if (!MEMEQ(ref->length, ref->data, tag))
  {
    printf ("test_poly1305_mac on reu-use\n");
    printf ("msg: "); print_hex (msg->length, msg->data);
    printf ("length: %u\n", (unsigned) msg->length);
    printf ("tag: "); print_hex (ref->length, tag);
    printf ("ref: "); print_hex (ref->length, ref->data);
    abort ();
  }

  /* attempt byte-by-byte hashing */
  for (i=0;i<msg->length;i++)
    poly1305_mac_update (&ctx, 1, msg->data+i);
  poly1305_mac_digest(&ctx, s->data, tag);
  if (!MEMEQ(ref->length, ref->data, tag))
  {
    printf ("test_poly1305_mac on byte-by-byte\n");
    printf ("msg: "); print_hex (msg->length, msg->data);
    printf ("length: %u\n", (unsigned) msg->length);
    printf ("tag: "); print_hex (ref->length, tag);
    printf ("ref: "); print_hex (ref->length, ref->data);
    abort ();
  }
}

void
test_main(void)
{
  /* From Bernstein's paper. */
  test_poly1305
   (SHEX("75deaa25c09f208e1dc4ce6b5cad3fbfa0f3080000f46400d0c7e9076c834403"),
    SHEX("61ee09218d29b0aaed7e154a2c5509cc"),
    SHEX(""),
    SHEX("dd3fab2251f11ac759f0887129cc2ee7"));

  test_poly1305
   (SHEX("ec074c835580741701425b623235add6851fc40c3467ac0be05cc20404f3f700"),
    SHEX("fb447350c4e868c52ac3275cf9d4327e"),
    SHEX("f3f6"),
    SHEX("f4c633c3044fc145f84f335cb81953de"));

  test_poly1305
   (SHEX("6acb5f61a7176dd320c5c1eb2edcdc74"
         "48443d0bb0d21109c89a100b5ce2c208"),
    SHEX("ae212a55399729595dea458bc621ff0e"),
    SHEX("663cea190ffb83d89593f3f476b6bc24"
         "d7e679107ea26adb8caf6652d0656136"),
    SHEX("0ee1c16bb73f0f4fd19881753c01cdbe"));

  test_poly1305
   (SHEX("e1a5668a4d5b66a5f68cc5424ed5982d12976a08c4426d0ce8a82407c4f48207"),
    SHEX("9ae831e743978d3a23527c7128149e3a"),
    SHEX("ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491"
         "faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb2109"
         "5c1bf9"),
    SHEX("5154ad0d2cb26e01274fc51148491f1b"));

  test_fixed();
  test_random();

  /* From RFC 8439 */
  test_poly1305_mac
    (SHEX("85d6be7857556d337f4452fe42d506a8"),
     SHEX("0103808afb0db2fd4abff6af4149f51b"),
     SHEX("43727970746f6772617068696320466f72756d2052657365617263682047726f7570"),
     SHEX("a8061dc1305136c6c22b8baf0c0127a9"));

  test_poly1305_mac
    (SHEX("00000000000000000000000000000000"),
     SHEX("00000000000000000000000000000000"),
     SHEX("00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"),
     SHEX("00000000000000000000000000000000"));

  test_poly1305_mac
    (SHEX("00000000000000000000000000000000"),
     SHEX("36e5f6b5c5e06070f0efca96227a863e"),
     SHEX("416e79207375626d697373696f6e2074"
          "6f20746865204945544620696e74656e"
          "6465642062792074686520436f6e7472"
          "696275746f7220666f72207075626c69"
          "636174696f6e20617320616c6c206f72"
          "2070617274206f6620616e2049455446"
          "20496e7465726e65742d447261667420"
          "6f722052464320616e6420616e792073"
          "746174656d656e74206d616465207769"
          "7468696e2074686520636f6e74657874"
          "206f6620616e20494554462061637469"
          "7669747920697320636f6e7369646572"
          "656420616e20224945544620436f6e74"
          "7269627574696f6e222e205375636820"
          "73746174656d656e747320696e636c75"
          "6465206f72616c2073746174656d656e"
          "747320696e2049455446207365737369"
          "6f6e732c2061732077656c6c20617320"
          "7772697474656e20616e6420656c6563"
          "74726f6e696320636f6d6d756e696361"
          "74696f6e73206d61646520617420616e"
          "792074696d65206f7220706c6163652c"
          "20776869636820617265206164647265"
          "7373656420746f"),
     SHEX("36e5f6b5c5e06070f0efca96227a863e"));

  test_poly1305_mac
    (SHEX("36e5f6b5c5e06070f0efca96227a863e"),
     SHEX("00000000000000000000000000000000"),
     SHEX("416e79207375626d697373696f6e2074"
          "6f20746865204945544620696e74656e"
          "6465642062792074686520436f6e7472"
          "696275746f7220666f72207075626c69"
          "636174696f6e20617320616c6c206f72"
          "2070617274206f6620616e2049455446"
          "20496e7465726e65742d447261667420"
          "6f722052464320616e6420616e792073"
          "746174656d656e74206d616465207769"
          "7468696e2074686520636f6e74657874"
          "206f6620616e20494554462061637469"
          "7669747920697320636f6e7369646572"
          "656420616e20224945544620436f6e74"
          "7269627574696f6e222e205375636820"
          "73746174656d656e747320696e636c75"
          "6465206f72616c2073746174656d656e"
          "747320696e2049455446207365737369"
          "6f6e732c2061732077656c6c20617320"
          "7772697474656e20616e6420656c6563"
          "74726f6e696320636f6d6d756e696361"
          "74696f6e73206d61646520617420616e"
          "792074696d65206f7220706c6163652c"
          "20776869636820617265206164647265"
          "7373656420746f"),
     SHEX("f3477e7cd95417af89a6b8794c310cf0"));

  test_poly1305_mac
    (SHEX("1c9240a5eb55d38af333888604f6b5f0"),
     SHEX("473917c1402b80099dca5cbc207075c0"),
     SHEX("2754776173206272696c6c69672c2061"
          "6e642074686520736c6974687920746f"
          "7665730a446964206779726520616e64"
          "2067696d626c6520696e207468652077"
          "6162653a0a416c6c206d696d73792077"
          "6572652074686520626f726f676f7665"
          "732c0a416e6420746865206d6f6d6520"
          "7261746873206f757467726162652e"),
     SHEX("4541669a7eaaee61e708dc7cbcc5eb62"));

  test_poly1305_mac
    (SHEX("02000000000000000000000000000000"),
     SHEX("00000000000000000000000000000000"),
     SHEX("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
     SHEX("03000000000000000000000000000000"));

  test_poly1305_mac
    (SHEX("02000000000000000000000000000000"),
     SHEX("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
     SHEX("02000000000000000000000000000000"),
     SHEX("03000000000000000000000000000000"));

  test_poly1305_mac
    (SHEX("01000000000000000000000000000000"),
     SHEX("00000000000000000000000000000000"),
     SHEX("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
          "F0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
          "11000000000000000000000000000000"),
     SHEX("05000000000000000000000000000000"));

  test_poly1305_mac
    (SHEX("01000000000000000000000000000000"),
     SHEX("00000000000000000000000000000000"),
     SHEX("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
          "FBFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE"
          "01010101010101010101010101010101"),
     SHEX("00000000000000000000000000000000"));

  test_poly1305_mac
    (SHEX("02000000000000000000000000000000"),
     SHEX("00000000000000000000000000000000"),
     SHEX("FDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
     SHEX("FAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));

  test_poly1305_mac
    (SHEX("01000000000000000400000000000000"),
     SHEX("00000000000000000000000000000000"),
     SHEX("E33594D7505E43B90000000000000000"
          "3394D7505E4379CD0100000000000000"
          "00000000000000000000000000000000"
          "01000000000000000000000000000000"),
     SHEX("14000000000000005500000000000000"));

  test_poly1305_mac
    (SHEX("01000000000000000400000000000000"),
     SHEX("00000000000000000000000000000000"),
     SHEX("E33594D7505E43B90000000000000000"
          "3394D7505E4379CD0100000000000000"
          "00000000000000000000000000000000"),
     SHEX("13000000000000000000000000000000"));
}
