/* testutils.c */

#include "testutils.h"

#include "cbc.h"
#include "knuth-lfib.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* For getopt() */
#include <unistd.h>

/* -1 means invalid */
static const signed char hex_digits[0x100] =
  {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  };

unsigned
decode_hex_length(const char *h)
{
  const unsigned char *hex = (const unsigned char *) h;
  unsigned count;
  unsigned i;
  
  for (count = i = 0; hex[i]; i++)
    {
      if (isspace(hex[i]))
	continue;
      if (hex_digits[hex[i]] < 0)
	abort();
      count++;
    }

  if (count % 2)
    abort();
  return count / 2;  
}

int
decode_hex(uint8_t *dst, const char *h)
{  
  const unsigned char *hex = (const unsigned char *) h;
  unsigned i = 0;
  
  for (;;)
  {
    int high, low;
    
    while (*hex && isspace(*hex))
      hex++;

    if (!*hex)
      return 1;

    high = hex_digits[*hex++];
    if (high < 0)
      return 0;

    while (*hex && isspace(*hex))
      hex++;

    if (!*hex)
      return 0;

    low = hex_digits[*hex++];
    if (low < 0)
      return 0;

    dst[i++] = (high << 4) | low;
  }
}

const uint8_t *
decode_hex_dup(const char *hex)
{
  uint8_t *p;
  unsigned length = decode_hex_length(hex);

  p = malloc(length);
  if (!p)
    abort();

  if (decode_hex(p, hex))
    return p;
  else
    {
      free(p);
      return NULL;
    }
}

void
print_hex(unsigned length, uint8_t *data)
{
  unsigned i;
  
  for (i = 0; i < length; i++)
    {
      if (! (i % 8))
        printf(" ");
      printf("%02x", data[i]);
    }
}

int verbose = 0;

int
main(int argc, char **argv)
{
  int c;

  while ((c = getopt (argc, argv, "v")) != -1)
    switch (c)
      {
      case 'v':
	verbose = 1;
	break;
      case '?':
	if (isprint (optopt))
	  fprintf (stderr, "Unknown option `-%c'.\n", optopt);
	else
	  fprintf (stderr,
		   "Unknown option character `\\x%x'.\n",
		   optopt);
      default:
	abort();
      }

  return test_main();
}

void
test_cipher(const struct nettle_cipher *cipher,
	    unsigned key_length,
	    const uint8_t *key,
	    unsigned length,
	    const uint8_t *cleartext,
	    const uint8_t *ciphertext)
{
  void *ctx = alloca(cipher->context_size);
  uint8_t *data = alloca(length);

  cipher->set_encrypt_key(ctx, key_length, key);
  cipher->encrypt(ctx, length, data, cleartext);

  if (!MEMEQ(length, data, ciphertext))
    FAIL();

  cipher->set_decrypt_key(ctx, key_length, key);
  cipher->decrypt(ctx, length, data, data);

  if (!MEMEQ(length, data, cleartext))
    FAIL();
}

void
test_cipher_cbc(const struct nettle_cipher *cipher,
		unsigned key_length,
		const uint8_t *key,
		unsigned length,
		const uint8_t *cleartext,
		const uint8_t *ciphertext,
		const uint8_t *iiv)
{
  void *ctx = alloca(cipher->context_size);
  uint8_t *data = alloca(length);
  uint8_t *iv = alloca(cipher->block_size);
  
  cipher->set_encrypt_key(ctx, key_length, key);
  memcpy(iv, iiv, cipher->block_size);

  cbc_encrypt(ctx, cipher->encrypt,
	      cipher->block_size, iv,
	      length, data, cleartext);

  if (!MEMEQ(length, data, ciphertext))
    FAIL();

  cipher->set_decrypt_key(ctx, key_length, key);
  memcpy(iv, iiv, cipher->block_size);

  cbc_decrypt(ctx, cipher->decrypt,
	      cipher->block_size, iv,
	      length, data, data);

  if (!MEMEQ(length, data, cleartext))
    FAIL();
}

void
test_hash(const struct nettle_hash *hash,
	  unsigned length,
	  const uint8_t *data,
	  const uint8_t *digest)
{
  void *ctx = alloca(hash->context_size);
  uint8_t *buffer = alloca(hash->digest_size);

  hash->init(ctx);
  hash->update(ctx, length, data);
  hash->digest(ctx, hash->digest_size, buffer);

  if (!MEMEQ(hash->digest_size, digest, buffer))
    FAIL();

  memset(buffer, 0, hash->digest_size);

  hash->init(ctx);
  hash->update(ctx, length, data);
  hash->digest(ctx, hash->digest_size - 1, buffer);

  if (!MEMEQ(hash->digest_size - 1, digest, buffer))
    FAIL();

  if (buffer[hash->digest_size - 1])
    FAIL();
}

void
test_armor(const struct nettle_armor *armor,
           unsigned data_length,
           const uint8_t *data,
           const uint8_t *ascii)
{
  void *ctx = alloca(armor->context_size);
  uint8_t *buffer = alloca(1 + strlen(ascii));
  uint8_t *check = alloca(1 + data_length);

  memset(buffer, 0x33, 1 + strlen(ascii));
  memset(check, 0x55, 1 + data_length);

  if (strlen(ascii) != armor->encode(buffer, data_length, data))
    FAIL();

  if (!MEMEQ(strlen(ascii), buffer, ascii))
    FAIL();

  if (0x33 != buffer[strlen(ascii)])
    FAIL();  

  armor->decode_init(ctx);
  if (data_length != armor->decode_update(ctx, check, strlen(ascii), buffer))
    FAIL();

  if (!MEMEQ(data_length, check, data))
    FAIL();

  if (0x55 != check[data_length])
    FAIL();
}

#if HAVE_LIBGMP
/* Missing in current gmp */
static void
mpz_togglebit (mpz_t x, unsigned long int bit)
{
  if (mpz_tstbit(x, bit))
    mpz_clrbit(x, bit);
  else
    mpz_setbit(x, bit);
}
#endif /* HAVE_LIBGMP */

#if WITH_PUBLIC_KEY
#define SIGN(key, hash, msg, signature) do {	\
  hash##_update(&hash, LDATA(msg));		\
  rsa_##hash##_sign(key, &hash, signature);	\
} while(0)

#define VERIFY(key, hash, msg, signature) (	\
  hash##_update(&hash, LDATA(msg)),		\
  rsa_##hash##_verify(key, &hash, signature)	\
)

void
test_rsa_md5(struct rsa_public_key *pub,
	     struct rsa_private_key *key,
	     mpz_t expected)
{
  struct md5_ctx md5;
  mpz_t signature;

  md5_init(&md5);
  mpz_init(signature);
  
  SIGN(key, md5, "The magic words are squeamish ossifrage", signature);

  if (verbose)
    {
      fprintf(stderr, "rsa-md5 signature: ");
      mpz_out_str(stderr, 16, signature);
      fprintf(stderr, "\n");
    }

  if (mpz_cmp(signature, expected))
    FAIL();
  
  /* Try bad data */
  if (VERIFY(pub, md5,
	     "The magick words are squeamish ossifrage", signature))
    FAIL();

  /* Try correct data */
  if (!VERIFY(pub, md5,
	      "The magic words are squeamish ossifrage", signature))
    FAIL();

  /* Try bad signature */
  mpz_togglebit(signature, 17);

  if (VERIFY(pub, md5,
	     "The magic words are squeamish ossifrage", signature))
    FAIL();

  mpz_clear(signature);
}

void
test_rsa_sha1(struct rsa_public_key *pub,
	     struct rsa_private_key *key,
	     mpz_t expected)
{
  struct sha1_ctx sha1;
  mpz_t signature;

  sha1_init(&sha1);
  mpz_init(signature);

  SIGN(key, sha1, "The magic words are squeamish ossifrage", signature);

  if (verbose)
    {
      fprintf(stderr, "rsa-sha1 signature: ");
      mpz_out_str(stderr, 16, signature);
      fprintf(stderr, "\n");
    }

  if (mpz_cmp(signature, expected))
    FAIL();
  
  /* Try bad data */
  if (VERIFY(pub, sha1,
	     "The magick words are squeamish ossifrage", signature))
    FAIL();

  /* Try correct data */
  if (!VERIFY(pub, sha1,
	      "The magic words are squeamish ossifrage", signature))
    FAIL();

  /* Try bad signature */
  mpz_togglebit(signature, 17);

  if (VERIFY(pub, sha1,
	     "The magic words are squeamish ossifrage", signature))
    FAIL();

  mpz_clear(signature);
}

#undef SIGN
#undef VERIFY

void
test_rsa_key(struct rsa_public_key *pub,
	     struct rsa_private_key *key)
{
  mpz_t tmp;
  mpz_t phi;
  
  mpz_init(tmp); mpz_init(phi);
  
  if (verbose)
    {
      /* FIXME: Use gmp_printf */
      fprintf(stderr, "Public key: n=");
      mpz_out_str(stderr, 16, pub->n);
      fprintf(stderr, "\n    e=");
      mpz_out_str(stderr, 16, pub->e);

      fprintf(stderr, "\n\nPrivate key: d=");
      mpz_out_str(stderr, 16, key->d);
      fprintf(stderr, "\n    p=");
      mpz_out_str(stderr, 16, key->p);
      fprintf(stderr, "\n    q=");
      mpz_out_str(stderr, 16, key->q);
      fprintf(stderr, "\n    a=");
      mpz_out_str(stderr, 16, key->a);
      fprintf(stderr, "\n    b=");
      mpz_out_str(stderr, 16, key->b);
      fprintf(stderr, "\n    c=");
      mpz_out_str(stderr, 16, key->c);
      fprintf(stderr, "\n\n");
    }

  /* Check n = p q */
  mpz_mul(tmp, key->p, key->q);
  if (mpz_cmp(tmp, pub->n))
    FAIL();

  /* Check c q = 1 mod p */
  mpz_mul(tmp, key->c, key->q);
  mpz_fdiv_r(tmp, tmp, key->p);
  if (mpz_cmp_ui(tmp, 1))
    FAIL();

  /* Check ed = 1 (mod phi) */
  mpz_sub_ui(phi, key->p, 1);
  mpz_sub_ui(tmp, key->q, 1);

  mpz_mul(phi, phi, tmp);

  mpz_mul(tmp, pub->e, key->d);
  mpz_fdiv_r(tmp, tmp, phi);
  if (mpz_cmp_ui(tmp, 1))
    FAIL();

  /* Check a e = 1 (mod (p-1) ) */
  mpz_sub_ui(phi, key->p, 1);
  mpz_mul(tmp, pub->e, key->a);
  mpz_fdiv_r(tmp, tmp, phi);
  if (mpz_cmp_ui(tmp, 1))
    FAIL();
  
  /* Check b e = 1 (mod (q-1) ) */
  mpz_sub_ui(phi, key->q, 1);
  mpz_mul(tmp, pub->e, key->b);
  mpz_fdiv_r(tmp, tmp, phi);
  if (mpz_cmp_ui(tmp, 1))
    FAIL();
  
  mpz_clear(tmp); mpz_clear(phi);
}

#define DSA_VERIFY(key, hash, msg, signature) (	\
  sha1_update(hash, LDATA(msg)),		\
  dsa_verify(key, hash, signature)		\
)

void
test_dsa(struct dsa_private_key *key)
{
  struct sha1_ctx sha1;
  struct dsa_signature signature;
  struct knuth_lfib_ctx lfib;
  
  sha1_init(&sha1);
  dsa_signature_init(&signature);
  knuth_lfib_init(&lfib, 1111);
  
  sha1_update(&sha1, LDATA("The magic words are squeamish ossifrage"));
  dsa_sign(key,
	   &lfib, (nettle_random_func) knuth_lfib_random,
	   &sha1, &signature);
  
  if (verbose)
    {
      fprintf(stderr, "dsa signature: ");
      mpz_out_str(stderr, 16, signature.r);
      fprintf(stderr, ", ");
      mpz_out_str(stderr, 16, signature.s);
      fprintf(stderr, "\n");
    }

#if 0
  if (mpz_cmp(signature, expected))
    FAIL();
#endif
  
  /* Try bad data */
  if (DSA_VERIFY(&key->pub, &sha1,
		 "The magick words are squeamish ossifrage", &signature))
    FAIL();

  /* Try correct data */
  if (!DSA_VERIFY(&key->pub, &sha1,
		 "The magic words are squeamish ossifrage", &signature))
    FAIL();

  /* Try bad signature */
  mpz_togglebit(signature.r, 17);

  if (DSA_VERIFY(&key->pub, &sha1,
		 "The magic words are squeamish ossifrage", &signature))
    FAIL();

  dsa_signature_clear(&signature);
}

#endif /* WITH_PUBLIC_KEY */

