#ifndef NETTLE_TESTUTILS_H_INCLUDED
#define NETTLE_TESTUTILS_H_INCLUDED

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <inttypes.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if HAVE_LIBGMP
# include "rsa.h"
#endif

#include "nettle-meta.h"

/* Decodes a NUL-terminated hex string. */

unsigned
decode_hex_length(const char *hex);

int
decode_hex(uint8_t *dst, const char *hex);

/* Allocates space */
const uint8_t *
decode_hex_dup(const char *hex);

/* The main program */
int
test_main(void);

extern int verbose;

void
test_cipher(const struct nettle_cipher *cipher,
	    unsigned key_length,
	    const uint8_t *key,
	    unsigned length,
	    const uint8_t *cleartext,
	    const uint8_t *ciphertext);

void
test_cipher_cbc(const struct nettle_cipher *cipher,
		unsigned key_length,
		const uint8_t *key,
		unsigned length,
		const uint8_t *cleartext,
		const uint8_t *ciphertext,
		const uint8_t *iv);

void
test_hash(const struct nettle_hash *hash,
	  unsigned length,
	  const uint8_t *data,
	  const uint8_t *digest);

#if HAVE_LIBGMP
void
test_rsa_md5(struct rsa_public_key *pub,
	     struct rsa_private_key *key,
	     mpz_t expected);

void
test_rsa_sha1(struct rsa_public_key *pub,
	      struct rsa_private_key *key,
	      mpz_t expected);
#endif /* HAVE_LIBGMP */

#define H2(d, s) decode_hex((d), (s))
#define H(x) decode_hex_dup(x)
#define HL(x) decode_hex_length(x), decode_hex_dup(x)

#define LDATA(x) strlen(x), x

#define MEMEQ(length, a, b) (!memcmp((a), (b), (length)))

#define FAIL() abort()
#define SKIP() exit(77)
#define SUCCESS() return EXIT_SUCCESS

#endif /* NETTLE_TESTUTILS_H_INCLUDED */
