/* rsa_sha1.c
 *
 * Signatures using RSA and SHA1.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001 Niels Möller
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
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#if WITH_PUBLIC_KEY

#include "rsa.h"

#include "bignum.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Forward declarations */
static void
pkcs1_encode_sha1(mpz_t m, unsigned length, struct sha1_ctx *hash);

void
rsa_sha1_sign(struct rsa_private_key *key,
              struct sha1_ctx *hash,
              mpz_t s)
{
  assert(key->size >= 45);

  pkcs1_encode_sha1(s, key->size - 1, hash);

  rsa_compute_root(key, s, s);
}

int
rsa_sha1_verify(struct rsa_public_key *key,
                struct sha1_ctx *hash,
                const mpz_t s)
{
  int res;
  
  mpz_t m1;
  mpz_t m2;

  if ( (mpz_sgn(s) <= 0)
       || (mpz_cmp(s, key->n) >= 0) )
    return 0;

  mpz_init(m1); mpz_init(m2);
  
  mpz_powm(m1, s, key->e, key->n);

  /* FIXME: Is it cheaper to convert s to a string and check that? */
  pkcs1_encode_sha1(m2, key->size - 1, hash);
  res = !mpz_cmp(m1, m2);

  mpz_clear(m1); mpz_clear(m2);
  
  return res;
}

/* From pkcs-1v2
 *
 *   id-sha1 OBJECT IDENTIFIER ::=
 *     {iso(1) identified-organization(3) oiw(14) secsig(3)
 *   	 algorithms(2) 26}
 *   
 *   The default hash function is SHA-1: 
 *   sha1Identifier ::= AlgorithmIdentifier {id-sha1, NULL}
 */

static const uint8_t
sha1_prefix[] =
{
  /* 15 octets prefix, 20 octets hash, total 35 */
  0x30,       33, /* SEQUENCE */
    0x30,      9, /* SEQUENCE */
      0x06,    5, /* OBJECT IDENTIFIER */
  	  0x2b, 0x0e, 0x03, 0x02, 0x1a,
      0x05,    0, /* NULL */
    0x04,     20  /* OCTET STRING */
      /* Here comes the raw hash value */
};
    
static void
pkcs1_encode_sha1(mpz_t m, unsigned length, struct sha1_ctx *hash)
{
  uint8_t *em = alloca(length);
  unsigned i;

  assert(length >= SHA1_DIGEST_SIZE);

  i = length - SHA1_DIGEST_SIZE;
  
  sha1_digest(hash, SHA1_DIGEST_SIZE, em + i);

  assert(i >= sizeof(sha1_prefix));

  i -= sizeof(sha1_prefix);
  memcpy(em + i, sha1_prefix, sizeof(sha1_prefix));

  assert(i);
  em[--i] = 0;

  assert(i >= 9);

  em[0] = 1;
  memset(em + 1, 0xff, i - 1);

  nettle_mpz_set_str_256(m, length, em);
}

#endif /* WITH_PUBLIC_KEY */
