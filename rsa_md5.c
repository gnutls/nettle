/* rsa_md5.c
 *
 * Signatures using RSA and MD5.
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
pkcs1_encode_md5(mpz_t m, unsigned length, struct md5_ctx *hash);

void
rsa_md5_sign(struct rsa_private_key *key,
             struct md5_ctx *hash,
             mpz_t s)
{
  assert(key->size >= 45);

  pkcs1_encode_md5(s, key->size - 1, hash);

  rsa_compute_root(key, s, s);
}

int
rsa_md5_verify(struct rsa_public_key *key,
               struct md5_ctx *hash,
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

  /* FIXME: Is it cheaper to convert m1 to a string and check that? */
  pkcs1_encode_md5(m2, key->size - 1, hash);
  res = !mpz_cmp(m1, m2);

  mpz_clear(m1); mpz_clear(m2);

  return res;
}

/* From pkcs-1v2
 *
 *   md5 OBJECT IDENTIFIER ::=
 *     {iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 5}
 *
 * The parameters part of the algorithm identifier is NULL:
 *
 *   md5Identifier ::= AlgorithmIdentifier {md5, NULL}
 */

static const uint8_t
md5_prefix[] =
{
  /* 18 octets prefix, 16 octets hash, 34 total. */
  0x30,       32, /* SEQUENCE */
    0x30,     12, /* SEQUENCE */
      0x06,    8, /* OBJECT IDENTIFIER */
  	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
      0x05,    0, /* NULL */
    0x04,     16  /* OCTET STRING */
      /* Here comes the raw hash value */
};

static void
pkcs1_encode_md5(mpz_t m, unsigned length, struct md5_ctx *hash)
{
  uint8_t *em = alloca(length);
  unsigned i;

  assert(length >= MD5_DIGEST_SIZE);

  i = length - MD5_DIGEST_SIZE;
  
  md5_digest(hash, MD5_DIGEST_SIZE, em + i);

  assert(i >= sizeof(md5_prefix));

  i -= sizeof(md5_prefix);
  memcpy(em + i, md5_prefix, sizeof(md5_prefix));

  assert(i);
  em[--i] = 0;

  assert(i >= 9);

  em[0] = 1;
  memset(em + 1, 0xff, i - 1);

  nettle_mpz_set_str_256(m, length, em);
}

#endif /* WITH_PUBLIC_KEY */
