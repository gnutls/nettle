/* pkcs1-rsa-md5.c
 *
 * PKCS stuff for rsa-md5.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001, 2003 Niels Möller
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
# include "config.h"
#endif

#if WITH_PUBLIC_KEY

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "rsa.h"

#include "bignum.h"
#include "pkcs1.h"

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

void
pkcs1_rsa_md5_encode(mpz_t m, unsigned length, struct md5_ctx *hash)
{
  uint8_t *em = alloca(length);

  assert(length >= MD5_DIGEST_SIZE);
  pkcs1_signature_prefix(length - MD5_DIGEST_SIZE, em,
			 sizeof(md5_prefix),
			 md5_prefix);
  
  md5_digest(hash, MD5_DIGEST_SIZE, em + length - MD5_DIGEST_SIZE);
  nettle_mpz_set_str_256_u(m, length, em);
}

void
pkcs1_rsa_md5_encode_digest(mpz_t m, unsigned length, const uint8_t *digest)
{
  uint8_t *em = alloca(length);

  assert(length >= MD5_DIGEST_SIZE);
  pkcs1_signature_prefix(length - MD5_DIGEST_SIZE, em,
			 sizeof(md5_prefix),
			 md5_prefix);

  memcpy(em + length - MD5_DIGEST_SIZE, digest, MD5_DIGEST_SIZE);
  nettle_mpz_set_str_256_u(m, length, em);
}

#endif /* WITH_PUBLIC_KEY */
