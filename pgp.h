/* pgp.h
 *
 * PGP related functions.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001, 2002 Niels Möller
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

#ifndef NETTLE_PGP_H_INCLUDED
#define NETTLE_PGP_H_INCLUDED

#include "bignum.h"

struct nettle_buffer;

int
pgp_put_uint32(struct nettle_buffer *buffer, uint32_t i);

int
pgp_put_uint16(struct nettle_buffer *buffer, unsigned i);

int
pgp_put_mpi(struct nettle_buffer *buffer, mpz_t x);

int
pgp_put_string(struct nettle_buffer *buffer,
	       unsigned length,
	       const uint8_t *s);

int
pgp_put_length(struct nettle_buffer *buffer,
	       unsigned length);

int
pgp_put_header(struct nettle_buffer *buffer,
	       unsigned tag, unsigned length);

void
pgp_put_header_length(struct nettle_buffer *buffer,
		      /* start of the header */
		      unsigned start,
		      unsigned field_size);

unsigned
pgp_sub_packet_start(struct nettle_buffer *buffer);

int
pgp_put_sub_packet(struct nettle_buffer *buffer,
		   unsigned type,
		   unsigned length,
		   const uint8_t *data);

void
pgp_sub_packet_end(struct nettle_buffer *buffer, unsigned start);


int
pgp_put_userid(struct nettle_buffer *buffer,
	       unsigned length,
	       const uint8_t *name);

uint32_t
pgp_crc24(unsigned length, const uint8_t *data);

int
pgp_armor(struct nettle_buffer *buffer,
	  const char *tag,
	  unsigned length,
	  const uint8_t *data);

/* Values that can be passed to pgp_put_header when the size of the
 * length field, but not the length itself, is known. Also the minimum length
 * for the given field size. */
enum pgp_lengths
  {
    PGP_LENGTH_ONE_OCTET = 0,
    PGP_LENGTH_TWO_OCTETS = 192,
    PGP_LENGTH_FOUR_OCTETS = 8384,
  };

enum pgp_public_key_algorithm
  {
    PGP_RSA = 1,
    PGP_RSA_ENCRYPT = 2,
    PGP_RSA_SIGN = 3,
    PGP_EL_GAMAL_ENCRYPT = 16,
    PGP_DSA = 17,
    PGP_EL_GAMAL = 20,
  };

enum pgp_symmetric_algorithm
  {
    PGP_PLAINTEXT = 0,
    PGP_IDEA = 1,
    PGP_3DES = 2,
    PGP_CAST5 = 3,
    PGP_BLOWFISH = 4,
    PGP_SAFER_SK = 5,
    PGP_AES128 = 7,
    PGP_AES192 = 8,
    PGP_AES256 = 9,
  };

enum pgp_compression_algorithm
  {
    PGP_UNCOMPRESSED = 0,
    PGP_ZIP = 1,
    PGP_ZLIB = 2,
  };

enum pgp_hash_algorithm
  {
    PGP_MD5 = 1,
    PGP_SHA1 = 2,
    PGP_RIPEMD = 3,
    PGP_MD2 = 5,
    PGP_TIGER192 = 6,
    PGP_HAVAL = 7,
  };

enum pgp_tag
  {
    PGP_TAG_PUBLIC_SESSION_KEY = 1,
    PGP_TAG_SIGNATURE = 2,
    PGP_TAG_SYMMETRIC_SESSION_KEY = 3,
    PGP_TAG_ONE_PASS_SIGNATURE = 4,
    PGP_TAG_SECRET_KEY = 5,
    PGP_TAG_PUBLIC_KEY = 6,
    PGP_TAG_SECRET_SUBKEY = 7,
    PGP_TAG_COMPRESSED = 8,
    PGP_TAG_ENCRYPTED = 9,
    PGP_TAG_MARKER = 10,
    PGP_TAG_LITERAL = 11,
    PGP_TAG_TRUST = 12,
    PGP_TAG_USERID = 13,
    PGP_TAG_PUBLIC_SUBKEY = 14,
  };

enum pgp_signature_type
  {
    PGP_SIGN_BINARY = 0,
    PGP_SIGN_TEXT = 1,
    PGP_SIGN_STANDALONE = 2,
    PGP_SIGN_CERTIFICATION = 0x10,
    PGP_SIGN_CERTIFICATION_PERSONA = 0x11,
    PGP_SIGN_CERTIFICATION_CASUAL = 0x12,
    PGP_SIGN_CERTIFICATION_POSITIVE = 0x13,
    PGP_SIGN_SUBKEY = 0x18,
    PGP_SIGN_KEY = 0x1f,
    PGP_SIGN_REVOCATION = 0x20,
    PGP_SIGN_REVOCATION_SUBKEY = 0x28,
    PGP_SIGN_REVOCATION_CERTIFICATE = 0x30,
    PGP_SIGN_TIMESTAMP = 0x40,
  };

#endif /* NETTLE_PGP_H_INCLUDED */
