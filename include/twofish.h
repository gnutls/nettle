/* twofish.h
 *
 * $Id$
 */

/*
 * twofish - An implementation of the twofish cipher.
 * Copyright (C) 1999 Ruud de Rooij <ruud@debian.org>
 *
 * Modifications for lsh
 * Copyright (C) 1999 J.H.M. Dassen (Ray) <jdassen@wi.LeidenUniv.nl>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * Twofish is a 128-bit block cipher that accepts a variable-length
 * key up to 256 bits, designed by Bruce Schneier and others.  See
 * http://www.counterpane.com/twofish.html for details.
 */

#if !defined(TWOFISH_H)
#define TWOFISH_H

#include <stdlib.h>	/* For size_t */

#include "crypto_types.h"

#define TWOFISH_BLOCKSIZE 16 /* bytes */


/* Other key lengths are possible, but in the context of the ssh protocols,
 * 256 bits is the default. */
#define TWOFISH_KEYSIZE 32 /* bytes */

/* Allow keys of size 128 <= bits <= 256 */

#define TWOFISH_MIN_KEYSIZE 16 /* bytes */
#define TWOFISH_MAX_KEYSIZE 32 /* bytes */

typedef struct {
    UINT32 keys[40];
    UINT32 s_box[4][256];
} TWOFISH_context;

/* Set up internal tables required for twofish encryption and decryption.
 *
 * The key size is specified in bytes. Key sizes up to 32 bytes are
 * supported. Larger key sizes are silently truncated. */

void
twofish_setup(TWOFISH_context *ctx, size_t keysize, const UINT8 *key);

/* void twofish_encrypt(TWOFISH_context *context,
 *                      const UINT8 *plaintext,
 *                      UINT8 *ciphertext);
 *
 * Encrypt 16 bytes of data with the twofish algorithm.
 *
 * Before this function can be used, twofish_setup() must be used in order to
 * set up various tables required for the encryption algorithm.
 * 
 * This function always encrypts 16 bytes of plaintext to 16 bytes of
 * ciphertext.  The memory areas of the plaintext and the ciphertext can
 * overlap.
 */

void
twofish_encrypt(TWOFISH_context *context,
		const UINT8 *plaintext,
		UINT8 *ciphertext);

/* void twofish_decrypt(TWOFISH_context *context,
 *                      const UINT8 *ciphertext,
 *                      UINT8 *plaintext);
 *
 * Decrypt 16 bytes of data with the twofish algorithm.
 *
 * Before this function can be used, twofish_setup() must be used in order to
 * set up various tables required for the decryption algorithm.
 * 
 * This function always decrypts 16 bytes of ciphertext to 16 bytes of
 * plaintext.  The memory areas of the plaintext and the ciphertext can
 * overlap.
 */

void
twofish_decrypt(TWOFISH_context *context,
		const UINT8 *ciphertext,
		UINT8 *plaintext);

int
twofish_selftest(void);

#endif /* TWOFISH_H */
