
/*
 *
 * Serpent is a 128-bit block cipher that accepts a key size of 256 bits,
 * designed by Ross Anderson, Eli Biham, and Lars Knudsen.  See
 * http://www.cl.cam.ac.uk/~rja14/serpent.html for details.
 */

#if !defined(SERPENT_H)
#define SERPENT_H

#include <stdlib.h>
#include "crypto_types.h"

#define SERPENT_BLOCKSIZE 16

/* Other key lengths are possible, but we only use 256 bits.  Besides, the
   design of Serpent makes other key lengths useless; they cheated with the
   AES requirements, using a 256-bit key length exclusively and just padding
   it out if the desired key length was less, so there really is no advantage
   to using key lengths less than 256 bits. */
#define SERPENT_KEYSIZE 32

typedef struct {
  UINT32 keys[33][4];		/* key schedule */
} SERPENT_context;

/* This performs Serpent's key scheduling algorithm. */
void
serpent_setup(SERPENT_context *ctx, const UINT8 *key);

/*
 * serpent_encrypt()
 *
 * Encrypt 16 bytes of data with the Serpent algorithm.  Before this
 * function can be used, serpent_setup must be used in order to initialize
 * Serpent's key schedule.
 *
 * This function always encrypts 16 bytes of plaintext to 16 bytes of
 * ciphertext.  The memory areas of the plaintext and the ciphertext can
 * overlap.
 */
void
serpent_encrypt(SERPENT_context *context,
		const UINT8 *plaintext,
		UINT8 *ciphertext);

/*
 * serpent_decrypt()
 *
 * Decrypt 16 bytes of data with the Serpent algorithm.
 *
 * Before this function can be used, serpent_setup() must be used in order
 * to set up the key schedule required for the decryption algorithm.
 * 
 * This function always decrypts 16 bytes of ciphertext to 16 bytes of
 * plaintext.  The memory areas of the plaintext and the ciphertext can
 * overlap.
 */

void
serpent_decrypt(SERPENT_context *context,
		const UINT8 *ciphertext,
		UINT8 *plaintext);

#endif /* SERPENT_H */
